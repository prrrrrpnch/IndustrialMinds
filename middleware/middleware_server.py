"""
middleware/middleware_server.py — proxy between SCADA and PLC.

Architecture:

SCADA
  |
  v
Middleware :5021
  |
  |-- DROP --> STOP (never reaches PLC)
  |
  |-- PASS --> PLC :5020
                 |
                 v
             PLC feedback
                 |
                 v
              Middleware
                 |
                 v
               SCADA

Dashboard:
  LEFT  = every SCADA -> PLC security decision
  RIGHT = only actual PLC confirmations for PASSed commands

Source IP:
  The source IP of every command is taken from the TCP connection that
  delivered it (asyncio transport peername), captured per request by
  SourceTrackingRequestHandler. Nothing the client sends is used as its IP.

Authentication:
  Trusted commands arrive as HMAC-SHA256 signed frames (FC16 to FRAME_BASE,
  see docs/hmac_auth.py). Plain writes to machine registers are still run
  through the pipeline so they are visibly rejected (HMAC_MISSING) and logged.

Blocked attacks:
  Every DROP is appended to logs/blocked_attacks.jsonl (docs/attack_log.py).
"""

from __future__ import annotations

import asyncio
import contextvars
import gc
import logging
import os
import time
import threading
import uuid
from typing import Any, Dict, List, Optional

import requests

from pymodbus.client import ModbusTcpClient
from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusSlaveContext,
    ModbusServerContext,
)
from pymodbus.server import ModbusTcpServer
from pymodbus.server.async_io import ModbusServerRequestHandler

from docs.interfaces import (
    make_command,
    REGISTER_MAP,
    MACHINES,
    MACHINE_BY_REGISTER,
    ALL_REGISTERS,
    NUM_REGISTERS,
    FRAME_BASE,
    FRAME_LEN,
    DATASTORE_SIZE,
    SCALE,
)
from docs import hmac_auth, attack_log

from middleware import (
    cyber_agent,
    physical_agent,
    orchestrator,
)
from pipeline.multi_model_pipeline import get_pipeline

log = logging.getLogger("industrialmind.middleware")

LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s - %(message)s"

# How often the live telemetry + machine health line is logged.
TELEMETRY_LOG_INTERVAL = float(os.environ.get("IM_TELEMETRY_LOG_SECONDS", "5"))
_last_telemetry_log = 0.0


# =========================================================
# CONFIG
# =========================================================

PLC_HOST = "127.0.0.1"
PLC_PORT = 5020

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 5021

DASHBOARD_URL = "http://127.0.0.1:5050"

# PLC is checked frequently for real feedback.
POLL_INTERVAL = 0.2

# Dashboard telemetry does not need to be sent every
# PLC polling cycle.
TELEMETRY_REPORT_INTERVAL = 1.0

# Used ONLY when a command is injected without any network connection
# (e.g. a unit test calling _handle_downstream_write directly). It is not a
# trusted address, so such commands fail the source whitelist.
UNKNOWN_SOURCE_IP = "unknown"

FEEDBACK_SETTLED_TOLERANCE = 0.05


_ALL_REGISTERS = ALL_REGISTERS


# =========================================================
# REAL SOURCE IP CAPTURE
# =========================================================

# Set for the duration of each Modbus request so the datastore hook
# (MiddlewareDataBlock.setValues) knows which connection sent it.
_request_ctx: contextvars.ContextVar = contextvars.ContextVar(
    "im_request_ctx", default=None
)


def _normalize_ip(ip: object) -> str:
    ip = str(ip or "")
    if ip.startswith("::ffff:"):
        ip = ip[7:]
    return ip


class SourceTrackingRequestHandler(ModbusServerRequestHandler):
    """Per-connection handler that records the real peer address and
    function code of each request before it touches the datastore."""

    async def _async_execute(self, request: Any, *addr: Any) -> None:
        peer = None
        try:
            peer = self.transport.get_extra_info("peername")
        except Exception:
            peer = None

        ctx = {
            "source_ip": _normalize_ip(peer[0]) if peer else UNKNOWN_SOURCE_IP,
            "source_port": peer[1] if peer and len(peer) > 1 else None,
            "function_code": getattr(request, "function_code", None),
        }

        token = _request_ctx.set(ctx)
        try:
            await super()._async_execute(request, *addr)
        finally:
            _request_ctx.reset(token)


class SourceTrackingTcpServer(ModbusTcpServer):
    def callback_new_connection(self) -> "SourceTrackingRequestHandler":
        return SourceTrackingRequestHandler(self)


# =========================================================
# SHARED STATE
# =========================================================

_state_lock = threading.Lock()

_plc_state = {
    "registers": {
        m["register"]: float(m["initial"]) for m in MACHINES
    },
    "timestamp": time.time(),
}


# Only PASSed commands that were actually forwarded
# to the PLC are stored here.
_pending_commands = {}


_register_settled_since = {
    reg: time.time() - 3.0
    for reg in _ALL_REGISTERS
}


_plc_client: ModbusTcpClient | None = None

_last_telemetry_report = 0.0


# =========================================================
# RAW / REAL VALUE CONVERSION
# =========================================================

def _to_raw(value: float) -> int:
    return max(
        0,
        min(
            65535,
            int(round(value * SCALE))
        )
    )


def _from_raw(raw: int) -> float:
    return raw / SCALE


# =========================================================
# MODBUS DATA BLOCK
# =========================================================

class MiddlewareDataBlock(ModbusSequentialDataBlock):
    """
    SCADA-facing holding registers.

    External writes enter here and are processed by
    the security pipeline.
    """

    def setValues(self, address: int, values: List[int]) -> None:

        # Store the value locally first.
        super().setValues(address, values)

        _process_write(
            address,
            list(values),
            _request_ctx.get() or {}
        )


def _process_write(address: int, values: List[int], ctx: Dict[str, Any]) -> None:
    """
    Routes one external Modbus write into the security pipeline.

      FRAME_BASE ........ signed command frame -> verified by Cyber Agent
      machine registers . plain unsigned write -> HMAC_MISSING
      anything else ..... probe of an unmapped address -> INVALID_REGISTER
    """

    source_ip = ctx.get("source_ip") or UNKNOWN_SOURCE_IP
    source_port = ctx.get("source_port")
    function_code = ctx.get("function_code") or (16 if len(values) > 1 else 6)

    if FRAME_BASE <= address < FRAME_BASE + FRAME_LEN:

        if address == FRAME_BASE:
            parsed = hmac_auth.parse_frame(values)
        else:
            parsed = {
                "register": None,
                "raw_value": None,
                "auth": {"malformed": True, "detail": "write did not start at frame base"},
            }

        register = parsed["register"] if parsed["register"] is not None else address
        raw_value = parsed["raw_value"]

        _handle_downstream_write(
            register,
            _from_raw(raw_value) if raw_value is not None else 0.0,
            source_ip=source_ip,
            source_port=source_port,
            function_code=function_code,
            raw_value=raw_value,
            auth=parsed["auth"],
        )
        return

    for i, raw_value in enumerate(values):

        _handle_downstream_write(
            address + i,
            _from_raw(raw_value),
            source_ip=source_ip,
            source_port=source_port,
            function_code=function_code,
            raw_value=raw_value,
            auth=None,
        )


# =========================================================
# SCADA -> PLC
# =========================================================

def _handle_downstream_write(
    register: int,
    value: float,
    source_ip: str | None = None,
    source_port: int | None = None,
    function_code: int = 6,
    raw_value: int | None = None,
    auth: dict | None = None,
) -> None:

    start_time = time.time()

    tx_id = str(uuid.uuid4())

    if source_ip is None:
        ctx = _request_ctx.get() or {}
        source_ip = ctx.get("source_ip") or UNKNOWN_SOURCE_IP
        source_port = source_port or ctx.get("source_port")

    register_name = REGISTER_MAP.get(
        register, {}
    ).get("name", f"REGISTER_{register}")

    # -----------------------------------------------------
    # Build command
    # -----------------------------------------------------

    command = make_command(
        tx_id=tx_id,
        timestamp=start_time,
        source_ip=source_ip,
        function_code=function_code,
        register=register,
        value=value,
        raw_value=raw_value,
        auth=auth,
        source_port=source_port,
    )

    # -----------------------------------------------------
    # Current PLC state
    # -----------------------------------------------------

    with _state_lock:

        registers_now = dict(
            _plc_state["registers"]
        )

        # Projected plant state = targets already approved and still
        # ramping, else live telemetry. Used for cross-register checks.
        setpoints = dict(registers_now)
        for reg, pending in _pending_commands.items():
            setpoints[reg] = pending["value"]

        current_state = {
            "registers": registers_now,

            "setpoints": setpoints,

            "timestamp": _register_settled_since.get(
                register,
                _plc_state["timestamp"]
            ),
        }

    # -----------------------------------------------------
    # MultiModelPipeline
    #
    # Runs concurrently:
    #   Cyber Agent rules    + CyberModel anomaly score
    #   Physical Agent rules + PhysicalModel health / RUL
    # then the Orchestrator fuses the rule verdicts into
    # PASS / DROP exactly as before.
    # -----------------------------------------------------

    report = get_pipeline().process_command(
        command,
        current_state,
        start_time=start_time,
        command_label=f"{register_name} → {value:.2f}",
    )

    cyber_verdict = report["cyber"]["gate_verdict"]
    physical_verdict = report["physical"]["rule_verdict"]
    decision = report["decision"]

    cyber_ml = report["cyber"]["model"]

    # -----------------------------------------------------
    # Terminal output
    # -----------------------------------------------------

    log.info(
        f"[MIDDLEWARE] "
        f"{decision['verdict']:4s} "
        f"src={source_ip} "
        f"{register_name}={value:.2f} "
        f"reason={decision['reason']} "
        f"ml_score={cyber_ml.get('anomaly_score')} "
        f"ml_flag={cyber_ml.get('threat_flag')} "
        f"t={report['timings_ms']['total']:.2f}ms"
    )

    # -----------------------------------------------------
    # DROP
    #
    # Nothing is added to _pending_commands.
    # Therefore there will be NO PLC response.
    # -----------------------------------------------------

    if decision["verdict"] == "DROP":

        _log_blocked(
            command,
            cyber_verdict,
            physical_verdict,
            decision,
            current_state["registers"].get(register),
            report,
        )

        return

    # -----------------------------------------------------
    # PASS
    #
    # Register the pending command BEFORE forwarding.
    # -----------------------------------------------------

    with _state_lock:

        _pending_commands[register] = {
            "tx_id": tx_id,
            "value": value,
            "time": start_time,
        }

    # -----------------------------------------------------
    # Forward approved command to REAL PLC
    # -----------------------------------------------------

    success = _forward_to_plc(
        register,
        value
    )

    # If forwarding failed, remove pending command.
    if not success:

        with _state_lock:

            _pending_commands.pop(
                register,
                None
            )


# =========================================================
# PERSISTENT BLOCKED-ATTACK LOG
# =========================================================

def _log_blocked(
    command: dict,
    cyber_verdict: dict,
    physical_verdict: dict,
    decision: dict,
    current_value: Optional[float],
    report: dict | None = None,
) -> None:
    """
    Append a DROPped command to logs/blocked_attacks.jsonl.
    Never includes the HMAC secret or tag.
    """

    register = command["register"]
    machine = MACHINE_BY_REGISTER.get(register, {})

    auth = command.get("auth")
    if auth is None:
        signature = "absent"
    elif auth.get("malformed"):
        signature = "malformed"
    else:
        signature = "present"

    record = {
        "timestamp": command["timestamp"],
        "direction": "scada_to_plc",
        "source_ip": command["source_ip"],
        "source_port": command.get("source_port"),
        "tx_id": command["tx_id"],
        "function_code": command.get("function_code"),
        "register": register,
        "register_name": machine.get("name", f"REGISTER_{register}"),
        "machine": machine.get("machine", f"Unmapped address {register}"),
        "unit": machine.get("unit", ""),
        "requested_value": command.get("value"),
        "current_value": current_value,
        "signature": signature,
        "hmac_status": cyber_verdict.get("auth_status", "NOT_CHECKED"),
        "cyber": {
            "verdict": "PASS" if cyber_verdict["pass"] else "FAIL",
            "reason": cyber_verdict["reason"],
        },
        "physical": {
            "verdict": "PASS" if physical_verdict["pass"] else "FAIL",
            "reason": physical_verdict["reason"],
        },
        "orchestrator": {
            "decision": decision["verdict"],
            "reason": decision["reason"],
        },
        "latency_ms": decision["latency_ms"],
    }

    if report is not None:
        ml = report["cyber"]["model"]
        record["ml"] = {
            "cyber_anomaly_score": ml.get("anomaly_score"),
            "cyber_threat_flag": ml.get("threat_flag"),
            "cyber_model_status": ml.get("status"),
            "plant_min_health_index": report["physical"]["model"].get("min_health_index"),
            "mode": report.get("mode"),
        }

    try:
        attack_log.log_blocked_attack(record)
    except Exception as e:
        log.error(f"[MIDDLEWARE] ERROR writing attack log: {e}")


# =========================================================
# FORWARD WRITE TO REAL PLC
# =========================================================

def _forward_to_plc(
    register: int,
    value: float
) -> bool:

    if _plc_client is None:

        log.warning(
            "[MIDDLEWARE] WARNING: "
            "no PLC connection — write not forwarded"
        )

        return False

    try:

        result = _plc_client.write_register(
            register,
            _to_raw(value)
        )

        if result.isError():

            log.warning(
                f"[MIDDLEWARE] "
                f"PLC rejected write "
                f"register={register} "
                f"value={value:.2f}"
            )

            return False

        log.info(
            f"[MIDDLEWARE] "
            f"FORWARDED TO PLC "
            f"register={register} "
            f"value={value:.2f}"
        )

        return True

    except Exception as e:

        log.error(
            f"[MIDDLEWARE] "
            f"ERROR forwarding to PLC: {e}"
        )

        return False


# =========================================================
# INTERNAL DATA SYNC
# =========================================================

def _internal_sync_write(
    block: ModbusSequentialDataBlock,
    address: int,
    values: list
) -> None:

    """
    Writes real PLC telemetry into the SCADA-facing
    datastore WITHOUT triggering the downstream
    command pipeline again.
    """

    ModbusSequentialDataBlock.setValues(
        block,
        address,
        values
    )


# =========================================================
# DASHBOARD — PLC -> SCADA RESPONSE
# =========================================================

def _report_plc_response(
    tx_id: str,
    register: int,
    value: float,
    latency_ms: float
) -> None:

    """
    Report an ACTUAL PLC confirmation.

    This is called ONLY when:

      1. The original command was PASSed.
      2. It was forwarded to the real PLC.
      3. PLC feedback confirms the requested value.

    DROPped commands never reach this function.
    """

    register_name = REGISTER_MAP[register]["name"]

    payload = {
        "tx_id": tx_id,
        "direction": "plc_to_scada",
        "verdict": "PASS",
        "reason": "PLC confirmed the requested value.",
        "command": f"{register_name} → {value:.2f}",
        "latency_ms": round(latency_ms, 2),
        "timestamp": time.time(),
    }

    try:

        response = requests.post(
            f"{DASHBOARD_URL}/api/security-event",
            json=payload,
            timeout=1
        )

        if response.ok:

            log.info(
                f"[MIDDLEWARE] "
                f"PLC RESPONSE "
                f"tx={tx_id} "
                f"{register_name}={value:.2f}"
            )

        else:

            log.warning(
                f"[MIDDLEWARE] "
                f"Dashboard rejected PLC response: "
                f"{response.status_code}"
            )

    except Exception as e:

        log.warning(
            f"[MIDDLEWARE] "
            f"Could not report PLC response: {e}"
        )


# =========================================================
# DASHBOARD — REAL PLC TELEMETRY
# =========================================================

def _report_telemetry() -> None:

    """
    Send actual PLC telemetry to dashboard.
    """

    with _state_lock:

        registers = {
            REGISTER_MAP[reg]["name"]:
            _plc_state["registers"][reg]
            for reg in _ALL_REGISTERS
        }

    payload = {
        "registers": registers
    }

    try:

        requests.post(
            f"{DASHBOARD_URL}/api/telemetry",
            json=payload,
            timeout=1
        )

    except Exception:
        pass


# =========================================================
# LIVE TELEMETRY LOG LINE
# =========================================================

def _log_live_telemetry(now: float, pipeline: Any) -> None:

    global _last_telemetry_log

    if now - _last_telemetry_log < TELEMETRY_LOG_INTERVAL:
        return

    _last_telemetry_log = now

    with _state_lock:
        values = " ".join(
            f"{MACHINE_BY_REGISTER[reg]['name']}={_plc_state['registers'][reg]:.1f}"
            for reg in _ALL_REGISTERS
        )

    health = pipeline.health_report()

    if health.get("status") == "OK":
        worst = min(
            health["machines"].items(),
            key=lambda kv: kv[1]["health_index"]
        )
        health_txt = (
            f"min_health={health['min_health_index']:.2f} "
            f"({worst[0]} RUL={worst[1]['rul_hours']:.0f}h)"
        )
    else:
        health_txt = (
            f"health={health.get('status')} "
            f"window={health.get('window_fill')}"
        )

    log.info(f"[TELEMETRY] {values} | {health_txt}")


# =========================================================
# PLC POLLING
# =========================================================

def _poll_once(
    block: "MiddlewareDataBlock"
) -> None:

    global _last_telemetry_report

    """
    One polling cycle:

    1. Read actual PLC telemetry.
    2. Update middleware state.
    3. Synchronize SCADA-facing registers.
    4. Check PASSed pending commands.
    5. Create PLC -> SCADA response only after
       actual PLC confirmation.
    """

    if _plc_client is None:
        return

    try:

        # -------------------------------------------------
        # Read REAL PLC
        # -------------------------------------------------

        if not _plc_client.is_socket_open():

            _plc_client.connect()

        result = _plc_client.read_holding_registers(
            0,
            count=NUM_REGISTERS
        )

        if result.isError():
            return

        raws = result.registers

        now = time.time()

        # -------------------------------------------------
        # Update middleware's copy of REAL PLC state
        # -------------------------------------------------

        with _state_lock:

            for reg, raw in zip(
                _ALL_REGISTERS,
                raws
            ):

                _plc_state["registers"][reg] = (
                    _from_raw(raw)
                )

            _plc_state["timestamp"] = now

            # -------------------------------------------------
            # Mirror REAL PLC state into SCADA datastore
            # -------------------------------------------------

            for reg, raw in zip(
                _ALL_REGISTERS,
                raws
            ):

                _internal_sync_write(
                    block,
                    reg,
                    [raw]
                )

        # -------------------------------------------------
        # Dashboard telemetry: once per second
        #
        # PLC polling remains every 0.2 seconds.
        # -------------------------------------------------

        if (
            now - _last_telemetry_report
            >= TELEMETRY_REPORT_INTERVAL
        ):

            _report_telemetry()

            _last_telemetry_report = now

        # -------------------------------------------------
        # Feed the PhysicalModel sliding window and log a
        # live telemetry + machine-health line.
        # -------------------------------------------------

        pipeline = get_pipeline()
        pipeline.ingest_telemetry(
            dict(_plc_state["registers"])
        )
        _log_live_telemetry(now, pipeline)

        # -------------------------------------------------
        # Check ONLY commands that were PASSed
        # -------------------------------------------------

        for reg in list(_pending_commands.keys()):

            with _state_lock:

                pending = _pending_commands.get(reg)

                if pending is None:
                    continue

                reported = (
                    _plc_state["registers"][reg]
                )

            # -------------------------------------------------
            # Check actual PLC value
            # -------------------------------------------------

            feedback_ok = (
                abs(
                    reported -
                    pending["value"]
                )
                < FEEDBACK_SETTLED_TOLERANCE
            )

            # -------------------------------------------------
            # PLC has NOT confirmed yet.
            #
            # No right-side event.
            # -------------------------------------------------

            if not feedback_ok:

                continue

            # -------------------------------------------------
            # PLC HAS confirmed the command.
            #
            # Now create the PLC -> SCADA response.
            # -------------------------------------------------

            latency_ms = (
                now - pending["time"]
            ) * 1000

            _report_plc_response(
                tx_id=pending["tx_id"],
                register=reg,
                value=pending["value"],
                latency_ms=latency_ms
            )

            # -------------------------------------------------
            # Remove pending command so the same response
            # is not reported repeatedly.
            # -------------------------------------------------

            with _state_lock:

                _pending_commands.pop(
                    reg,
                    None
                )

                _register_settled_since[reg] = now

    except Exception as e:

        log.error(
            f"[MIDDLEWARE] "
            f"ERROR polling PLC: {e}"
        )


# =========================================================
# POLLING LOOP
# =========================================================

def _poll_plc_loop(
    block: "MiddlewareDataBlock"
) -> None:

    while True:

        _poll_once(block)

        time.sleep(
            POLL_INTERVAL
        )


# =========================================================
# START MIDDLEWARE
# =========================================================

def start_middleware_server(
    listen_host: str = LISTEN_HOST,
    listen_port: int = LISTEN_PORT,
    plc_host: str = PLC_HOST,
    plc_port: int = PLC_PORT,
) -> None:

    global _plc_client

    # -----------------------------------------------------
    # Connect to PLC
    # -----------------------------------------------------

    _plc_client = ModbusTcpClient(
        host=plc_host,
        port=plc_port
    )

    if not _plc_client.connect():

        log.warning(
            f"[MIDDLEWARE] WARNING: "
            f"could not connect to PLC at "
            f"{plc_host}:{plc_port} yet — "
            f"will keep retrying"
        )

    # -----------------------------------------------------
    # Create SCADA-facing datastore
    # -----------------------------------------------------

    # Machine registers 0..N-1 plus the signed-frame window at FRAME_BASE.
    block = MiddlewareDataBlock(
        0,
        [0] * DATASTORE_SIZE
    )

    store = ModbusSlaveContext(
        hr=block,
        zero_mode=True
    )

    context = ModbusServerContext(
        slaves=store,
        single=True
    )

    # -----------------------------------------------------
    # Initial PLC synchronization
    # -----------------------------------------------------

    _poll_once(block)

    # -----------------------------------------------------
    # Start background polling
    # -----------------------------------------------------

    threading.Thread(
        target=_poll_plc_loop,
        args=(block,),
        daemon=True
    ).start()

    # -----------------------------------------------------
    # Start Modbus server
    # -----------------------------------------------------

    log.info(
        f"[MIDDLEWARE] "
        f"Listening for SCADA on "
        f"{listen_host}:{listen_port}, "
        f"forwarding approved writes to PLC at "
        f"{plc_host}:{plc_port}"
    )

    # Load (or create) the HMAC secret up-front so a bad configuration
    # fails at startup rather than on the first command.
    hmac_auth.get_secret()

    log.info(
        f"[MIDDLEWARE] Blocked attacks are logged to "
        f"{attack_log.LOG_FILE}"
    )

    async def _serve() -> None:
        server = SourceTrackingTcpServer(
            context=context,
            address=(
                listen_host,
                listen_port
            )
        )
        await server.serve_forever()

    asyncio.run(_serve())


# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":

    logging.basicConfig(
        level=os.environ.get("IM_LOG_LEVEL", "INFO"),
        format=LOG_FORMAT,
    )

    # pymodbus is chatty at INFO; keep it to warnings.
    logging.getLogger("pymodbus").setLevel(logging.WARNING)

    # Load both models before accepting traffic.
    get_pipeline()

    # Startup objects (modules, models, config) live for the whole process.
    # Moving them out of the GC's view keeps full collections short, so they
    # cannot stall command processing for tens of milliseconds.
    gc.collect()
    gc.freeze()

    start_middleware_server()