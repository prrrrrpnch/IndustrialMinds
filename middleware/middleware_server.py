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
from docs import hmac_auth, attack_log, netconfig
from middleware import trace as tracer

from middleware import (
    cyber_agent,
    physical_agent,
    orchestrator,
)
from pipeline.multi_model_pipeline import get_pipeline

log = logging.getLogger("industrialmind.middleware")

LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s - %(message)s"

# How often the live telemetry + plant state line is logged.
TELEMETRY_LOG_INTERVAL = float(os.environ.get("IM_TELEMETRY_LOG_SECONDS", "5"))
_last_telemetry_log = 0.0


# =========================================================
# CONFIG
# =========================================================

# Resolved in docs/netconfig.py (env: IM_PLC_HOST/PORT, IM_LISTEN_HOST/PORT, IM_DASHBOARD_URL;
# CLI flags in __main__ override).
PLC_HOST = netconfig.PLC_HOST
PLC_PORT = netconfig.PLC_PORT

LISTEN_HOST = netconfig.LISTEN_HOST
LISTEN_PORT = netconfig.LISTEN_PORT

DASHBOARD_URL = netconfig.DASHBOARD_URL

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

# A PASSed command is "pending" until the PLC telemetry shows the register has
# reached the commanded value. If it never settles (the plant is being dragged
# elsewhere by an attack, the twin cannot physically reach the exact value, or
# the PLC rebooted), the pending entry must not linger forever: it would keep
# being projected into the cross-register `setpoints` snapshot and could skew
# later checks. After this many seconds without settling, the command is
# expired (logged once) and the projection falls back to live telemetry.
# Env override: IM_PENDING_TIMEOUT_S.
PENDING_COMMAND_TIMEOUT_S = float(
    os.environ.get("IM_PENDING_TIMEOUT_S", "15")
)


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

# Rate-limit the "cannot reach the PLC" error so a down PLC laptop does not
# flood the middleware log at the 0.2 s poll rate.
_last_poll_error_log = 0.0
POLL_ERROR_LOG_INTERVAL = 5.0


def _dashboard_headers() -> Dict[str, str]:
    """Headers for posts to the dashboard: adds the shared token when configured
    (IM_DASHBOARD_TOKEN), so a network-exposed dashboard only accepts the
    middleware's posts. Empty when no token is set (loopback demo, unchanged)."""
    token = os.environ.get("IM_DASHBOARD_TOKEN", "").strip()
    return {"X-IM-Token": token} if token else {}


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
    #   Physical Agent rules + PhysicalModel plant state / anomaly score
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

        logged = _log_blocked(
            command,
            cyber_verdict,
            physical_verdict,
            decision,
            current_state["registers"].get(register),
            report,
        )

        _publish_trace(report, forwarded=False,
                       logged_to=attack_log.LOG_FILE if logged else None,
                       note="dropped before the PLC; no response will come back")

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

    _publish_trace(report, forwarded=success, logged_to=None,
                   note="forwarded with an advisory ALERT" if decision["verdict"] == "ALERT" else "")

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
) -> bool:
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
            "plant_state": report["physical"]["model"].get("plant_state"),
            "physical_model_status": report["physical"]["model"].get("status"),
            "physical_anomaly_score": report["physical"]["model"].get("anomaly_score"),
            "physical_attack_probability": report["physical"]["model"].get("attack_probability"),
            "physical_bounds_violations": len(report["physical"]["model"].get("bounds_violations") or []),
            "mode": report.get("mode"),
        }

    try:
        attack_log.log_blocked_attack(record)
        return True
    except Exception as e:
        log.error(f"[MIDDLEWARE] ERROR writing attack log: {e}")
        return False


def _publish_model_card() -> None:
    """Tell the dashboard what the live physical model is and what it cannot do (never fatal: it is only documentation)."""
    try:
        from models.physical_model_v2 import model_card
        card = model_card(get_pipeline().physical_model)
        orchestrator.forward_model_card_to_dashboard(card)
        log.info("[MIDDLEWARE] physical model: %s (%s) threshold %.4f - %s", card.get("model"), card.get("status"),
                 card.get("threshold") or 0.0, card.get("held_out_result") or "no held-out result recorded")
    except Exception as e:
        log.info(f"[MIDDLEWARE] model card unavailable: {e}")


def _publish_trace(report: dict, forwarded: bool, logged_to: Optional[str], note: str = "") -> None:
    """Add the final outcome hop to this command's packet-trace and hand it to the dashboard (never blocks)."""
    hop_trace = report.get("trace")
    if not hop_trace:
        return
    try:
        tracer.add_outcome(hop_trace, forwarded, logged_to, note)
        orchestrator.forward_trace_to_dashboard(hop_trace)
    except Exception as e:
        log.error(f"[MIDDLEWARE] trace publish failed (decision unaffected): {e}")


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
            headers=_dashboard_headers(),
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
            headers=_dashboard_headers(),
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
        score = health.get("anomaly_score")
        prob = health.get("attack_probability")
        health_txt = (
            f"plant={health.get('plant_state')} "
            f"score={'n/a' if score is None else f'{score:.3f}'} "
            f"p_attack={'n/a' if prob is None else f'{prob:.3f}'} "
            f"bounds_viol={len(health.get('bounds_violations') or [])}"
        )
    else:
        health_txt = (
            f"plant={health.get('plant_state', health.get('status'))} "
            f"window={health.get('window_fill')}/{health.get('window_size')}"
        )

    log.info(f"[TELEMETRY] {values} | {health_txt}")


# =========================================================
# PLC POLLING
# =========================================================

ENVELOPE_ALERTS = os.environ.get("IM_ENVELOPE_ALERTS", "1") != "0"
ENVELOPE_ALERT_INTERVAL = float(os.environ.get("IM_ENVELOPE_ALERT_SECONDS", "30"))
_last_envelope_alert: Dict[str, float] = {}


def _check_upstream_envelope(registers: Dict[Any, float], now: float) -> None:
    """Raise an upstream DROP decision for sensors outside the measured envelope (rate-limited per sensor)."""
    try:
        verdict = physical_agent.check_telemetry(registers)
        if verdict["pass"]:
            return
        fresh = [v for v in verdict["violations"] if now - _last_envelope_alert.get(v["tag"], 0.0) >= ENVELOPE_ALERT_INTERVAL]
        if not fresh:
            return
        for v in fresh:
            _last_envelope_alert[v["tag"]] = now
        verdict["tx_id"] = f"UP-ENV-{int(now * 1000)}"
        verdict["command"] = "UPSTREAM TELEMETRY " + ",".join(v["tag"] for v in fresh)
        orchestrator.decide(None, verdict, now)
        log.warning("[UPSTREAM] %s", verdict["reason"])
    except Exception:
        log.exception("upstream envelope check failed - ignored (rules elsewhere still gate)")


def _expire_pending_if_stale(reg: int, pending: dict, reported: float, now: float) -> bool:
    """Drop a PASSed command that was forwarded but whose register never settled
    to the commanded value within PENDING_COMMAND_TIMEOUT_S. Returns True if it
    was expired. Keeps a never-settling command from being projected forever
    into the cross-register setpoints snapshot. Safe to call under no lock; it
    takes _state_lock for the mutation itself."""
    if now - pending["time"] <= PENDING_COMMAND_TIMEOUT_S:
        return False
    with _state_lock:
        _pending_commands.pop(reg, None)
        _register_settled_since[reg] = now
    log.warning(
        f"[MIDDLEWARE] command tx={pending['tx_id']} "
        f"reg={REGISTER_MAP[reg]['name']} value={pending['value']:.2f} was "
        f"forwarded but the PLC never settled to it within "
        f"{PENDING_COMMAND_TIMEOUT_S:.0f}s (last reported {reported:.2f}); "
        f"expiring it. The plant may be displaced (attack/recovery) or the "
        f"PLC may be unreachable."
    )
    return True


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
        # live telemetry + plant-state line.
        # -------------------------------------------------

        pipeline = get_pipeline()
        pipeline.ingest_telemetry(
            dict(_plc_state["registers"]),
            _plc_state.get("timestamp") or now,
        )
        _log_live_telemetry(now, pipeline)

        # -------------------------------------------------
        # Upstream sensor-envelope RULE (measured SWaT envelope).
        # Detect-and-ALERT: the telemetry is still mirrored to SCADA; an
        # upstream DROP decision is raised on the dashboard, at most once
        # per sensor per ENVELOPE_ALERT_INTERVAL seconds.
        # -------------------------------------------------

        if ENVELOPE_ALERTS:
            _check_upstream_envelope(dict(_plc_state["registers"]), now)

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

                # Expire a command that never settled, so its value stops
                # being projected into the cross-register setpoints snapshot
                # and the dashboard stops showing it as forever-pending.
                _expire_pending_if_stale(reg, pending, reported, now)

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

        # The poll runs every 0.2 s; if the PLC laptop is down or unreachable
        # this would flood the log 5x/second. Rate-limit to one actionable
        # line every POLL_ERROR_LOG_INTERVAL seconds, and say what to check.
        global _last_poll_error_log
        now_err = time.time()
        if now_err - _last_poll_error_log >= POLL_ERROR_LOG_INTERVAL:
            _last_poll_error_log = now_err
            log.error(
                f"[MIDDLEWARE] cannot reach the PLC at "
                f"{PLC_HOST}:{PLC_PORT} ({e}). Retrying every "
                f"{POLL_INTERVAL:.1f}s. Check: the PLC process is running, "
                f"IM_PLC_HOST is correct, and the PLC laptop's firewall "
                f"allows this host inbound on {PLC_PORT}."
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
    _publish_model_card()

    # Startup objects (modules, models, config) live for the whole process.
    # Moving them out of the GC's view keeps full collections short, so they
    # cannot stall command processing for tens of milliseconds.
    gc.collect()
    gc.freeze()

    import argparse
    parser = argparse.ArgumentParser(description="Industrial Mind middleware (Modbus proxy + agents)")
    parser.add_argument("--listen-host", default=LISTEN_HOST, help="address to bind for SCADA (env IM_LISTEN_HOST)")
    parser.add_argument("--listen-port", type=int, default=LISTEN_PORT, help="port for SCADA (env IM_LISTEN_PORT)")
    parser.add_argument("--plc-host", default=PLC_HOST, help="PLC address (env IM_PLC_HOST)")
    parser.add_argument("--plc-port", type=int, default=PLC_PORT, help="PLC port (env IM_PLC_PORT)")
    parser.add_argument("--dashboard-url", default=DASHBOARD_URL, help="dashboard base URL (env IM_DASHBOARD_URL)")
    args = parser.parse_args()

    DASHBOARD_URL = args.dashboard_url
    netconfig.DASHBOARD_URL = args.dashboard_url   # orchestrator reads this at call time

    start_middleware_server(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        plc_host=args.plc_host,
        plc_port=args.plc_port,
    )