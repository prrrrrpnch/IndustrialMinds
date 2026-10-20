"""
middleware/middleware_server.py — the SCADA-facing Modbus transport, and the process entry point.

Architecture:

SCADA
  |
  v
Middleware :5021            transport (this file)
  |                           -> ingest     : decide            (middleware/ingest.py)
  |                           -> forwarding : write to the PLC  (middleware/forwarding.py)
  |                           <- polling    : read the PLC      (middleware/polling.py)
  |                              runtime    : config + state    (middleware/runtime.py)
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
  see core/hmac_auth.py). Plain writes to machine registers are still run
  through the pipeline so they are visibly rejected (HMAC_MISSING) and logged.

Blocked attacks:
  Every DROP is appended to logs/blocked_attacks.jsonl (core/attack_log.py).

AUDIT A1/A2 (the split). This module used to be 1,478 lines owning the server, the datastore hook, the whole security
pipeline, the PLC client, the poll loop, logging and the CLI. It now owns the transport and the entry point only, and the
datastore hook ENQUEUES rather than decides - the pipeline no longer runs as a side effect of a storage call.

Names that moved are re-exported at the bottom for callers that still import them from here, but new code should import
the owning module: a re-export is a snapshot of a binding, so reassigning `middleware_server._plc_client` does NOT change
what `forwarding` uses. Patch `forwarding._plc_client` instead.
"""

from __future__ import annotations

import asyncio
import gc
import logging
import os
import threading
from typing import Any, Dict, List

from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusSlaveContext,
    ModbusServerContext,
)
from pymodbus.server import ModbusTcpServer
from pymodbus.server.async_io import ModbusServerRequestHandler

from core.interfaces import DATASTORE_SIZE
from core import hmac_auth, attack_log, netconfig
from middleware import runtime
from middleware import forwarding
from middleware import ingest
from middleware import polling
from pipeline.multi_model_pipeline import get_pipeline

log = logging.getLogger("industrialmind.middleware")

LOG_FORMAT = runtime.LOG_FORMAT

LISTEN_HOST = runtime.LISTEN_HOST
LISTEN_PORT = runtime.LISTEN_PORT
PLC_HOST = runtime.PLC_HOST
PLC_PORT = runtime.PLC_PORT
DASHBOARD_URL = runtime.DASHBOARD_URL
UNKNOWN_SOURCE_IP = runtime.UNKNOWN_SOURCE_IP


# =========================================================
# REAL SOURCE IP CAPTURE
# =========================================================

# Set for the duration of each Modbus request so the datastore hook
# (MiddlewareDataBlock.setValues) knows which connection sent it. It is defined
# in ingest, which is where it is read.
_request_ctx = ingest._request_ctx


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
# LOG NOISE CONTROL
# =========================================================

class _RateLimitFilter(logging.Filter):
    """Let one record per interval through, per message template, for the named loggers.

    AUDIT C3: the middleware rate-limits its own 'cannot reach the PLC' line, but pymodbus logs its own connection failure
    at ERROR on every attempt. During a 30 s outage that was 99 library lines against 2 of ours - ~5/s, enough to bury
    every DROP in the log an operator is actually reading. Silencing the library outright would also hide real faults, so
    it is rate limited instead: the first failure is reported, then at most one line per interval, and the next line that
    gets through says how many were suppressed.

    This must be attached to a HANDLER, not to the 'pymodbus' logger: a logger's filters are NOT inherited by its
    children, and the records actually originate at 'pymodbus.logging'.
    """

    def __init__(self, prefixes, interval_s: float = 5.0) -> None:
        super().__init__()
        self.prefixes = tuple(prefixes)
        self.interval = interval_s
        self._last: Dict[str, float] = {}
        self._suppressed: Dict[str, int] = {}

    def filter(self, record: logging.LogRecord) -> bool:
        import time as _time
        if not record.name.startswith(self.prefixes):
            return True                                   # our own logs are never rate limited
        key = f"{record.name}:{record.levelno}:{record.msg}"
        now = _time.monotonic()
        last = self._last.get(key)
        if last is not None and now - last < self.interval:
            self._suppressed[key] = self._suppressed.get(key, 0) + 1
            return False
        n = self._suppressed.pop(key, 0)
        if n:
            record.msg = f"{record.msg}  [+{n} identical suppressed in the last {self.interval:g}s]"
        self._last[key] = now
        return True


# =========================================================
# MODBUS DATA BLOCK
# =========================================================

class MiddlewareDataBlock(ModbusSequentialDataBlock):
    """
    SCADA-facing holding registers.

    AUDIT A2: this hook stores the value and HANDS THE WRITE OFF. It does not decide. The entire security pipeline used to
    run here, as a side effect of a storage call on the asyncio event loop, which is both the wrong place for it
    architecturally and the reason one slow decision blocked every other client.
    """

    def setValues(self, address: int, values: List[int]) -> None:

        # Store the value locally first.
        super().setValues(address, values)

        ingest.submit(
            address,
            list(values),
            _request_ctx.get() or {}
        )


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


# polling writes telemetry back into this datastore; it cannot import this module (this module imports it), so the
# function is handed over here.
polling._internal_sync_write = _internal_sync_write


# =========================================================
# START MIDDLEWARE
# =========================================================

def start_middleware_server(
    listen_host: str = LISTEN_HOST,
    listen_port: int = LISTEN_PORT,
    plc_host: str = PLC_HOST,
    plc_port: int = PLC_PORT,
) -> None:

    # -----------------------------------------------------
    # Connect to PLC and start the two workers
    # -----------------------------------------------------

    client = forwarding.connect(plc_host, plc_port)
    forwarding.start_forwarder()       # approved writes leave the event loop here (AUDIT C2)
    ingest.start_worker()              # decisions leave the event loop here (AUDIT A2)

    if not client.connect():

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

    polling._poll_once(block)

    # -----------------------------------------------------
    # Start background polling
    # -----------------------------------------------------

    threading.Thread(
        target=polling._poll_plc_loop,
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
# COMPATIBILITY RE-EXPORTS
#
# These names were defined here before the split (AUDIT A1). They are re-exported so existing callers keep working, but
# they are SNAPSHOTS of a binding: rebinding middleware_server._plc_client does not change what forwarding uses. Patch
# the owning module instead. Functions and mutable containers are the same objects, so those are safe either way.
# =========================================================

health_snapshot = runtime.health_snapshot
_to_raw = runtime._to_raw
_from_raw = runtime._from_raw
_state_lock = runtime._state_lock
_plc_state = runtime._plc_state
_pending_commands = runtime._pending_commands
_register_settled_since = runtime._register_settled_since
_health = runtime._health
_dashboard_headers = runtime._dashboard_headers
_ALL_REGISTERS = runtime._ALL_REGISTERS
PENDING_COMMAND_TIMEOUT_S = runtime.PENDING_COMMAND_TIMEOUT_S
POLL_INTERVAL = runtime.POLL_INTERVAL
POLL_BACKOFF_AFTER = runtime.POLL_BACKOFF_AFTER
POLL_BACKOFF_MAX = runtime.POLL_BACKOFF_MAX
TELEMETRY_REPORT_INTERVAL = runtime.TELEMETRY_REPORT_INTERVAL
FEEDBACK_SETTLED_TOLERANCE = runtime.FEEDBACK_SETTLED_TOLERANCE

PLC_IO_TIMEOUT_S = forwarding.PLC_IO_TIMEOUT_S
PLC_IO_RETRIES = forwarding.PLC_IO_RETRIES
FORWARD_QUEUE_MAX = forwarding.FORWARD_QUEUE_MAX
_forward_queue = forwarding._forward_queue
_forward_to_plc = forwarding._forward_to_plc
_report_undelivered = forwarding._report_undelivered
_forward_job = forwarding._forward_job
_forward_worker = forwarding._forward_worker

_process_write = ingest._process_write
_handle_downstream_write = ingest._handle_downstream_write
_log_blocked = ingest._log_blocked
_publish_trace = ingest._publish_trace
_publish_model_card = ingest._publish_model_card

POLL_ERROR_LOG_INTERVAL = polling.POLL_ERROR_LOG_INTERVAL
_poll_once = polling._poll_once
_poll_delay = polling._poll_delay
_poll_plc_loop = polling._poll_plc_loop
_note_poll_success = polling._note_poll_success
_note_poll_failure = polling._note_poll_failure
_report_plc_response = polling._report_plc_response
_report_telemetry = polling._report_telemetry
_log_live_telemetry = polling._log_live_telemetry
_expire_pending_if_stale = polling._expire_pending_if_stale
_check_upstream_envelope = polling._check_upstream_envelope


# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":

    logging.basicConfig(
        level=os.environ.get("IM_LOG_LEVEL", "INFO"),
        format=LOG_FORMAT,
    )

    # pymodbus is chatty at INFO, and logs a connection failure at ERROR on EVERY attempt (AUDIT C3), so it needs both a
    # level floor and a rate limit - the level alone let ERROR straight through. The rate limit goes on the handler,
    # because a filter on the "pymodbus" logger would not see records from its child "pymodbus.logging".
    logging.getLogger("pymodbus").setLevel(logging.WARNING)
    _noise = _RateLimitFilter(("pymodbus",), POLL_ERROR_LOG_INTERVAL)
    for _handler in logging.getLogger().handlers:
        _handler.addFilter(_noise)

    # Load both models before accepting traffic.
    get_pipeline()
    ingest._publish_model_card()

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

    runtime.DASHBOARD_URL = args.dashboard_url
    netconfig.DASHBOARD_URL = args.dashboard_url   # orchestrator reads this at call time

    start_middleware_server(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        plc_host=args.plc_host,
        plc_port=args.plc_port,
    )
