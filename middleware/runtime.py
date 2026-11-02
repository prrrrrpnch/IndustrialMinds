"""
middleware/runtime.py - configuration, shared plant state and raw/engineering conversion.

Split out of middleware_server.py (AUDIT A1: a 1,229-line module owning the server, the datastore hook, the pipeline, the
PLC client, the poll loop, logging and the CLI). This is the layer every other middleware module needs and that needs none
of them, so it sits at the bottom and nothing here imports a sibling.

Everything mutable lives behind `_state_lock`. Read it through this module (`runtime._plc_state`), never by importing the
name - a `from ... import _plc_state` would freeze a copy of the binding and quietly stop seeing updates.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Dict

from core.interfaces import MACHINES, ALL_REGISTERS, SCALE
from core import netconfig

log = logging.getLogger("industrialmind.middleware")

LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s - %(message)s"

# How often the live telemetry + plant state line is logged.
TELEMETRY_LOG_INTERVAL = float(os.environ.get("IM_TELEMETRY_LOG_SECONDS", "5"))


# =========================================================
# CONFIG
# =========================================================


# Resolved in core/netconfig.py (env: IM_PLC_HOST/PORT, IM_LISTEN_HOST/PORT, IM_DASHBOARD_URL;
# CLI flags in __main__ override).
PLC_HOST = netconfig.PLC_HOST
PLC_PORT = netconfig.PLC_PORT

LISTEN_HOST = netconfig.LISTEN_HOST
LISTEN_PORT = netconfig.LISTEN_PORT

DASHBOARD_URL = netconfig.DASHBOARD_URL

# PLC is checked frequently for real feedback.
POLL_INTERVAL = 0.2
# AUDIT C4: back off while the PLC is unreachable instead of hammering it 5x/s forever.
POLL_BACKOFF_AFTER = int(os.environ.get("IM_POLL_BACKOFF_AFTER", "3"))     # consecutive failures before backing off
POLL_BACKOFF_MAX = float(os.environ.get("IM_POLL_BACKOFF_MAX_S", "5.0"))   # ceiling, so recovery is still noticed quickly

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




_health = {
    "plc_connected": False,          # did the last PLC poll succeed?
    "consecutive_poll_failures": 0,
    "last_plc_ok": 0.0,
    "dropped_forwards": 0,           # approved commands the forwarder queue could not even accept
    "undelivered": 0,                # approved commands the PLC did not take
    "forward_backlog": 0,
}


def health_snapshot() -> Dict[str, Any]:
    """A copy of the middleware's self-reported health (AUDIT A6/N6)."""
    with _state_lock:
        snap = dict(_health)
    from middleware import forwarding          # late: forwarding imports runtime, runtime must not import forwarding
    snap["forward_backlog"] = forwarding._forward_queue.qsize()
    snap["last_plc_ok_age_s"] = (round(time.time() - snap["last_plc_ok"], 1)
                                 if snap["last_plc_ok"] else None)
    return snap



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
# DASHBOARD POSTING
# =========================================================

def _dashboard_headers() -> Dict[str, str]:
    """Headers for posts to the dashboard: adds the shared token when configured
    (IM_DASHBOARD_TOKEN), so a network-exposed dashboard only accepts the
    middleware's posts. Empty when no token is set (loopback demo, unchanged)."""
    token = os.environ.get("IM_DASHBOARD_TOKEN", "").strip()
    return {"X-IM-Token": token} if token else {}

