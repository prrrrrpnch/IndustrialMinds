"""
benchmark/workload.py - deterministic command/state builders on a VIRTUAL clock.

The cyber rules (rate limit, HMAC freshness, replay) and the physical rate-of-change check read the command's own timestamp, not
the wall clock. Building frames and commands with a virtual timestamp makes every benchmark scenario exactly reproducible and lets
it run without sleeping. Nothing here is SWaT data: these are constructed scenarios, labelled as such wherever they are reported.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from docs import hmac_auth
from docs.interfaces import MACHINES, MACHINE_BY_REGISTER, make_command
from docs.netconfig import LOOPBACK

T0 = 1_800_000_000.0           # virtual epoch (fixed: reproducible)
TRUSTED = LOOPBACK             # the default trusted source
UNTRUSTED_PREFIX = "127.30."   # loopback addresses that are NOT in the default trusted list


def nominal_registers() -> Dict[int, float]:
    return {m["register"]: float(m["initial"]) for m in MACHINES}


def make_state(registers: Dict[int, float], last_change: float) -> Dict[str, Any]:
    return {"registers": dict(registers), "setpoints": dict(registers), "timestamp": last_change}


def signed(reg: int, value: float, t: float, ip: str = TRUSTED, tx: str = "tx", key: Optional[bytes] = None,
           frame: Optional[List[int]] = None, fc: int = 16, source_port: int = 40000) -> Dict[str, Any]:
    """A command whose frame is signed AT virtual time t (so it is fresh when evaluated at t)."""
    frame = frame if frame is not None else hmac_auth.build_frame(reg, value, key=key, timestamp_ms=int(t * 1000))
    p = hmac_auth.parse_frame(frame)
    return make_command(tx, t, ip, fc, p["register"], (p["raw_value"] or 0) / 10.0, raw_value=p["raw_value"], auth=p["auth"],
                        source_port=source_port)


def unsigned(reg: int, value: float, t: float, ip: str = TRUSTED, tx: str = "tx") -> Dict[str, Any]:
    return make_command(tx, t, ip, 6, reg, value, raw_value=int(round(value * 10)), auth=None, source_port=40000)


def actuators() -> List[int]:
    return [m["register"] for m in MACHINES if m["kind"] == "actuator"]


def sensors() -> List[int]:
    return [m["register"] for m in MACHINES if m["kind"] == "sensor"]


def bounds(reg: int):
    m = MACHINE_BY_REGISTER[reg]
    return float(m["min"]), float(m["max"])
