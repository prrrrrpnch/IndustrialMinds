"""
middleware/quarantine.py - automatic response: a source that keeps violating the rules is cut off for a while.

Detect-and-RESPOND, rule-based. Every blocked command adds a weighted "strike" to its source. When the strikes inside a sliding window
reach the limit, the source is quarantined: its next commands are refused at the very first check (SOURCE_QUARANTINED) before any
cryptography runs. The quarantine lifts BY ITSELF after a hold time, and repeat offenders are held longer (doubling, capped), so a
legitimate device that misbehaves once is not locked out for good.

OPT-IN: IM_QUARANTINE=1 (default off = unchanged demo). Settings (env):
  IM_QUARANTINE_LIMIT     strikes in the window that trigger quarantine        (default 12)
  IM_QUARANTINE_WINDOW_S  sliding window in seconds                            (default 30)
  IM_QUARANTINE_HOLD_S    first hold in seconds                                (default 60)
  IM_QUARANTINE_MAX_S     longest hold after repeated offences                 (default 600)
  IM_QUARANTINE_EXEMPT    comma list of source addresses that are never quarantined

Strike weights are by severity: forged/unsigned/replayed/unauthorised commands and out-of-policy writes count most (an authentic
operator never produces them), flooding and physical-rule violations less, an advisory model flag nothing. Commands refused BECAUSE of
the quarantine do not add strikes (otherwise a flood would extend its own quarantine forever).
"""

from __future__ import annotations

import os
import threading
import time
from collections import deque
from typing import Any, Deque, Dict, List, Optional, Tuple

STRIKE_WEIGHTS: List[Tuple[str, float]] = [
    ("SOURCE_QUARANTINED", 0.0),
    ("HMAC_INVALID", 6.0), ("HMAC_MISSING", 4.0), ("HMAC_MALFORMED", 4.0), ("HMAC_EXPIRED", 2.0),
    ("REPLAY_DETECTED", 4.0), ("UNKNOWN_DEVICE", 6.0), ("UNTRUSTED_SOURCE", 4.0),
    ("UNAUTHORIZED_", 6.0), ("POLICY_ERROR", 0.0),
    ("INVALID_FUNCTION_CODE", 3.0), ("INVALID_REGISTER", 3.0),
    ("RATE_LIMIT_EXCEEDED", 1.0),
    ("CROSS_REGISTER", 3.0), ("OUT_OF_BOUNDS", 2.0), ("RATE_OF_CHANGE_EXCEEDED", 2.0),
    ("WRITE_TO_SENSOR_REGISTER", 3.0), ("UNKNOWN_REGISTER", 3.0),
]
DEFAULT_WEIGHT = 1.0

_lock = threading.Lock()
_strikes: Dict[str, Deque[Tuple[float, float]]] = {}        # source -> (time, weight)
_active: Dict[str, Dict[str, Any]] = {}                     # source -> {until, since, count, hold_s, reason}
_history: Dict[str, int] = {}                               # source -> number of quarantines so far


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


def enabled() -> bool:
    return os.environ.get("IM_QUARANTINE", "").strip().lower() in ("1", "true", "yes", "on")


def _exempt(source: str) -> bool:
    return source in {x.strip() for x in os.environ.get("IM_QUARANTINE_EXEMPT", "").split(",") if x.strip()}


def weight_for(reason: str) -> float:
    reason = str(reason or "")
    for prefix, w in STRIKE_WEIGHTS:
        if reason.startswith(prefix):
            return w
    return DEFAULT_WEIGHT


def is_quarantined(source: str, now: Optional[float] = None) -> Tuple[bool, float]:
    """(quarantined, seconds_remaining). Expired quarantines are cleared here."""
    if not enabled():
        return False, 0.0
    now = time.time() if now is None else now
    with _lock:
        q = _active.get(source)
        if q is None:
            return False, 0.0
        if now >= q["until"]:
            del _active[source]
            _strikes.pop(source, None)
            return False, 0.0
        return True, q["until"] - now


def record(source: str, reason: str, now: Optional[float] = None) -> Optional[Dict[str, Any]]:
    """Add a strike for a blocked command. Returns the quarantine record if THIS strike started one."""
    if not enabled() or _exempt(source):
        return None
    w = weight_for(reason)
    if w <= 0:
        return None
    now = time.time() if now is None else now
    window = _env_float("IM_QUARANTINE_WINDOW_S", 30.0)
    limit = _env_float("IM_QUARANTINE_LIMIT", 12.0)
    with _lock:
        if source in _active and now < _active[source]["until"]:
            return None
        dq = _strikes.setdefault(source, deque())
        dq.append((now, w))
        while dq and now - dq[0][0] > window:
            dq.popleft()
        total = sum(x[1] for x in dq)
        if total < limit:
            return None
        n = _history.get(source, 0)
        hold = min(_env_float("IM_QUARANTINE_HOLD_S", 60.0) * (2 ** n), _env_float("IM_QUARANTINE_MAX_S", 600.0))
        _history[source] = n + 1
        rec = {"source": source, "since": now, "until": now + hold, "hold_s": hold, "strikes": round(total, 1),
               "offence": n + 1, "trigger": str(reason).split(":", 1)[0]}
        _active[source] = rec
        dq.clear()
        return dict(rec)


def release(source: str) -> bool:
    """Lift a quarantine now (operator action / tests). Strike history is kept, so a repeat still escalates."""
    with _lock:
        _strikes.pop(source, None)
        return _active.pop(source, None) is not None


def status(now: Optional[float] = None) -> Dict[str, Any]:
    now = time.time() if now is None else now
    with _lock:
        live = [dict(q, remaining_s=round(q["until"] - now, 1)) for q in _active.values() if q["until"] > now]
    return {"enabled": enabled(), "quarantined": live,
            "limit": _env_float("IM_QUARANTINE_LIMIT", 12.0), "window_s": _env_float("IM_QUARANTINE_WINDOW_S", 30.0),
            "hold_s": _env_float("IM_QUARANTINE_HOLD_S", 60.0)}


def reset() -> None:
    with _lock:
        _strikes.clear()
        _active.clear()
        _history.clear()
