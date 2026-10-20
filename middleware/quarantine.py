"""
middleware/quarantine.py - automatic response: a source that keeps violating the rules is cut off for a while.

Detect-and-RESPOND, rule-based. Every blocked command adds a weighted "strike" to its source. When the strikes inside a sliding window
reach the limit, the source is quarantined: its next commands are refused at the very first check (SOURCE_QUARANTINED) before any
cryptography runs. The quarantine lifts BY ITSELF after a hold time, and repeat offenders are held longer (doubling, capped), so a
legitimate device that misbehaves once is not locked out for good.

OPT-IN: IM_QUARANTINE=1 (or "auto"); default off = unchanged demo. It switches itself OFF on a single-laptop demo: when every trusted source
(IM_TRUSTED_SOURCES, default loopback) is a loopback address, SCADA and the attacker share one address, so quarantining the attacker would
lock SCADA out as well. IM_QUARANTINE=force overrides that (tests, deliberate use). The launcher sets IM_QUARANTINE=auto for the middleware,
so multi-laptop runs get it and one-laptop rehearsals do not, with no manual step. Settings (env):
  IM_QUARANTINE_LIMIT     strikes in the window that trigger quarantine        (default 12)
  IM_QUARANTINE_WINDOW_S  sliding window in seconds                            (default 30)
  IM_QUARANTINE_HOLD_S    first hold in seconds                                (default 60)
  IM_QUARANTINE_MAX_S     longest hold after repeated offences                 (default 600)
  IM_QUARANTINE_EXEMPT    comma list of source addresses that are never quarantined

Strike weights are by severity: unauthorised writes and replays of an authenticated command count most (an authentic operator never
produces them), physical-rule violations less, an advisory model flag nothing. Commands refused BECAUSE of the quarantine do not add
strikes (otherwise a flood would extend its own quarantine forever).

AUTHENTICATED STRIKES ONLY (AUDIT S4). Trust used to be source-address based, and so was this response: on a flat L2 lab an attacker
could ARP-spoof the operator's address, send six forged frames, and the middleware would quarantine THE REAL SCADA for 60 s, doubling on
repeat - the response mechanism turned into a denial-of-service lever against the legitimate operator, which is worse than not having it.

A strike is therefore only ever recorded for a command that PASSED HMAC verification, i.e. one whose sender provably holds the key. A
pre-authentication failure (HMAC_*, UNKNOWN_DEVICE, UNTRUSTED_SOURCE, a bad function code or register, a flood) is forgeable by anyone who
can put a packet on the wire with someone else's source address, so it can never cut anyone off. Those are still logged, still dropped,
still raise an incident, and the per-source rate limit still caps the flood - they just cannot be used as a weapon.

For the same reason the quarantine CHECK runs after HMAC verification, not before it: refusing a frame before knowing who sent it means
refusing it on an address, which is exactly the thing an attacker controls.

With a per-device key registry (IM_HMAC_KEYS) an authenticated strike provably came from that device, so the quarantine is spoof-proof.
With a single shared secret, every key holder can sign as any address - the DoS lever is gone (an attacker without the key cannot score a
strike at all) but a compromised key holder could still frame another device. Running the quarantine on a shared secret logs a warning
saying so.
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

# AUDIT S4: reasons a command can be refused for BEFORE its signature is verified. Anyone able to spoof a source address can
# produce every one of them on someone else's behalf, so none of them may ever cut that someone off. Kept as an explicit list
# rather than inferred, so adding a new pre-auth check is a deliberate decision about whether it can be forged.
PRE_AUTH_REASONS: Tuple[str, ...] = (
    "UNTRUSTED_SOURCE", "SOURCE_QUARANTINED", "INVALID_FUNCTION_CODE", "INVALID_REGISTER",
    "RATE_LIMIT_EXCEEDED", "UNKNOWN_DEVICE", "HMAC_MISSING", "HMAC_MALFORMED", "HMAC_INVALID", "HMAC_EXPIRED",
)


def is_pre_auth(reason: str) -> bool:
    """Could this refusal have been produced by someone who does NOT hold the key? (AUDIT S4)"""
    return str(reason or "").startswith(PRE_AUTH_REASONS)

_lock = threading.Lock()
_strikes: Dict[str, Deque[Tuple[float, float]]] = {}        # source -> (time, weight)
_active: Dict[str, Dict[str, Any]] = {}                     # source -> {until, since, count, hold_s, reason}
_history: Dict[str, int] = {}                               # source -> number of quarantines so far


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


def single_laptop() -> bool:
    """True when every trusted source is a loopback address (a one-machine demo)."""
    import ipaddress
    from core import netconfig
    spec = os.environ.get("IM_TRUSTED_SOURCES", netconfig.TRUSTED_SOURCES)
    nets = []
    for item in str(spec).split(","):
        item = item.strip()
        if item:
            try:
                nets.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                return False                      # unparseable entry: do not guess, treat as multi-laptop
    return all(n.is_loopback for n in nets)


_noted = False


def mode() -> str:
    """'off' (not requested), 'auto-off-single-laptop' (requested but this is a one-laptop demo), or 'on'."""
    global _noted
    val = os.environ.get("IM_QUARANTINE", "").strip().lower()
    if val == "force":
        return "on"
    if val not in ("1", "true", "yes", "on", "auto"):
        return "off"
    if single_laptop():
        if not _noted:
            _noted = True
            import logging
            logging.getLogger("industrialmind.quarantine").info(
                "quarantine is OFF: every trusted source is loopback (single-laptop demo), a quarantine would also lock out SCADA")
        return "auto-off-single-laptop"
    return "on"


def enabled() -> bool:
    return mode() == "on"


def _exempt(source: str) -> bool:
    return source in {x.strip() for x in os.environ.get("IM_QUARANTINE_EXEMPT", "").split(",") if x.strip()}


def weight_for(reason: str) -> float:
    reason = str(reason or "")
    for prefix, w in STRIKE_WEIGHTS:
        if reason.startswith(prefix):
            return w
    return DEFAULT_WEIGHT


def shared_secret_warning() -> Optional[str]:
    """Why the quarantine is weaker without a per-device key registry (AUDIT S4), or None when it is not."""
    if not enabled():
        return None
    from core import hmac_auth
    if hmac_auth.has_key_registry():
        return None
    return ("quarantine is ON with a single shared HMAC secret: an attacker without the key cannot trigger it, but any "
            "holder of the shared key can sign as another address. Set IM_HMAC_KEYS for per-device keys to make it "
            "spoof-proof (AUDIT S4).")


def is_quarantined(source: str, now: Optional[float] = None) -> Tuple[bool, float]:
    """(quarantined, seconds_remaining). Expired quarantines are cleared here.

    Call this only for a source whose command has AUTHENTICATED (AUDIT S4) - see the module docstring."""
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


def record(source: str, reason: str, now: Optional[float] = None,
           authenticated: bool = False) -> Optional[Dict[str, Any]]:
    """Add a strike for a blocked command. Returns the quarantine record if THIS strike started one.

    `authenticated` must be True only when the command passed HMAC verification, i.e. the sender provably holds the key.
    Unauthenticated refusals NEVER score a strike (AUDIT S4): they are forgeable with a spoofed source address, so counting
    them lets an attacker quarantine the real operator. They are still dropped, logged and raised as an incident."""
    if not enabled() or _exempt(source):
        return None
    if not authenticated or is_pre_auth(reason):
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
    return {"enabled": enabled(), "mode": mode(), "single_laptop": single_laptop(), "quarantined": live,
            "limit": _env_float("IM_QUARANTINE_LIMIT", 12.0), "window_s": _env_float("IM_QUARANTINE_WINDOW_S", 30.0),
            "hold_s": _env_float("IM_QUARANTINE_HOLD_S", 60.0)}


def reset() -> None:
    with _lock:
        _strikes.clear()
        _active.clear()
        _history.clear()
