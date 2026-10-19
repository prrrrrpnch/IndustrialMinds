"""
middleware/incidents.py - incident correlation: turn a stream of single blocked/alerted commands into a few readable incidents.

A flat log of 400 DROP lines tells an analyst nothing. Here every non-PASS decision is attached to an INCIDENT: all events from the
same source close together in time. An incident carries what happened (counts per attack type, registers touched, verdicts), a short
timeline, a severity and a one-line summary, e.g. "Source A: 14 events in 9 s - Replay, Flood / Rate Limit - quarantined".

Rule-based and deterministic (the attack type comes from docs/attack_log.classify_reason, the same derivation the blocked-attack log
uses). An incident stays open while events keep arriving within IM_INCIDENT_GAP_S (default 30); after that the next event from the
same source opens a new one.

Severity (highest rule wins):
  critical  the source was quarantined, OR three or more distinct attack types from one source (multi-stage)
  high      any authenticity / authorisation / replay failure (forged, unsigned, unauthorised, unknown device)
  medium    flooding, bounds / rate-of-change / cross-register violations, invalid function or register
  low       only advisory model alerts (command was forwarded)
"""

from __future__ import annotations

import os
import threading
import time
from collections import Counter, OrderedDict
from typing import Any, Dict, List, Optional

from docs import attack_log
from docs.interfaces import MACHINE_BY_REGISTER

MAX_INCIDENTS = 200
MAX_TIMELINE = 40
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_HIGH_PREFIXES = ("HMAC_", "REPLAY_DETECTED", "UNKNOWN_DEVICE", "UNAUTHORIZED_", "UNTRUSTED_SOURCE")
_LOW_PREFIXES = ("PHYSICAL_MODEL",)

_lock = threading.Lock()
_incidents: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()   # id -> incident
_open_by_source: Dict[str, str] = {}
_seq = 0


def _gap() -> float:
    try:
        return float(os.environ.get("IM_INCIDENT_GAP_S", "30"))
    except ValueError:
        return 30.0


def _event_severity(verdict: str, reason: str) -> str:
    reason = str(reason or "")
    if reason.startswith(_LOW_PREFIXES) or verdict == "ALERT":
        return "low"
    if reason.startswith(_HIGH_PREFIXES):
        return "high"
    return "medium"


def _attack_type(verdict: str, reason: str) -> str:
    if verdict == "ALERT":
        return "Advisory Model Alert"
    if str(reason).startswith("SOURCE_QUARANTINED"):
        return "Blocked While Quarantined"
    if str(reason).startswith("UNAUTHORIZED_"):
        return "Unauthorized Write (Policy)"
    if str(reason).startswith("UNKNOWN_DEVICE"):
        return "Unknown Device"
    return attack_log.classify_reason(reason)


def _summarise(inc: Dict[str, Any]) -> str:
    span = max(0.0, inc["last_seen"] - inc["first_seen"])
    types = ", ".join(t for t, _ in Counter(inc["types"]).most_common(3))
    tail = " - source quarantined" if inc["quarantined"] else ""
    return f"{inc['source']}: {inc['events']} event(s) in {span:.0f} s - {types}{tail}"


def _severity(inc: Dict[str, Any]) -> str:
    sev = inc["_max_event_severity"]
    if inc["quarantined"] or len([t for t in inc["types"] if t not in ("Blocked While Quarantined", "Advisory Model Alert")]) >= 3:
        sev = "critical"
    return sev


def record(command: Dict[str, Any], decision: Dict[str, Any], quarantine_started: Optional[Dict[str, Any]] = None
           ) -> Optional[Dict[str, Any]]:
    """Attach one decision to an incident. PASS decisions are ignored. Returns a copy of the incident, or None."""
    verdict = decision.get("verdict")
    if verdict not in ("DROP", "ALERT"):
        return None
    global _seq
    now = float(command.get("timestamp") or time.time())
    source = str(command.get("source_ip") or "unknown")
    reason = str(decision.get("reason") or "")
    reg = command.get("register")
    reg_name = MACHINE_BY_REGISTER.get(reg, {}).get("name", f"#{reg}")
    with _lock:
        iid = _open_by_source.get(source)
        inc = _incidents.get(iid) if iid else None
        if inc is not None and now - inc["last_seen"] > _gap():
            inc["status"] = "closed"
            inc = None
        if inc is None:
            _seq += 1
            iid = f"INC-{_seq:04d}"
            inc = {"id": iid, "source": source, "status": "open", "first_seen": now, "last_seen": now, "events": 0,
                   "drops": 0, "alerts": 0, "types": [], "registers": [], "timeline": [], "quarantined": False,
                   "quarantine": None, "_max_event_severity": "low"}
            _incidents[iid] = inc
            _open_by_source[source] = iid
            while len(_incidents) > MAX_INCIDENTS:
                _incidents.popitem(last=False)
        inc["last_seen"] = max(inc["last_seen"], now)
        inc["events"] += 1
        inc["drops" if verdict == "DROP" else "alerts"] += 1
        atype = _attack_type(verdict, reason)
        if atype not in inc["types"] or atype in ("Blocked While Quarantined",):
            inc["types"].append(atype)
        if reg_name not in inc["registers"]:
            inc["registers"].append(reg_name)
        sev = _event_severity(verdict, reason)
        if _SEVERITY_RANK[sev] > _SEVERITY_RANK[inc["_max_event_severity"]]:
            inc["_max_event_severity"] = sev
        if quarantine_started:
            inc["quarantined"] = True
            inc["quarantine"] = {k: quarantine_started[k] for k in ("since", "until", "hold_s", "offence", "trigger")}
        if str(reason).startswith("SOURCE_QUARANTINED"):
            inc["quarantined"] = True
        if len(inc["timeline"]) < MAX_TIMELINE:
            inc["timeline"].append({"t": now, "tx_id": command.get("tx_id"), "verdict": verdict, "type": atype,
                                    "register": reg_name, "value": command.get("value"), "reason": reason.split(":", 1)[0]})
        inc["severity"] = _severity(inc)
        inc["summary"] = _summarise(inc)
        return _public(inc)


def _public(inc: Dict[str, Any]) -> Dict[str, Any]:
    out = {k: v for k, v in inc.items() if not k.startswith("_")}
    out["types"] = [{"type": t, "count": c} for t, c in Counter(x["type"] for x in inc["timeline"]).most_common()] \
        if inc["events"] <= MAX_TIMELINE else [{"type": t, "count": None} for t in inc["types"]]
    out["timeline"] = list(inc["timeline"])
    out["registers"] = list(inc["registers"])
    return out


def list_incidents(limit: int = 50) -> List[Dict[str, Any]]:
    """Newest first. Open incidents whose gap has passed are reported closed."""
    now = time.time()
    with _lock:
        for inc in _incidents.values():
            if inc["status"] == "open" and now - inc["last_seen"] > _gap():
                inc["status"] = "closed"
        return [_public(i) for i in list(_incidents.values())[::-1][:limit]]


def reset() -> None:
    global _seq
    with _lock:
        _incidents.clear()
        _open_by_source.clear()
        _seq = 0
