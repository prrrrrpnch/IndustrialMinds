"""
middleware/trace.py - Phase 9 packet-tracer: a hop-by-hop record of what every layer computed for ONE command.

The trace is built from the REAL verdicts, model reports and decision the pipeline just produced (nothing is re-decided
or simulated here). The rule agents stop at the first failing check, so the per-check list is reconstructed from the
fixed check order: checks before the failure PASS, the failing one FAILs, the rest are NOT_RUN. Values shown next to a
check (rate counts, bounds, rate limits, thresholds) are read from the same state the agents used.

Hops, in the order a downstream command meets them:
    1 arrival          socket peer, function code, register, value, signature present?
    2 cyber_rules      whitelist, function code, register allow-list, rate limit, HMAC, replay   (deterministic rules)
    3 cyber_model      advisory score (NO_MODEL: the cyber branch is rules-only by design)
    4 physical_rules   register/actuator check, bounds, rate-of-change, cross-register           (deterministic rules)
    5 physical_model   advisory SWaT-trained window model (plant_state, scores, flagged_by)
    6 orchestrator     fusion inputs -> branch taken -> verdict
    7 outcome          forwarded to the PLC, or dropped and where the drop was logged   (added by the middleware)
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from docs import hmac_auth
from docs.interfaces import CROSS_REGISTER_RULES, MACHINE_BY_REGISTER

CYBER_ORDER = ["source_whitelist", "function_code", "register_allowlist", "rate_limit", "hmac", "replay"]
_CYBER_BY_PREFIX = {"UNTRUSTED_SOURCE": "source_whitelist", "INVALID_FUNCTION_CODE": "function_code",
                    "INVALID_REGISTER": "register_allowlist", "RATE_LIMIT_EXCEEDED": "rate_limit",
                    "HMAC_": "hmac", "REPLAY_DETECTED": "replay"}
PHYSICAL_ORDER = ["register_known", "actuator_only", "bounds", "rate_of_change", "cross_register"]
_PHYS_BY_PREFIX = {"UNKNOWN_REGISTER": "register_known", "WRITE_TO_SENSOR_REGISTER": "actuator_only",
                   "OUT_OF_BOUNDS": "bounds", "RATE_OF_CHANGE_EXCEEDED": "rate_of_change",
                   "CROSS_REGISTER_VIOLATION": "cross_register"}


def _failed(reason: str, table: Dict[str, str]) -> Optional[str]:
    for prefix, name in table.items():
        if reason.startswith(prefix):
            return name
    return None


def _sequence(order: List[str], verdict: Dict[str, Any], table: Dict[str, str], detail: Dict[str, str]) -> List[Dict[str, Any]]:
    passed = bool(verdict.get("pass"))
    bad = None if passed else (_failed(str(verdict.get("reason", "")), table) or order[-1])
    out, failed_seen = [], False
    for name in order:
        if failed_seen:
            out.append({"check": name, "result": "NOT_RUN", "detail": "an earlier check already failed"})
        elif name == bad:
            out.append({"check": name, "result": "FAIL", "detail": str(verdict.get("reason"))})
            failed_seen = True
        else:
            out.append({"check": name, "result": "PASS", "detail": detail.get(name, "")})
    return out


def cyber_checks(command: Dict[str, Any], verdict: Dict[str, Any]) -> List[Dict[str, Any]]:
    from middleware import cyber_agent
    auth = command.get("auth")
    ip = command.get("source_ip", "")
    recent = len(cyber_agent._request_timestamps.get(ip, ()))
    detail = {
        "source_whitelist": f"{ip} is in the trusted list",
        "function_code": f"FC {command.get('function_code')} is allowed",
        "register_allowlist": f"register {command.get('register')} is a known machine",
        "rate_limit": f"{recent} request(s) from {ip} in the last {cyber_agent.RATE_WINDOW_SECONDS:g}s (limit {cyber_agent.RATE_LIMIT_PER_SEC})",
        "hmac": f"tag verified ({verdict.get('auth_status', 'HMAC_OK')})",
        "replay": "nonce unused and payload not duplicated",
    }
    return _sequence(CYBER_ORDER, verdict, _CYBER_BY_PREFIX, detail)


def physical_checks(command: Dict[str, Any], verdict: Dict[str, Any], state: Dict[str, Any]) -> List[Dict[str, Any]]:
    from middleware import physical_agent as pa
    reg = command.get("register")
    m = MACHINE_BY_REGISTER.get(reg, {})
    value = command.get("value")
    detail = {"register_known": f"{m.get('name', reg)} exists", "actuator_only": f"{m.get('name', reg)} is an actuator (writable)"}
    if m and value is not None:
        detail["bounds"] = f"{float(value):.2f} within [{m['min']}, {m['max']}] {m.get('unit', '')}"
        cur = pa._get_value(state, reg)
        if cur is not None and reg in pa._RATE_LIMIT_PER_SEC:
            dt = max(command.get("timestamp", time.time()) - state.get("timestamp", time.time()), pa._MIN_DT)
            detail["rate_of_change"] = (f"change {abs(float(value) - cur):.2f} <= max {pa._RATE_LIMIT_PER_SEC[reg] * dt:.2f} "
                                        f"({pa._RATE_LIMIT_PER_SEC[reg]:.1f}/s over {dt:.2f}s)")
        else:
            detail["rate_of_change"] = "no baseline value: not enforced"
        involved = [r["id"] for r in CROSS_REGISTER_RULES if reg in {c[0] for c in r["conditions"]}]
        detail["cross_register"] = f"{len(involved)} stage rule(s) evaluated on the projected plant state" + (f": {', '.join(involved)}" if involved else "")
    return _sequence(PHYSICAL_ORDER, verdict, _PHYS_BY_PREFIX, detail)


def _outcome(passed: Optional[bool]) -> str:
    return "NOT_RUN" if passed is None else ("PASS" if passed else "FAIL")


def build_trace(command: Dict[str, Any], state: Dict[str, Any], cyber_rule: Dict[str, Any], gate_cyber: Dict[str, Any],
                cyber_ml: Dict[str, Any], phys_rule: Dict[str, Any], phys_ml: Dict[str, Any], decision: Dict[str, Any],
                timings_ms: Dict[str, Any], mode: str) -> Dict[str, Any]:
    reg = command.get("register")
    m = MACHINE_BY_REGISTER.get(reg, {})
    auth = command.get("auth")
    signature = "absent" if auth is None else ("malformed" if auth.get("malformed") else "present")
    fusion = decision.get("fusion", {})
    wire = {}
    if auth and not auth.get("malformed") and auth.get("nonce") is not None:
        # The frame's nonce as the four 16-bit register words a Wireshark/tshark capture shows (words 3..6 of the FC16 write):
        # this is how a packet on the wire is matched to this trace.
        wire = {"nonce": f"{int(auth['nonce']):016x}", "nonce_words": hmac_auth._u64_to_regs(int(auth["nonce"])),
                "frame_timestamp_ms": auth.get("timestamp_ms")}
    hops = [
        {"hop": "arrival", "layer": "network", "outcome": "INFO", "ms": None,
         "values": {"source": f"{command.get('source_ip')}:{command.get('source_port')}", "function_code": command.get("function_code"),
                    "register": f"{m.get('name', reg)} (#{reg})", "requested_value": command.get("value"),
                    "raw_value": command.get("raw_value"), "signature": signature, **wire},
         "checks": []},
        {"hop": "cyber_rules", "layer": "cyber", "outcome": _outcome(cyber_rule.get("pass")), "ms": None,
         "values": {"reason": cyber_rule.get("reason"), "auth_status": cyber_rule.get("auth_status", "NOT_CHECKED")},
         "checks": cyber_checks(command, cyber_rule)},
        {"hop": "cyber_model", "layer": "cyber", "outcome": "INFO", "ms": cyber_ml.get("latency_ms"),
         "values": {"status": cyber_ml.get("status"), "anomaly_score": cyber_ml.get("anomaly_score"),
                    "threat_flag": cyber_ml.get("threat_flag"), "mode": mode,
                    "gate_reason": gate_cyber.get("reason") if gate_cyber is not cyber_rule else "(unchanged)"},
         "checks": []},
        {"hop": "physical_rules", "layer": "physical", "outcome": _outcome(phys_rule.get("pass")), "ms": None,
         "values": {"reason": phys_rule.get("reason")},
         "checks": physical_checks(command, phys_rule, state)},
        {"hop": "physical_model", "layer": "physical", "outcome": "ALERT" if phys_ml.get("threat_flag") else "INFO",
         "ms": phys_ml.get("latency_ms"),
         "values": {"status": phys_ml.get("status"), "plant_state": phys_ml.get("plant_state"),
                    "anomaly_score": phys_ml.get("anomaly_score"), "attack_probability": phys_ml.get("attack_probability"),
                    "threat_flag": phys_ml.get("threat_flag"), "flagged_by": phys_ml.get("flagged_by"),
                    "bounds_violations": len(phys_ml.get("bounds_violations") or []),
                    "thresholds": {"isolation_forest": phys_ml.get("threshold"), "classifier": phys_ml.get("clf_threshold")}},
         "checks": []},
        {"hop": "orchestrator", "layer": "orchestrator", "outcome": decision.get("verdict"), "ms": None,
         "values": {"inputs": fusion.get("inputs"), "branch": fusion.get("branch"), "verdict": decision.get("verdict"),
                    "reason": decision.get("reason"), "latency_ms": decision.get("latency_ms")},
         "checks": []},
    ]
    return {"tx_id": command.get("tx_id"), "time": command.get("timestamp"), "direction": decision.get("direction", "downstream"),
            "verdict": decision.get("verdict"), "reason": decision.get("reason"), "hops": hops,
            "timings_ms": {k: v for k, v in timings_ms.items() if v is not None}}


def add_outcome(trace: Dict[str, Any], forwarded: Optional[bool], logged_to: Optional[str], note: str = "") -> Dict[str, Any]:
    """Final hop: the real forward-or-drop result (set by the middleware once it knows)."""
    dropped = trace.get("verdict") == "DROP"
    trace["hops"] = [h for h in trace["hops"] if h["hop"] != "outcome"] + [{
        "hop": "outcome", "layer": "middleware", "outcome": "DROP" if dropped else ("PASS" if forwarded else "FAIL"), "ms": None,
        "values": {"forwarded_to_plc": bool(forwarded) if not dropped else False,
                   "dropped": dropped, "logged_to": logged_to, "note": note},
        "checks": []}]
    return trace
