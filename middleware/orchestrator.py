"""
Orchestrator — fuses Cyber Agent and Physical Agent verdicts into one decision.
RULE-BASED four-branch table (a learned fusion was tried on SWaT and rejected:
docs/reports/fusion_training_report_swat.md - worse than the physical model alone on the test block):

    cyber rules fail                      -> DROP  (reason = cyber reason)
    physical RULES fail                   -> DROP  (reason = physical reason)
    rules pass, physical MODEL flags      -> ALERT (command is FORWARDED; advisory, never blocks)
    otherwise                             -> PASS

The physical ML model is advisory (it cannot block legitimate traffic on its own), so a model flag
produces ALERT, not DROP. On the upstream (PLC -> SCADA) path, cyber_verdict will be None — only the
Physical Agent runs there, per the team's design.
"""

from __future__ import annotations

import atexit
import json
import os
import queue
import threading
import time
import urllib.request
from typing import Optional

from docs import netconfig
from docs.interfaces import make_decision

_decision_log = []


# Decisions are forwarded to the dashboard by ONE long-lived worker thread that is
# drained at interpreter exit. (A daemon thread per decision was still inside urllib
# when CPython 3.13 finalised and segfaulted the process, e.g. at the end of unit tests.)
_forward_queue: "queue.Queue[Optional[tuple]]" = queue.Queue(maxsize=1000)
_forward_worker: Optional[threading.Thread] = None
_forward_lock = threading.Lock()


def _forward_loop() -> None:
    while True:
        item = _forward_queue.get()
        if item is None:
            return
        path, payload = item
        try:
            data = json.dumps(payload).encode("utf-8")
            headers = {"Content-Type": "application/json"}
            token = os.environ.get("IM_DASHBOARD_TOKEN", "").strip()
            if token:
                headers["X-IM-Token"] = token
            req = urllib.request.Request(
                f"{netconfig.DASHBOARD_URL}{path}",
                data=data,
                headers=headers,
            )
            urllib.request.urlopen(req, timeout=1.0)
        except Exception:
            pass  # Silently ignore forwarding errors so middleware operation is never affected


def _shutdown_forwarder() -> None:
    worker = _forward_worker
    if worker is not None and worker.is_alive():
        try:
            _forward_queue.put_nowait(None)
        except queue.Full:
            pass
        worker.join(timeout=2.0)


def _forward_decision_to_dashboard(payload: dict) -> None:
    _enqueue("/api/security-event", payload)


def forward_trace_to_dashboard(trace: dict) -> None:
    """Phase 9 packet-tracer: hand one per-tx hop-by-hop trace to the dashboard (same non-blocking worker)."""
    _enqueue("/api/trace", trace)


def forward_incident_to_dashboard(incident: dict) -> None:
    """Hand the current state of one correlated incident to the dashboard (same non-blocking worker)."""
    _enqueue("/api/incident", incident)


def _enqueue(path: str, payload: dict) -> None:
    global _forward_worker
    with _forward_lock:
        if _forward_worker is None or not _forward_worker.is_alive():
            _forward_worker = threading.Thread(target=_forward_loop, name="dashboard-forwarder", daemon=True)
            _forward_worker.start()
    try:
        _forward_queue.put_nowait((path, payload))
    except queue.Full:
        pass  # dashboard unreachable/slow: drop the notification, never block the middleware


atexit.register(_shutdown_forwarder)


def decide(cyber_verdict: dict | None, physical_verdict: dict, start_time: float = None,
           physical_advisory: dict | None = None) -> dict:
    """
    cyber_verdict: verdict dict from cyber_agent.check(), or None on the upstream path.
    physical_verdict: verdict dict from physical_agent.check_command() or check_feedback().
    start_time: time.time() captured when the command first arrived, for latency measurement.
    physical_advisory: PhysicalModel assessment (threat_flag / flagged_by / plant_state), or None. Only a
    threat_flag raised while both rule layers pass yields ALERT.
    """
    tx_id = physical_verdict["tx_id"]
    direction = "downstream" if cyber_verdict is not None else "upstream"

    if cyber_verdict is not None and not cyber_verdict["pass"]:
        verdict, reason = "DROP", cyber_verdict["reason"]
    elif not physical_verdict["pass"]:
        verdict, reason = "DROP", physical_verdict["reason"]
    elif physical_advisory and physical_advisory.get("threat_flag"):
        flagged = "+".join(physical_advisory.get("flagged_by") or ["model"])
        verdict, reason = "ALERT", f"PHYSICAL_MODEL:{flagged}"
    else:
        verdict, reason = "PASS", "OK"

    latency_ms = round((time.time() - start_time) * 1000, 3) if start_time else 0.0

    decision = make_decision(tx_id, verdict, reason, latency_ms, direction)
    adv_flag = bool(physical_advisory and physical_advisory.get("threat_flag"))
    cyber_ok = None if cyber_verdict is None else bool(cyber_verdict["pass"])
    decision["fusion"] = {          # Phase 9: what the fusion saw and which branch of the table fired
        "inputs": {"cyber_rules_pass": cyber_ok, "cyber_reason": None if cyber_verdict is None else cyber_verdict["reason"],
                   "physical_rules_pass": bool(physical_verdict["pass"]), "physical_reason": physical_verdict["reason"],
                   "physical_model_flag": adv_flag,
                   "physical_model_flagged_by": list((physical_advisory or {}).get("flagged_by") or [])},
        "branch": {"DROP": ("cyber_rules_failed" if cyber_ok is False else "physical_rules_failed"),
                   "ALERT": "rules_passed_physical_model_flagged", "PASS": "all_clear"}[verdict],
    }
    _decision_log.append(decision)

    payload = {
        "tx_id": decision["tx_id"],
        "direction": "scada_to_plc" if direction == "downstream" else "plc_to_scada",
        "verdict": decision["verdict"],
        "reason": decision["reason"],
        "latency_ms": decision["latency_ms"],
        "command": physical_verdict.get("command", "MODBUS_COMMAND"),
    }
    _forward_decision_to_dashboard(payload)

    return decision



def get_log() -> list:
    """Returns all logged decisions so far — this is what the dashboard will read."""
    return list(_decision_log)


def reset_log() -> None:
    """Clears the decision log — call this between test runs."""
    _decision_log.clear()