"""
Orchestrator — fuses Cyber Agent and Physical Agent verdicts into one decision.
DROP if either agent fails. PASS only if both (or the only one running) pass.
On the upstream (PLC -> SCADA) path, cyber_verdict will be None — only the
Physical Agent runs there, per the team's design.
"""

from __future__ import annotations

import atexit
import json
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
_forward_queue: "queue.Queue[Optional[dict]]" = queue.Queue(maxsize=1000)
_forward_worker: Optional[threading.Thread] = None
_forward_lock = threading.Lock()


def _forward_loop() -> None:
    while True:
        payload = _forward_queue.get()
        if payload is None:
            return
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                f"{netconfig.DASHBOARD_URL}/api/security-event",
                data=data,
                headers={"Content-Type": "application/json"},
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
    global _forward_worker
    with _forward_lock:
        if _forward_worker is None or not _forward_worker.is_alive():
            _forward_worker = threading.Thread(target=_forward_loop, name="dashboard-forwarder", daemon=True)
            _forward_worker.start()
    try:
        _forward_queue.put_nowait(payload)
    except queue.Full:
        pass  # dashboard unreachable/slow: drop the notification, never block the middleware


atexit.register(_shutdown_forwarder)


def decide(cyber_verdict: dict | None, physical_verdict: dict, start_time: float = None) -> dict:
    """
    cyber_verdict: verdict dict from cyber_agent.check(), or None on the upstream path.
    physical_verdict: verdict dict from physical_agent.check_command() or check_feedback().
    start_time: time.time() captured when the command first arrived, for latency measurement.
    """
    tx_id = physical_verdict["tx_id"]
    direction = "downstream" if cyber_verdict is not None else "upstream"

    if cyber_verdict is not None and not cyber_verdict["pass"]:
        verdict, reason = "DROP", cyber_verdict["reason"]
    elif not physical_verdict["pass"]:
        verdict, reason = "DROP", physical_verdict["reason"]
    else:
        verdict, reason = "PASS", "OK"

    latency_ms = round((time.time() - start_time) * 1000, 3) if start_time else 0.0

    decision = make_decision(tx_id, verdict, reason, latency_ms, direction)
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