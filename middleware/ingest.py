"""
middleware/ingest.py - one external Modbus write turned into a security decision.

Split out of middleware_server.py (AUDIT A1), and the home of the fix for AUDIT A2: "business logic in a storage hook - the
entire security pipeline runs as a side effect of setValues(); the write handler should enqueue, not decide".

It now does exactly that. MiddlewareDataBlock.setValues stores the value and calls submit(), which puts the write on a
bounded FIFO queue and returns to the asyncio event loop immediately. One worker thread drains the queue and runs the
pipeline. One worker, not a pool: commands must be decided in the order they arrived, because the rate limiter, the replay
window and the cross-register rules are all order-dependent.

The arrival time is captured at submit(), not at dequeue, so a queued command is rate-limited and timestamped by when it
reached the middleware - the decision moving off the hot path must not change what the decision IS.
"""

from __future__ import annotations

import contextvars
import logging
import os
import queue
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

from core.interfaces import (make_command, REGISTER_MAP, MACHINE_BY_REGISTER, FRAME_BASE, FRAME_LEN)
from core import hmac_auth, attack_log
from middleware import cyber_agent, orchestrator, physical_agent
from middleware import trace as tracer
from middleware import forwarding, runtime
from pipeline.multi_model_pipeline import get_pipeline

log = logging.getLogger("industrialmind.middleware")

# Set by the transport for the duration of each Modbus request. Read here, which is why it lives here: the handler that
# needs a source address is _handle_downstream_write. Note that the decision worker runs on its OWN thread, where this
# context variable is NOT set - which is exactly why submit() captures the context and passes it along explicitly.
_request_ctx: contextvars.ContextVar = contextvars.ContextVar("im_request_ctx", default=None)

# AUDIT A2: the decision queue. Bounded, so a stall cannot grow without limit; a full queue is reported, never silent.
DECISION_QUEUE_MAX = int(os.environ.get("IM_DECISION_QUEUE", "500"))
_decision_queue: "queue.Queue[Optional[Dict[str, Any]]]" = queue.Queue(maxsize=DECISION_QUEUE_MAX)
_decision_thread: Optional[threading.Thread] = None
_dropped_writes = 0


def submit(address: int, values: List[int], ctx: Dict[str, Any]) -> bool:
    """Called from the datastore hook on the event loop. Enqueue and return; never decide here (AUDIT A2)."""
    global _dropped_writes
    job = {"address": address, "values": list(values), "ctx": dict(ctx), "arrival": time.time()}
    try:
        _decision_queue.put_nowait(job)
        return True
    except queue.Full:
        _dropped_writes += 1
        log.error("[MIDDLEWARE] DECISION QUEUE FULL (%s) - write to %s from %s was not evaluated; %s so far. "
                  "Nothing was forwarded, so the command did not reach the plant.",
                  DECISION_QUEUE_MAX, address, ctx.get("source_ip"), _dropped_writes)
        return False


def dropped_writes() -> int:
    """Writes the decision queue could not accept. They were NOT forwarded - failing closed."""
    return _dropped_writes


def _decision_worker() -> None:
    """Drain the queue in arrival order. Never dies: one bad write must not strand every later command."""
    while True:
        job = _decision_queue.get()
        if job is None:
            return
        try:
            _process_write(job["address"], job["values"], job["ctx"], arrival=job["arrival"])
        except Exception as exc:                                   # pragma: no cover - defensive
            log.exception("[MIDDLEWARE] decision worker failed on a write to %s: %s", job.get("address"), exc)
        finally:
            _decision_queue.task_done()


def start_worker() -> None:
    global _decision_thread
    if _decision_thread is None or not _decision_thread.is_alive():
        _decision_thread = threading.Thread(target=_decision_worker, name="decision-worker", daemon=True)
        _decision_thread.start()


def drain(timeout: float = 5.0) -> bool:
    """Wait for the queue to empty. Tests and the shutdown path only."""
    end = time.time() + timeout
    while time.time() < end:
        if _decision_queue.unfinished_tasks == 0:
            return True
        time.sleep(0.01)
    return _decision_queue.unfinished_tasks == 0


# =========================================================
# ROUTE ONE WRITE
# =========================================================

def _process_write(address: int, values: List[int], ctx: Dict[str, Any],
                   arrival: Optional[float] = None) -> None:
    """
    Routes one external Modbus write into the security pipeline.

      FRAME_BASE ........ signed command frame -> verified by Cyber Agent
      machine registers . plain unsigned write -> HMAC_MISSING
      anything else ..... probe of an unmapped address -> INVALID_REGISTER

    `arrival` is when the write reached the middleware (AUDIT A2). The decision now runs on a worker, so time.time() here
    is dequeue time, and using it would silently change what the rate limiter, the replay window and the reported latency
    measure. Called directly (tests, tools) it defaults to now, which is the old behaviour.
    """

    source_ip = ctx.get("source_ip") or runtime.UNKNOWN_SOURCE_IP
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
            runtime._from_raw(raw_value) if raw_value is not None else 0.0,
            source_ip=source_ip,
            source_port=source_port,
            function_code=function_code,
            raw_value=raw_value,
            auth=parsed["auth"],
            arrival=arrival,
        )
        return

    for i, raw_value in enumerate(values):

        _handle_downstream_write(
            address + i,
            runtime._from_raw(raw_value),
            source_ip=source_ip,
            source_port=source_port,
            function_code=function_code,
            raw_value=raw_value,
            auth=None,
            arrival=arrival,
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
    arrival: float | None = None,
) -> None:

    # When the write arrived, not when this worker picked it up (AUDIT A2).
    start_time = time.time() if arrival is None else arrival

    tx_id = str(uuid.uuid4())

    if source_ip is None:
        ctx = _request_ctx.get() or {}
        source_ip = ctx.get("source_ip") or runtime.UNKNOWN_SOURCE_IP
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

    with runtime._state_lock:

        registers_now = dict(
            runtime._plc_state["registers"]
        )

        # Projected plant state = targets already approved and still
        # ramping, else live telemetry. Used for cross-register checks.
        setpoints = dict(registers_now)
        for reg, pending in runtime._pending_commands.items():
            setpoints[reg] = pending["value"]

        current_state = {
            "registers": registers_now,

            "setpoints": setpoints,

            "timestamp": runtime._register_settled_since.get(
                register,
                runtime._plc_state["timestamp"]
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
    # Nothing is added to runtime._pending_commands.
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

    with runtime._state_lock:

        runtime._pending_commands[register] = {
            "tx_id": tx_id,
            "value": value,
            "time": start_time,
        }

    # -----------------------------------------------------
    # Forward approved command to REAL PLC
    # -----------------------------------------------------

    # -----------------------------------------------------
    # Hand the approved command to the forwarder thread and return (AUDIT C2).
    #
    # The decision is already made and published; what is left is blocking socket I/O, and it must not run on the event
    # loop. The trace and the delivery outcome are published by the worker once it knows whether the PLC took the write.
    # -----------------------------------------------------

    job = {
        "register": register,
        "register_name": register_name,
        "value": value,
        "tx_id": tx_id,
        "report": report,
        "alert": decision["verdict"] == "ALERT",
    }

    try:

        forwarding._forward_queue.put_nowait(job)

    except queue.Full:

        # The PLC has been unreachable long enough to fill the backlog. This is still an approved command that the plant
        # never received, so it is reported exactly like one the PLC refused - never dropped in silence.
        with runtime._state_lock:
            runtime._health["dropped_forwards"] += 1
            dropped = runtime._health["dropped_forwards"]

        log.error(
            f"[MIDDLEWARE] FORWARD QUEUE FULL ({forwarding.FORWARD_QUEUE_MAX}) - "
            f"dropping {register_name}={value:.2f} tx={tx_id}; "
            f"{dropped} approved command(s) dropped so far. The PLC is not keeping up or is unreachable."
        )

        forwarding._report_undelivered(job, "FORWARD_QUEUE_FULL: approved, but the PLC backlog was full and the command was dropped")



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



# forwarding publishes the trace once it knows whether the PLC took the write; it cannot import this module (this module
# imports it), so the function is handed over here.
forwarding._publish_trace = _publish_trace
