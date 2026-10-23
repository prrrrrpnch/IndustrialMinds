"""
middleware/polling.py - the PLC read path: poll real telemetry, settle pending commands, report upstream.

Split out of middleware_server.py (AUDIT A1). Runs on its own daemon thread and shares the PLC client with the forwarder
through forwarding._plc_io_lock.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, Optional

import requests

from core.interfaces import MACHINES, MACHINE_BY_REGISTER, NUM_REGISTERS, REGISTER_MAP, make_verdict
from core import attack_log
from middleware import orchestrator, physical_agent
from middleware import forwarding, runtime
from pipeline.multi_model_pipeline import get_pipeline

log = logging.getLogger("industrialmind.middleware")

_last_telemetry_report = 0.0
_last_telemetry_log = 0.0
_last_poll_error_log = 0.0
POLL_ERROR_LOG_INTERVAL = 5.0


def _internal_sync_write(block, address, values) -> None:
    """Set by middleware_server (it owns the datastore classes)."""
    raise RuntimeError("polling._internal_sync_write was not wired up")


# =========================================================
# DASHBOARD - PLC -> SCADA RESPONSE
# =========================================================

def _report_plc_response(
    tx_id: str,
    register: int,
    value: float,
    latency_ms: float
) -> None:

    """
    Report an ACTUAL PLC confirmation.

    This is called ONLY when:

      1. The original command was PASSed.
      2. It was forwarded to the real PLC.
      3. PLC feedback confirms the requested value.

    DROPped commands never reach this function.
    """

    register_name = REGISTER_MAP[register]["name"]

    payload = {
        "tx_id": tx_id,
        "direction": "plc_to_scada",
        "verdict": "PASS",
        "reason": "PLC confirmed the requested value.",
        "command": f"{register_name} → {value:.2f}",
        "latency_ms": round(latency_ms, 2),
        "timestamp": time.time(),
    }

    try:

        response = requests.post(
            f"{runtime.DASHBOARD_URL}/api/security-event",
            json=payload,
            headers=runtime._dashboard_headers(),
            timeout=1
        )

        if response.ok:

            log.info(
                f"[MIDDLEWARE] "
                f"PLC RESPONSE "
                f"tx={tx_id} "
                f"{register_name}={value:.2f}"
            )

        else:

            log.warning(
                f"[MIDDLEWARE] "
                f"Dashboard rejected PLC response: "
                f"{response.status_code}"
            )

    except Exception as e:

        log.warning(
            f"[MIDDLEWARE] "
            f"Could not report PLC response: {e}"
        )



# =========================================================
# DASHBOARD - REAL PLC TELEMETRY
# =========================================================

def _report_telemetry() -> None:

    """
    Send actual PLC telemetry to dashboard.
    """

    with runtime._state_lock:

        registers = {
            REGISTER_MAP[reg]["name"]:
            runtime._plc_state["registers"][reg]
            for reg in runtime._ALL_REGISTERS
        }

    payload = {
        "registers": registers
    }

    try:

        requests.post(
            f"{runtime.DASHBOARD_URL}/api/telemetry",
            json=payload,
            headers=runtime._dashboard_headers(),
            timeout=1
        )

    except Exception:
        pass



# =========================================================
# LIVE TELEMETRY LOG LINE
# =========================================================

def _log_live_telemetry(now: float, pipeline: Any) -> None:

    global _last_telemetry_log

    if now - _last_telemetry_log < runtime.TELEMETRY_LOG_INTERVAL:
        return

    _last_telemetry_log = now

    with runtime._state_lock:
        values = " ".join(
            f"{MACHINE_BY_REGISTER[reg]['name']}={runtime._plc_state['registers'][reg]:.1f}"
            for reg in runtime._ALL_REGISTERS
        )

    health = pipeline.health_report()

    if health.get("status") == "OK":
        score = health.get("anomaly_score")
        prob = health.get("attack_probability")
        health_txt = (
            f"plant={health.get('plant_state')} "
            f"score={'n/a' if score is None else f'{score:.3f}'} "
            f"p_attack={'n/a' if prob is None else f'{prob:.3f}'} "
            f"bounds_viol={len(health.get('bounds_violations') or [])}"
        )
    else:
        health_txt = (
            f"plant={health.get('plant_state', health.get('status'))} "
            f"window={health.get('window_fill')}/{health.get('window_size')}"
        )

    log.info(f"[TELEMETRY] {values} | {health_txt}")



# =========================================================
# PLC POLLING
# =========================================================

ENVELOPE_ALERTS = os.environ.get("IM_ENVELOPE_ALERTS", "1") != "0"
ENVELOPE_ALERT_INTERVAL = float(os.environ.get("IM_ENVELOPE_ALERT_SECONDS", "30"))
_last_envelope_alert: Dict[str, float] = {}


def _check_upstream_envelope(registers: Dict[Any, float], now: float) -> None:
    """Raise an upstream DROP decision for sensors outside the measured envelope (rate-limited per sensor)."""
    try:
        verdict = physical_agent.check_telemetry(registers)
        if verdict["pass"]:
            return
        fresh = [v for v in verdict["violations"] if now - _last_envelope_alert.get(v["tag"], 0.0) >= ENVELOPE_ALERT_INTERVAL]
        if not fresh:
            return
        for v in fresh:
            _last_envelope_alert[v["tag"]] = now
        verdict["tx_id"] = f"UP-ENV-{int(now * 1000)}"
        verdict["command"] = "UPSTREAM TELEMETRY " + ",".join(v["tag"] for v in fresh)
        orchestrator.decide(None, verdict, now)
        log.warning("[UPSTREAM] %s", verdict["reason"])
    except Exception:
        log.exception("upstream envelope check failed - ignored (rules elsewhere still gate)")


INVARIANT_ALERT_INTERVAL = float(os.environ.get("IM_INVARIANT_ALERT_SECONDS", "30"))
_last_invariant_alert: Dict[str, float] = {}


def _check_upstream_invariants(pipeline: Any, now: float) -> None:
    """Physical-invariant rules (advisory, only when IM_INVARIANTS=1): publish an upstream ALERT for a violated invariant even when no
    command is flowing (rate-limited per invariant). ALERT, not DROP: the telemetry is still mirrored to SCADA."""
    try:
        monitor = getattr(pipeline, "invariants", None)
        if monitor is None:
            return
        rep = monitor.assess()
        if not rep.get("threat_flag"):
            return
        fresh = [v for v in rep["violated"] if now - _last_invariant_alert.get(v["id"], 0.0) >= INVARIANT_ALERT_INTERVAL]
        if not fresh:
            return
        for v in fresh:
            _last_invariant_alert[v["id"]] = now
        verdict = make_verdict(f"UP-INV-{int(now * 1000)}", True, "OK", "physical")
        verdict["command"] = "UPSTREAM INVARIANT " + ",".join(v["id"] for v in fresh[:3])
        advisory = {"threat_flag": True, "flagged_by": [f"invariant:{v['id']}" for v in fresh[:3]], "suspect_stage": fresh[0]["stage"],
                    "explanation": "physical invariant violated: " + fresh[0]["text"]}
        orchestrator.decide(None, verdict, now, physical_advisory=advisory)
        log.warning("[UPSTREAM] physical invariant violated: %s", fresh[0]["text"])
    except Exception:
        log.exception("upstream invariant check failed - ignored (rules elsewhere still gate)")


def _expire_pending_if_stale(reg: int, pending: dict, reported: float, now: float) -> bool:
    """Drop a PASSed command that was forwarded but whose register never settled
    to the commanded value within runtime.PENDING_COMMAND_TIMEOUT_S. Returns True if it
    was expired. Keeps a never-settling command from being projected forever
    into the cross-register setpoints snapshot. Safe to call under no lock; it
    takes runtime._state_lock for the mutation itself."""
    if now - pending["time"] <= runtime.PENDING_COMMAND_TIMEOUT_S:
        return False
    with runtime._state_lock:
        runtime._pending_commands.pop(reg, None)
        runtime._register_settled_since[reg] = now
    log.warning(
        f"[MIDDLEWARE] command tx={pending['tx_id']} "
        f"reg={REGISTER_MAP[reg]['name']} value={pending['value']:.2f} was "
        f"forwarded but the PLC never settled to it within "
        f"{runtime.PENDING_COMMAND_TIMEOUT_S:.0f}s (last reported {reported:.2f}); "
        f"expiring it. The plant may be displaced (attack/recovery) or the "
        f"PLC may be unreachable."
    )
    return True


def _poll_once(
    block: "Any"   # middleware_server.MiddlewareDataBlock
) -> None:

    global _last_telemetry_report

    """
    One polling cycle:

    1. Read actual PLC telemetry.
    2. Update middleware state.
    3. Synchronize SCADA-facing registers.
    4. Check PASSed pending commands.
    5. Create PLC -> SCADA response only after
       actual PLC confirmation.
    """

    if forwarding._plc_client is None:
        return

    try:

        # -------------------------------------------------
        # Read REAL PLC
        # -------------------------------------------------

        with forwarding._plc_io_lock:

            if not forwarding._plc_client.is_socket_open():

                forwarding._plc_client.connect()

            result = forwarding._plc_client.read_holding_registers(
                0,
                count=NUM_REGISTERS
            )

        if result.isError():
            _note_poll_failure()
            return

        _note_poll_success()

        raws = result.registers

        now = time.time()

        # -------------------------------------------------
        # Update middleware's copy of REAL PLC state
        # -------------------------------------------------

        with runtime._state_lock:

            for reg, raw in zip(
                runtime._ALL_REGISTERS,
                raws
            ):

                runtime._plc_state["registers"][reg] = (
                    runtime._from_raw(raw)
                )

            runtime._plc_state["timestamp"] = now

            # -------------------------------------------------
            # Mirror REAL PLC state into SCADA datastore
            # -------------------------------------------------

            for reg, raw in zip(
                runtime._ALL_REGISTERS,
                raws
            ):

                _internal_sync_write(
                    block,
                    reg,
                    [raw]
                )

        # -------------------------------------------------
        # Dashboard telemetry: once per second
        #
        # PLC polling remains every 0.2 seconds.
        # -------------------------------------------------

        if (
            now - _last_telemetry_report
            >= runtime.TELEMETRY_REPORT_INTERVAL
        ):

            _report_telemetry()

            _last_telemetry_report = now

        # -------------------------------------------------
        # Feed the PhysicalModel sliding window and log a
        # live telemetry + plant-state line.
        # -------------------------------------------------

        pipeline = get_pipeline()
        pipeline.ingest_telemetry(
            dict(runtime._plc_state["registers"]),
            runtime._plc_state.get("timestamp") or now,
        )
        _log_live_telemetry(now, pipeline)

        # -------------------------------------------------
        # Upstream sensor-envelope RULE (measured SWaT envelope).
        # Detect-and-ALERT: the telemetry is still mirrored to SCADA; an
        # upstream DROP decision is raised on the dashboard, at most once
        # per sensor per ENVELOPE_ALERT_INTERVAL seconds.
        # -------------------------------------------------

        if ENVELOPE_ALERTS:
            _check_upstream_envelope(dict(runtime._plc_state["registers"]), now)
        _check_upstream_invariants(pipeline, now)

        # -------------------------------------------------
        # Check ONLY commands that were PASSed
        # -------------------------------------------------

        for reg in list(runtime._pending_commands.keys()):

            with runtime._state_lock:

                pending = runtime._pending_commands.get(reg)

                if pending is None:
                    continue

                reported = (
                    runtime._plc_state["registers"][reg]
                )

            # -------------------------------------------------
            # Check actual PLC value
            # -------------------------------------------------

            feedback_ok = (
                abs(
                    reported -
                    pending["value"]
                )
                < runtime.FEEDBACK_SETTLED_TOLERANCE
            )

            # -------------------------------------------------
            # PLC has NOT confirmed yet.
            #
            # No right-side event.
            # -------------------------------------------------

            if not feedback_ok:

                # Expire a command that never settled, so its value stops
                # being projected into the cross-register setpoints snapshot
                # and the dashboard stops showing it as forever-pending.
                _expire_pending_if_stale(reg, pending, reported, now)

                continue

            # -------------------------------------------------
            # PLC HAS confirmed the command.
            #
            # Now create the PLC -> SCADA response.
            # -------------------------------------------------

            latency_ms = (
                now - pending["time"]
            ) * 1000

            _report_plc_response(
                tx_id=pending["tx_id"],
                register=reg,
                value=pending["value"],
                latency_ms=latency_ms
            )

            # -------------------------------------------------
            # Remove pending command so the same response
            # is not reported repeatedly.
            # -------------------------------------------------

            with runtime._state_lock:

                runtime._pending_commands.pop(
                    reg,
                    None
                )

                runtime._register_settled_since[reg] = now

    except Exception as e:

        _note_poll_failure()

        # The poll runs every 0.2 s; if the PLC laptop is down or unreachable
        # this would flood the log 5x/second. Rate-limit to one actionable
        # line every POLL_ERROR_LOG_INTERVAL seconds, and say what to check.
        global _last_poll_error_log
        now_err = time.time()
        if now_err - _last_poll_error_log >= POLL_ERROR_LOG_INTERVAL:
            _last_poll_error_log = now_err
            log.error(
                f"[MIDDLEWARE] cannot reach the PLC at "
                f"{runtime.PLC_HOST}:{runtime.PLC_PORT} ({e}). Retrying every "
                f"{runtime.POLL_INTERVAL:.1f}s. Check: the PLC process is running, "
                f"IM_PLC_HOST is correct, and the PLC laptop's firewall "
                f"allows this host inbound on {runtime.PLC_PORT}."
            )



# =========================================================
# POLLING LOOP
# =========================================================

def _note_poll_success() -> None:
    with runtime._state_lock:
        runtime._health["plc_connected"] = True
        runtime._health["consecutive_poll_failures"] = 0
        runtime._health["last_plc_ok"] = time.time()


def _note_poll_failure() -> None:
    with runtime._state_lock:
        runtime._health["plc_connected"] = False
        runtime._health["consecutive_poll_failures"] += 1


def _poll_delay() -> float:
    """How long to wait before the next poll (AUDIT C4).

    While the PLC answers, this is the normal 0.2 s cadence. While it does not, the interval doubles up to
    runtime.POLL_BACKOFF_MAX: against a dead PLC the fixed 0.2 s retry made ~18,000 connection attempts an hour, each one a
    timeout-bounded socket operation holding forwarding._plc_io_lock, which is both pointless load and a self-inflicted delay on the
    forwarder. Backoff is capped so recovery is still detected within a few seconds, and reset to 0.2 s by the first
    successful read."""

    with runtime._state_lock:
        failures = runtime._health["consecutive_poll_failures"]

    if failures <= runtime.POLL_BACKOFF_AFTER:
        return runtime.POLL_INTERVAL

    return min(runtime.POLL_INTERVAL * (2 ** (failures - runtime.POLL_BACKOFF_AFTER)), runtime.POLL_BACKOFF_MAX)


# How often the middleware tells the dashboard what it knows about the PLC (AUDIT A6/N6).
MIDDLEWARE_HEALTH_INTERVAL = 5.0
_last_health_report = 0.0


def _report_health_if_due() -> None:
    global _last_health_report
    now = time.time()
    if now - _last_health_report < MIDDLEWARE_HEALTH_INTERVAL:
        return
    _last_health_report = now
    try:
        orchestrator.forward_middleware_health(runtime.health_snapshot())
    except Exception:                                             # pragma: no cover - never let telemetry break the poll
        pass


def _poll_plc_loop(
    block: "Any"   # middleware_server.MiddlewareDataBlock
) -> None:

    while True:

        _poll_once(block)

        _report_health_if_due()

        time.sleep(
            _poll_delay()
        )

