"""
middleware/forwarding.py - everything that talks to the real PLC on the write path.

Split out of middleware_server.py (AUDIT A1). Holds the Modbus client, the lock that serialises it, and the single worker
thread that performs approved writes off the asyncio event loop (AUDIT C2).
"""

from __future__ import annotations

import logging
import os
import queue
import threading
from typing import Any, Dict, Optional

from pymodbus.client import ModbusTcpClient

from core.interfaces import REGISTER_MAP
from middleware import orchestrator
from middleware import runtime

log = logging.getLogger("industrialmind.middleware")

_plc_client: ModbusTcpClient | None = None

# Every call on _plc_client is serialised here (AUDIT A3/C2). pymodbus happens to hold an internal RLock around a
# transaction, but that is a library implementation detail; two of OUR threads now share this client (the poll loop and the
# forwarder below), so the mutual exclusion is made explicit and ours.
_plc_io_lock = threading.RLock()

# -----------------------------------------------------
# AUDIT C2 (structural fix): the forward runs on a worker, not on the asyncio event loop.
#
# pymodbus calls setValues from the single event-loop thread, and the forward was a BLOCKING socket write on that thread.
# A PLC that accepts TCP but never answers therefore stalled every SCADA client at once, not just the one issuing the
# command: measured 2,002 ms/command before the timeout fix, ~504 ms after it. Bounding the timeout limited the damage;
# it did not remove it. Handing the forward to a worker does: the event loop returns as soon as the verdict is published.
#
# ONE worker, not a pool: Modbus writes to the same register must keep their order, and a pool would reorder them.
# The queue is bounded - a dead PLC must not let the backlog grow without limit - and a full queue is reported as an
# undelivered command, never silently dropped.
# -----------------------------------------------------
FORWARD_QUEUE_MAX = int(os.environ.get("IM_FORWARD_QUEUE", "200"))
_forward_queue: "queue.Queue[Optional[Dict[str, Any]]]" = queue.Queue(maxsize=FORWARD_QUEUE_MAX)
_forward_thread: Optional[threading.Thread] = None


# How long one Modbus call to the PLC may take. Env override for slow links; see AUDIT C2.
PLC_IO_TIMEOUT_S = float(os.environ.get("IM_PLC_TIMEOUT_S", "0.5"))

# pymodbus retries 3 times by default, so a timeout costs retries x timeout. The poll loop already retries continuously and a
# forwarded setpoint that needs three attempts is a setpoint the operator should be told about, not one to keep grinding on.
PLC_IO_RETRIES = int(os.environ.get("IM_PLC_RETRIES", "1"))



def _publish_trace(report, forwarded: bool, logged_to, note: str = "") -> None:
    """Publish the per-hop trace once the PLC's answer is known.

    ingest owns this (it builds the trace) and imports forwarding, so forwarding cannot import ingest at module level.
    ingest rebinds this name when it loads; the late import is the fallback for a process that only imported forwarding."""
    from middleware import ingest
    ingest._publish_trace(report, forwarded=forwarded, logged_to=logged_to, note=note)


def _forward_to_plc(
    register: int,
    value: float
) -> bool:

    if _plc_client is None:

        log.warning(
            "[MIDDLEWARE] WARNING: "
            "no PLC connection — write not forwarded"
        )

        return False

    try:

        with _plc_io_lock:

            result = _plc_client.write_register(
                register,
                runtime._to_raw(value)
            )

        if result.isError():

            log.warning(
                f"[MIDDLEWARE] "
                f"PLC rejected write "
                f"register={register} "
                f"value={value:.2f}"
            )

            return False

        log.info(
            f"[MIDDLEWARE] "
            f"FORWARDED TO PLC "
            f"register={register} "
            f"value={value:.2f}"
        )

        return True

    except Exception as e:

        log.error(
            f"[MIDDLEWARE] "
            f"ERROR forwarding to PLC: {e}"
        )

        return False



def _report_undelivered(job: Dict[str, Any], reason: str) -> None:
    """AUDIT C1: a command the PLC never received is NOT a PASS.

    The verdict was decided and published before the forward was attempted. With the PLC unreachable the operator saw a
    green PASS for a setpoint that was never applied - the classic control-room failure where the HMI and the plant
    disagree and the operator believes the HMI. Correct the record."""

    with runtime._state_lock:

        runtime._pending_commands.pop(job["register"], None)
        runtime._health["undelivered"] += 1

    log.warning(
        f"[MIDDLEWARE] UNDELIVERED "
        f"{job['register_name']}={job['value']:.2f} "
        f"tx={job['tx_id']} - approved by the agents but the PLC did not accept it; "
        f"the operator view has been corrected"
    )

    orchestrator.forward_delivery_failure(
        tx_id=job["tx_id"],
        register_name=job["register_name"],
        value=job["value"],
        reason=reason
    )


def _forward_job(job: Dict[str, Any]) -> bool:
    """Run one queued forward to completion: write, trace, and correct the operator view on failure."""

    success = _forward_to_plc(
        job["register"],
        job["value"]
    )

    _publish_trace(job["report"], forwarded=success, logged_to=None,
                   note=("forwarded with an advisory ALERT" if job["alert"] else "") if success
                   else "the agents approved this command but it never reached the PLC")

    if not success:
        _report_undelivered(job, "PLC_UNREACHABLE: approved, but the PLC did not accept the write")

    return success


def _forward_worker() -> None:
    """The single FIFO forwarder (AUDIT C2). Never dies: one bad job must not strand every later command."""

    while True:

        job = _forward_queue.get()

        if job is None:            # shutdown sentinel
            return

        try:
            _forward_job(job)
        except Exception as exc:                                  # pragma: no cover - defensive
            log.exception(f"[MIDDLEWARE] forwarder failed on tx={job.get('tx_id')}: {exc}")
            try:
                _report_undelivered(job, f"FORWARD_ERROR: {exc}")
            except Exception:
                pass
        finally:
            _forward_queue.task_done()


def start_forwarder() -> None:
    """Start the single FIFO forward worker if it is not already running."""
    global _forward_thread
    if _forward_thread is None or not _forward_thread.is_alive():
        _forward_thread = threading.Thread(target=_forward_worker, name="plc-forwarder", daemon=True)
        _forward_thread.start()


def connect(plc_host: str, plc_port: int) -> ModbusTcpClient:
    """Build the shared PLC client. See AUDIT C2 for why the timeout and retries are pinned."""
    global _plc_client
    _plc_client = ModbusTcpClient(host=plc_host, port=plc_port,
                                  timeout=PLC_IO_TIMEOUT_S, retries=PLC_IO_RETRIES)
    return _plc_client
