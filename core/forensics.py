"""
core/forensics.py - the forensic record, kept OUTSIDE the process that displays it (AUDIT A4).

Traces, incidents, investigations and the security-event feed lived only in the Flask dashboard's memory: deques and
OrderedDicts on module globals. Restarting the dashboard - or its process dying, or someone pressing Reset - destroyed the
entire record of an incident. For a product whose stated value is visibility and after-the-fact explanation, the evidence
being a side effect of a web server's uptime is the wrong place for it.

Each kind of record is appended to its own JSONL file under IM_LOG_DIR (default `logs/`, the same place the blocked-attack
log already lives), one JSON object per line, and read back when the dashboard starts. The format is deliberately the
dullest one available: an append-only text file survives a kill -9 mid-write with at most one truncated last line, needs no
schema migration, and can be read by `tail`, `grep`, `jq` or a spreadsheet on a laptop with no tooling installed.

  traces.jsonl           one line per packet trace (keyed by tx_id; the newest line for a tx wins)
  incidents.jsonl        one line per incident UPDATE (keyed by id; the newest line for an id wins)
  investigations.jsonl   one line per investigator finding (keyed by incident_id)
  events.jsonl           one line per security event, including the later UNDELIVERED correction

Writes are append-only, so a record is never edited in place: a corrected event is a NEW line with the same tx_id, and the
replay below keeps the last one. That means the file is also a history - you can see that a command was published PASS at
12:00:01 and corrected to UNDELIVERED at 12:00:02, which an overwriting store would hide.

Rotation is by size (IM_FORENSICS_MAX_MB, default 32): the file is renamed `.1` and a fresh one started. Only the live file
is replayed at startup, so a rotation bounds both disk and boot time.

Opt-out: IM_FORENSICS=0 (the dashboard then behaves exactly as before, in memory only).
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from typing import Any, Dict, Iterator, List, Optional

log = logging.getLogger("industrialmind.forensics")

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

KINDS = ("traces", "incidents", "investigations", "events")

# The field whose latest line wins when a record is replayed. None = keep every line in order.
KEY_FIELD = {"traces": "tx_id", "incidents": "id", "investigations": "incident_id", "events": None}

_locks: Dict[str, threading.Lock] = {k: threading.Lock() for k in KINDS}
_write_failed: Dict[str, bool] = {}


def log_dir() -> str:
    """Read at call time, not import time, so a test can point IM_LOG_DIR somewhere else."""
    return os.environ.get("IM_LOG_DIR", os.path.join(PROJECT_ROOT, "logs"))


def path_for(kind: str) -> str:
    return os.path.join(log_dir(), f"{kind}.jsonl")


def enabled() -> bool:
    return os.environ.get("IM_FORENSICS", "1").strip().lower() not in ("0", "false", "no", "off")


def _max_bytes() -> int:
    try:
        return int(float(os.environ.get("IM_FORENSICS_MAX_MB", "32")) * 1024 * 1024)
    except ValueError:
        return 32 * 1024 * 1024


def _rotate_if_large(path: str) -> None:
    try:
        if os.path.exists(path) and os.path.getsize(path) >= _max_bytes():
            os.replace(path, path + ".1")
    except OSError:
        pass                    # a rotation we could not do is not a reason to lose the next record


def append(kind: str, record: Dict[str, Any]) -> bool:
    """Append one record. Never raises: losing the forensic copy must not break the live path.

    A write failure is reported once per kind and then stays quiet, so a full or read-only disk does not itself become the
    log flood the audit found in C3."""
    if not enabled() or kind not in KINDS:
        return False
    try:
        os.makedirs(log_dir(), exist_ok=True)
        path = path_for(kind)
        line = json.dumps(record, default=str, separators=(",", ":"))
        with _locks[kind]:
            _rotate_if_large(path)
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        _write_failed.pop(kind, None)
        return True
    except Exception as exc:
        if not _write_failed.get(kind):
            _write_failed[kind] = True
            log.warning("cannot persist %s to %s (%s) - the dashboard keeps working, in memory only",
                        kind, path_for(kind), exc)
        return False


def _read_lines(path: str) -> Iterator[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue      # a half-written last line after a kill -9: skip it, keep the rest
                if isinstance(obj, dict):
                    yield obj
    except FileNotFoundError:
        return
    except OSError as exc:
        log.warning("cannot read %s (%s) - starting with an empty record", path, exc)
        return


def load(kind: str, limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """Replay a kind, oldest first, with later lines for the same key replacing earlier ones.

    `limit` keeps only the newest N after de-duplication, matching the in-memory caps the dashboard applies."""
    if not enabled() or kind not in KINDS:
        return []
    key = KEY_FIELD.get(kind)
    if key is None:
        out: List[Dict[str, Any]] = list(_read_lines(path_for(kind)))
    else:
        merged: "Dict[str, Dict[str, Any]]" = {}
        for obj in _read_lines(path_for(kind)):
            k = str(obj.get(key, ""))
            if not k:
                continue
            merged.pop(k, None)          # re-insert so insertion order tracks the newest line
            merged[k] = obj
        out = list(merged.values())
    if limit is not None and len(out) > limit:
        out = out[-limit:]
    return out


def clear(kind: Optional[str] = None) -> None:
    """Start a fresh record. Used by the dashboard's Reset and by tests.

    The old file is kept as `.cleared-<unix>` rather than deleted: an operator pressing Reset during a demo should not be
    able to destroy the evidence of what just happened, which is exactly what the in-memory version did."""
    kinds = KINDS if kind is None else (kind,)
    stamp = int(time.time())
    for k in kinds:
        path = path_for(k)
        try:
            if os.path.exists(path):
                os.replace(path, f"{path}.cleared-{stamp}")
        except OSError as exc:
            log.warning("could not set aside %s (%s)", path, exc)


def summary() -> Dict[str, Any]:
    """What is on disk right now, for /api/health and the tests."""
    out: Dict[str, Any] = {"enabled": enabled(), "dir": log_dir()}
    for k in KINDS:
        p = path_for(k)
        try:
            out[k] = {"lines": sum(1 for _ in _read_lines(p)), "bytes": os.path.getsize(p)}
        except OSError:
            out[k] = {"lines": 0, "bytes": 0}
    return out
