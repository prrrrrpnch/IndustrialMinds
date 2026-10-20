"""
core/attack_log.py - persistent, file-based log of every detected/blocked attack.

No database or extra service: the middleware appends one JSON object per
blocked command to logs/blocked_attacks.jsonl, and the dashboard reads the
same file. Override the location with IM_LOG_DIR.

The attack type is derived from the agents' actual reason codes, never from
anything the sender claims about itself.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
import json
import os
import threading
import time
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.environ.get("IM_LOG_DIR", os.path.join(PROJECT_ROOT, "logs"))
LOG_FILE = os.path.join(LOG_DIR, "blocked_attacks.jsonl")

_write_lock = threading.Lock()

# Ordered: first matching prefix wins.
_REASON_TO_ATTACK_TYPE = [
    ("UNTRUSTED_SOURCE", "Untrusted Source"),
    ("INVALID_FUNCTION_CODE", "Invalid Function Code"),
    ("INVALID_REGISTER", "Invalid Register Access"),
    ("UNKNOWN_REGISTER", "Invalid Register Access"),
    ("SOURCE_QUARANTINED", "Blocked While Quarantined"),
    ("UNAUTHORIZED_", "Unauthorized Write (Policy)"),
    ("UNKNOWN_DEVICE", "Unknown Device"),
    ("POLICY_ERROR", "Policy Error (fail closed)"),
    ("WRITE_TO_SENSOR_REGISTER", "Write To Sensor Register"),
    ("RATE_LIMIT_EXCEEDED", "Flood / Rate Limit"),
    ("HMAC_MISSING", "Missing HMAC (Unsigned Command)"),
    ("HMAC_INVALID", "Tampered / Forged HMAC"),
    ("HMAC_MALFORMED", "Malformed Signed Frame"),
    ("HMAC_EXPIRED", "Expired Signature (Delayed Replay)"),
    ("REPLAY_DETECTED", "Replay"),
    ("OUT_OF_BOUNDS", "Impossible Command (Out of Bounds)"),
    ("RATE_OF_CHANGE_EXCEEDED", "Rate-of-Change Violation"),
    ("CROSS_REGISTER_VIOLATION", "Cross-Register Correlation"),
    ("CROSS_REGISTER", "Cross-Register Correlation"),
    ("TELEMETRY_MISMATCH", "Telemetry Mismatch / False Injection"),
]


def classify_reason(reason: str) -> str:
    reason = str(reason or "")
    for prefix, attack_type in _REASON_TO_ATTACK_TYPE:
        if reason.startswith(prefix):
            return attack_type
    return "Other Blocked Command"


def reason_code(reason: str) -> str:
    return str(reason or "").split(":", 1)[0]


# ---------------------------------------------------------------------------
# Writing (middleware)
# ---------------------------------------------------------------------------

def log_blocked_attack(record: dict, path: str = None) -> dict:
    """Appends one blocked-attack record. Returns the stored record."""
    path = path or LOG_FILE
    ts = record.get("timestamp") or time.time()

    entry = dict(record)
    entry["timestamp"] = ts
    entry["time"] = datetime.fromtimestamp(ts).isoformat(timespec="milliseconds")
    entry.setdefault("attack_type", classify_reason(entry.get("orchestrator", {}).get("reason")))
    entry.setdefault("reason_code", reason_code(entry.get("orchestrator", {}).get("reason")))

    line = json.dumps(entry, default=str, separators=(",", ":"))

    with _write_lock:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass

    return entry


# ---------------------------------------------------------------------------
# Reading (dashboard) - incremental, tolerant of partial/corrupt lines
# ---------------------------------------------------------------------------

class AttackLogReader:
    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path or LOG_FILE
        self._lock = threading.Lock()
        self._offset = 0
        self._inode = None
        self._records = []

    def _refresh(self) -> None:
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            self._offset, self._inode, self._records = 0, None, []
            return

        # File replaced or truncated -> re-read from start.
        if self._inode != st.st_ino or st.st_size < self._offset:
            self._offset, self._records = 0, []
            self._inode = st.st_ino

        if st.st_size == self._offset:
            return

        with open(self.path, "r", encoding="utf-8") as fh:
            fh.seek(self._offset)
            while True:
                pos = fh.tell()
                line = fh.readline()
                if not line:
                    break
                if not line.endswith("\n"):
                    # writer mid-line: retry next refresh
                    fh.seek(pos)
                    break
                line = line.strip()
                if line:
                    try:
                        self._records.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
            self._offset = fh.tell()

    def records(self) -> list:
        with self._lock:
            self._refresh()
            return list(self._records)


def filter_records(records: List[Dict[str, Any]], attack_type: Optional[str] = None,
                   ip_query: Optional[str] = None) -> List[Dict[str, Any]]:
    attack_type = (attack_type or "").strip()
    ip_query = (ip_query or "").strip().lower()
    out = []
    for r in records:
        if attack_type and attack_type.lower() != "all" and r.get("attack_type") != attack_type:
            continue
        if ip_query and ip_query not in str(r.get("source_ip", "")).lower():
            continue
        out.append(r)
    return out


def aggregate_by_ip(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """One row per source IP, most recently active first."""
    by_ip = {}
    for r in records:
        ip = r.get("source_ip") or "unknown"
        row = by_ip.get(ip)
        if row is None:
            row = by_ip[ip] = {
                "source_ip": ip,
                "attack_count": 0,
                "attack_types": {},
                "first_seen": r.get("timestamp"),
                "last_seen": r.get("timestamp"),
                "latest": r,
            }
        row["attack_count"] += 1
        t = r.get("attack_type", "Other Blocked Command")
        row["attack_types"][t] = row["attack_types"].get(t, 0) + 1
        ts = r.get("timestamp") or 0
        if ts < (row["first_seen"] or ts):
            row["first_seen"] = ts
        if ts >= (row["last_seen"] or 0):
            row["last_seen"] = ts
            row["latest"] = r

    rows = []
    for row in by_ip.values():
        latest = row.pop("latest")
        row["latest_attack_type"] = latest.get("attack_type")
        row["latest_reason"] = latest.get("orchestrator", {}).get("reason")
        row["latest_machine"] = latest.get("machine")
        row["latest_tx_id"] = latest.get("tx_id")
        row["last_seen_time"] = latest.get("time")
        rows.append(row)

    rows.sort(key=lambda x: x["last_seen"] or 0, reverse=True)
    return rows


def attack_type_counts(records: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {}
    for r in records:
        t = r.get("attack_type", "Other Blocked Command")
        counts[t] = counts.get(t, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: kv[0]))
