"""
dashboard/app.py

Industrial Mind - Real SCADA / PLC Security Dashboard.

SCADA -> PLC:
    Security decisions made by middleware.

PLC -> SCADA:
    Only actual PLC confirmations.

No simulated security events.
"""

from __future__ import annotations

import ipaddress
import os
import sys
import subprocess
import threading
import time
from collections import deque
from typing import Any, Dict, Optional

from flask import Flask, Response, jsonify, render_template, request
from flask.typing import ResponseReturnValue

try:
    import psutil
except ImportError:
    psutil = None


# =========================================================
# CONFIG
# =========================================================

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from docs.interfaces import MACHINES, STAGES  # noqa: E402
from docs import attack_log, netconfig  # noqa: E402

app = Flask(__name__)

MAX_EVENTS = 100

_lock = threading.Lock()

_scada_to_plc = deque(maxlen=MAX_EVENTS)
_plc_to_scada = deque(maxlen=MAX_EVENTS)

_cpu_history = deque(maxlen=60)

_metrics = {
    "total": 0,
    "pass": 0,
    "drop": 0,
}

# One entry per configured machine (docs/interfaces.MACHINES).
_telemetry = {
    m["name"]: float(m["initial"]) for m in MACHINES
}

# Reads logs/blocked_attacks.jsonl written by the middleware.
_attack_log_reader = attack_log.AttackLogReader()


# =========================================================
# TRANSACTION ID MAPPING
# =========================================================

_event_counter = 0
_tx_id_map = {}


def _short_tx_id(tx_id: Any) -> str:
    """
    Convert long UUID into a short dashboard ID.

    The same original transaction ID ALWAYS gets
    the same short ID.

    Example:

        long UUID -> TX-001
        same UUID -> TX-001
    """

    global _event_counter

    if not tx_id or tx_id == "-":
        _event_counter += 1
        return f"TX-{_event_counter:03d}"

    tx_id = str(tx_id)

    if tx_id.startswith("TX-"):
        return tx_id

    if tx_id in _tx_id_map:
        return _tx_id_map[tx_id]

    _event_counter += 1

    short_id = f"TX-{_event_counter:03d}"

    _tx_id_map[tx_id] = short_id

    return short_id


# =========================================================
# TIME
# =========================================================

def _format_time(timestamp: Optional[float] = None) -> str:

    try:

        if timestamp is None:
            timestamp = time.time()

        timestamp = float(timestamp)

        return time.strftime(
            "%H:%M:%S",
            time.localtime(timestamp)
        )

    except Exception:

        return time.strftime(
            "%H:%M:%S"
        )


# =========================================================
# SCADA -> PLC EVENT
# =========================================================

def add_scada_event(event: Dict[str, Any]) -> None:

    verdict = str(
        event.get(
            "verdict",
            "UNKNOWN"
        )
    ).upper()

    event = {
        "tx_id": _short_tx_id(
            event.get("tx_id")
        ),

        "command": event.get(
            "command",
            "-"
        ),

        "verdict": verdict,

        "reason": event.get(
            "reason",
            "-"
        ),

        "latency_ms": event.get(
            "latency_ms",
            0
        ),

        "timestamp": _format_time(
            event.get("timestamp")
        ),
    }

    with _lock:

        _scada_to_plc.appendleft(event)

        _metrics["total"] += 1

        if verdict == "PASS":
            _metrics["pass"] += 1

        elif verdict == "DROP":
            _metrics["drop"] += 1


# =========================================================
# PLC -> SCADA EVENT
# =========================================================

def add_plc_event(event: Dict[str, Any]) -> None:

    event = {
        "tx_id": _short_tx_id(
            event.get("tx_id")
        ),

        "command": event.get(
            "command",
            "-"
        ),

        "verdict": str(
            event.get(
                "verdict",
                "PASS"
            )
        ).upper(),

        "reason": event.get(
            "reason",
            "PLC confirmed the requested value."
        ),

        "latency_ms": event.get(
            "latency_ms",
            0
        ),

        "timestamp": _format_time(
            event.get("timestamp")
        ),
    }

    with _lock:

        _plc_to_scada.appendleft(
            event
        )


# =========================================================
# TELEMETRY
# =========================================================

def update_telemetry(registers: Dict[str, Any]) -> None:

    with _lock:

        for name in _telemetry:

            if name in registers:

                try:

                    _telemetry[name] = float(
                        registers[name]
                    )

                except (
                    ValueError,
                    TypeError
                ):

                    pass


# =========================================================
# CPU HISTORY
# =========================================================

def update_cpu_history() -> None:

    if psutil is None:
        return

    try:

        cpu = psutil.cpu_percent(
            interval=None
        )

        with _lock:

            _cpu_history.append({
                "time": time.strftime(
                    "%H:%M:%S"
                ),
                "value": round(
                    float(cpu),
                    1
                )
            })

    except Exception:
        pass


def _cpu_loop() -> None:

    if psutil is not None:

        psutil.cpu_percent(
            interval=None
        )

    while True:

        update_cpu_history()

        time.sleep(1)


# =========================================================
# ROUTES
# =========================================================

@app.route("/")
def index() -> str:

    return render_template(
        "index.html",
        machines=MACHINES,
        stages=STAGES
    )


@app.route(
    "/api/security-event",
    methods=["POST"]
)
def security_event() -> Response:

    data = (
        request.get_json(
            silent=True
        )
        or {}
    )

    direction = data.get(
        "direction",
        "scada_to_plc"
    )

    if direction == "scada_to_plc":

        add_scada_event(data)

    elif direction == "plc_to_scada":

        add_plc_event(data)

    return jsonify({
        "success": True
    })


@app.route(
    "/api/telemetry",
    methods=["POST"]
)
def telemetry() -> Response:

    data = (
        request.get_json(
            silent=True
        )
        or {}
    )

    registers = data.get(
        "registers",
        data
    )

    update_telemetry(
        registers
    )

    return jsonify({
        "success": True
    })


@app.route(
    "/api/dashboard",
    methods=["GET"]
)
def dashboard_data() -> Response:

    with _lock:

        return jsonify({

            "overview": {
                "total_requests":
                    _metrics["total"],

                "pass":
                    _metrics["pass"],

                "drop":
                    _metrics["drop"],
            },

            "scada_to_plc":
                list(_scada_to_plc),

            "plc_to_scada":
                list(_plc_to_scada),

            "telemetry": {

                "registers":
                    dict(_telemetry),

                "cpu_load":
                    (
                        _cpu_history[-1]["value"]
                        if _cpu_history
                        else 0
                    ),
            },

            "cpu_history":
                list(_cpu_history),
        })


# =========================================================
# BLOCKED IPS (reads logs/blocked_attacks.jsonl)
# =========================================================

@app.route(
    "/api/blocked-ips",
    methods=["GET"]
)
def blocked_ips() -> Response:

    attack_type = request.args.get("attack_type", "")
    ip_query = request.args.get("ip", "")

    records = _attack_log_reader.records()

    filtered = attack_log.filter_records(
        records,
        attack_type=attack_type,
        ip_query=ip_query
    )

    return jsonify({
        "log_file": os.path.relpath(attack_log.LOG_FILE, PROJECT_ROOT),
        "total_records": len(records),
        "matching_records": len(filtered),
        "attack_types": attack_log.attack_type_counts(records),
        "sources": attack_log.aggregate_by_ip(filtered),
    })


@app.route(
    "/api/blocked-ips/<path:ip>",
    methods=["GET"]
)
def blocked_ip_detail(ip: str) -> Response:

    attack_type = request.args.get("attack_type", "")

    records = [
        r for r in _attack_log_reader.records()
        if str(r.get("source_ip")) == ip
    ]

    records = attack_log.filter_records(
        records,
        attack_type=attack_type
    )

    records.sort(
        key=lambda r: r.get("timestamp") or 0,
        reverse=True
    )

    return jsonify({
        "source_ip": ip,
        "count": len(records),
        "attacks": records[:500],
    })


# =========================================================
# ATTACK TRIGGER
# =========================================================

@app.route(
    "/api/trigger-attack",
    methods=["POST"]
)
def trigger_attack() -> ResponseReturnValue:

    data = (
        request.get_json(
            silent=True
        )
        or {}
    )

    attack = data.get(
        "attack"
    )

    allowed = {
        "flood",
        "impossible-command",
        "replay",
        "false-injection",
        "cross-register",
        "hmac-missing",
        "hmac-tamper",
        "hmac-forged",
        "delayed-replay",
    }

    # Optional local address(es) for the attacker socket to bind to.
    # The middleware still records whatever address the connection
    # actually comes from.
    source_ip = str(data.get("source_ip") or "").strip()
    for ip in filter(None, (x.strip() for x in source_ip.split(","))):
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({
                "success": False,
                "error": f"Invalid source IP: {ip}"
            }), 400

    if attack not in allowed:

        return jsonify({
            "success": False,
            "error": "Invalid attack type"
        }), 400

    try:

        cmd = [
            sys.executable,
            "-m",
            "attacker.attacker",
            attack
        ]

        if source_ip:
            cmd += ["--source-ip", source_ip]

        subprocess.Popen(
            cmd,
            cwd=PROJECT_ROOT
        )

        print(
            f"[DASHBOARD] "
            f"Launching attack: {attack}"
        )

        return jsonify({
            "success": True,
            "attack": attack
        })

    except Exception as e:

        print(
            f"[DASHBOARD] "
            f"Attack failed: {e}"
        )

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# =========================================================
# RESET
# =========================================================

@app.route(
    "/api/reset",
    methods=["POST"]
)
def reset_dashboard() -> Response:

    global _event_counter

    with _lock:

        _scada_to_plc.clear()

        _plc_to_scada.clear()

        _cpu_history.clear()

        _metrics["total"] = 0
        _metrics["pass"] = 0
        _metrics["drop"] = 0

        for m in MACHINES:
            _telemetry[m["name"]] = float(m["initial"])

        _event_counter = 0
        _tx_id_map.clear()

    print(
        "[DASHBOARD] Reset"
    )

    return jsonify({
        "success": True
    })


# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":

    threading.Thread(
        target=_cpu_loop,
        daemon=True
    ).start()

    print()
    print("=" * 60)
    print(
        " 🛡️ INDUSTRIAL MIND SECURITY MONITORING SYSTEM"
    )
    print("=" * 60)
    import argparse
    parser = argparse.ArgumentParser(description="Industrial Mind dashboard")
    parser.add_argument("--host", default=netconfig.DASHBOARD_BIND_HOST,
                        help="bind address (env IM_DASHBOARD_BIND_HOST)")
    parser.add_argument("--port", type=int, default=netconfig.DASHBOARD_PORT,
                        help="bind port (env IM_DASHBOARD_PORT)")
    args = parser.parse_args()

    print(
        f" Dashboard listening on: http://{args.host}:{args.port}"
    )
    print(
        " Security API: "
        f"http://{args.host}:{args.port}/api/security-event"
    )
    print("=" * 60)
    print()

    app.run(
        host=args.host,
        port=args.port,
        debug=False,
        use_reloader=False
    )