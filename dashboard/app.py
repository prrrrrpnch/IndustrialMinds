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

import os
import sys
import threading
import time
from collections import OrderedDict, deque
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

_START_TIME = time.time()

# Optional shared-token auth for the state-changing POST endpoints. Default
# unset -> no auth (loopback-only demo, unchanged). Set IM_DASHBOARD_TOKEN on
# BOTH the dashboard and the middleware when the dashboard is bound to a network
# (IM_DASHBOARD_BIND_HOST=0.0.0.0) so only the middleware can post to it.
_DASHBOARD_TOKEN = os.environ.get("IM_DASHBOARD_TOKEN", "").strip()


@app.before_request
def _require_token_for_writes():
    import hmac as _hmac
    from flask import request as _req
    if not _DASHBOARD_TOKEN:
        return None                                  # no token configured -> open (current behaviour)
    if _req.method == "POST" and _req.path.startswith("/api/"):
        presented = _req.headers.get("X-IM-Token", "")
        if not _hmac.compare_digest(presented, _DASHBOARD_TOKEN):
            return jsonify({"success": False, "error": "unauthorized"}), 401
    return None


@app.route("/api/health")
def health() -> Response:
    """Unauthenticated liveness/readiness probe (GET)."""
    with _lock:
        n_traces = len(_traces)
    return jsonify({
        "status": "ok",
        "uptime_seconds": round(time.time() - _START_TIME, 1),
        "traces": n_traces,
        "auth": "token" if _DASHBOARD_TOKEN else "open",
    })

_scada_to_plc = deque(maxlen=MAX_EVENTS)
_plc_to_scada = deque(maxlen=MAX_EVENTS)

_cpu_history = deque(maxlen=60)

# Phase 9 packet-tracer: one hop-by-hop trace per command, newest first (full tx_id -> trace).
MAX_TRACES = 300
_traces: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
_model_card: Dict[str, Any] = {}                                 # the live physical model's card, pushed by the middleware
_incidents: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()   # correlated incidents from the middleware (id -> latest state)
MAX_INCIDENTS = 100
_trace_seq = 0                 # increases with every trace received; the Network Flow view asks for "everything after seq N"


def _host_labels() -> Dict[str, str]:
    """Optional friendly names for source hosts, e.g. IM_HOST_LABELS="<scada-ip>=SCADA (Mac B),<attacker-ip>=Attacker (Windows B)".
    Addresses come from the environment, never from code."""
    out = {netconfig.LOOPBACK: "this machine"}
    for item in os.environ.get("IM_HOST_LABELS", "").split(","):
        if "=" in item:
            ip, label = item.split("=", 1)
            if ip.strip() and label.strip():
                out[ip.strip()] = label.strip()
    return out


def _flow_summary(t: Dict[str, Any]) -> Dict[str, Any]:
    """What the Network Flow view needs from one trace: who sent it, how far it got, and why it stopped."""
    hop = {h["hop"]: h for h in t.get("hops", [])}
    src = str((hop.get("arrival", {}).get("values") or {}).get("source") or "")
    ip = src.rsplit(":", 1)[0] if ":" in src else src
    checks = {c["check"]: c["result"] for c in (hop.get("cyber_rules", {}).get("checks") or [])}
    stopped = None
    if t.get("verdict") == "DROP":
        stopped = "cyber" if hop.get("cyber_rules", {}).get("outcome") == "FAIL" else "physical"
    out_vals = hop.get("outcome", {}).get("values") or {}
    arr = hop.get("arrival", {}).get("values") or {}
    return {"seq": t.get("seq"), "tx": t.get("short_id"), "time": _format_time(t.get("time")), "source_ip": ip,
            "trusted": None if "source_whitelist" not in checks else checks["source_whitelist"] == "PASS",
            "verdict": t.get("verdict"), "reason": t.get("reason"), "stopped_at": stopped,
            "forwarded": bool(out_vals.get("forwarded_to_plc")), "command": arr.get("register"), "value": arr.get("requested_value"),
            "model_flag": bool((hop.get("physical_model", {}).get("values") or {}).get("threat_flag"))}

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

        elif verdict == "ALERT":
            _metrics["pass"] += 1          # forwarded to the PLC (advisory flag); shown in the event table
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


@app.route("/api/trace", methods=["POST"])
def post_trace() -> Response:
    """Middleware -> dashboard: the hop-by-hop trace of ONE command (what each layer actually computed)."""
    data = request.get_json(silent=True) or {}
    tx = str(data.get("tx_id") or "")
    if not tx or not isinstance(data.get("hops"), list):
        return jsonify({"success": False}), 400
    data["short_id"] = _short_tx_id(tx)
    global _trace_seq
    with _lock:
        _trace_seq += 1
        data["seq"] = _trace_seq
        _traces.pop(tx, None)
        _traces[tx] = data
        while len(_traces) > MAX_TRACES:
            _traces.popitem(last=False)
    return jsonify({"success": True})


@app.route("/api/model", methods=["POST"])
def post_model_card() -> Response:
    """Middleware -> dashboard: what the live physical model is, how it was measured, and what it cannot do."""
    data = request.get_json(silent=True) or {}
    if not data.get("model"):
        return jsonify({"success": False}), 400
    global _model_card
    with _lock:
        _model_card = data
    return jsonify({"success": True})


@app.route("/api/model")
def get_model_card() -> Response:
    """The model card, or an empty object until the middleware has published one."""
    with _lock:
        return jsonify(dict(_model_card))


@app.route("/api/incident", methods=["POST"])
def post_incident() -> Response:
    """Middleware -> dashboard: the latest state of one correlated incident (see middleware/incidents.py)."""
    data = request.get_json(silent=True) or {}
    iid = str(data.get("id") or "")
    if not iid or not isinstance(data.get("timeline"), list):
        return jsonify({"success": False}), 400
    with _lock:
        _incidents.pop(iid, None)
        _incidents[iid] = data
        while len(_incidents) > MAX_INCIDENTS:
            _incidents.popitem(last=False)
    return jsonify({"success": True})


@app.route("/api/incidents")
def list_incidents() -> Response:
    """Newest-first incidents; an open incident whose last event is older than its gap is shown as closed."""
    now = time.time()
    with _lock:
        items = list(_incidents.values())[::-1][:30]
    out = []
    for i in items:
        i = dict(i)
        if i.get("status") == "open" and now - float(i.get("last_seen") or 0) > 35:
            i["status"] = "closed"
        i["quarantine_remaining_s"] = max(0.0, round(float((i.get("quarantine") or {}).get("until") or 0) - now, 0))
        out.append(i)
    return jsonify(out)


@app.route("/api/traces")
def list_traces() -> Response:
    """Newest-first summaries for the packet-tracer list."""
    with _lock:
        items = list(_traces.values())[::-1][:60]
    return jsonify([{"tx_id": t["tx_id"], "short_id": t["short_id"], "time": _format_time(t.get("time")),
                     "verdict": t.get("verdict"), "reason": t.get("reason"),
                     "command": next((h["values"].get("register") for h in t["hops"] if h["hop"] == "arrival"), None),
                     "value": next((h["values"].get("requested_value") for h in t["hops"] if h["hop"] == "arrival"), None)}
                    for t in items])


@app.route("/api/flow")
def flow() -> Response:
    """Network Flow view: traces newer than ?since=<seq> in arrival order, plus host labels."""
    try:
        since = int(request.args.get("since", "0"))
    except ValueError:
        since = 0
    with _lock:
        items = [t for t in _traces.values() if (t.get("seq") or 0) > since]
        last = _trace_seq
    items.sort(key=lambda t: t.get("seq") or 0)
    return jsonify({"last_seq": last, "labels": _host_labels(), "events": [_flow_summary(t) for t in items[-200:]]})


@app.route("/api/trace/<tx>")
def get_trace(tx: str) -> ResponseReturnValue:
    """One full trace, by full tx_id or by the dashboard's short id (TX-007)."""
    with _lock:
        t = _traces.get(tx) or next((v for v in _traces.values() if v.get("short_id") == tx), None)
    if t is None:
        return jsonify({"error": "unknown tx_id"}), 404
    return jsonify(t)


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
        _traces.clear()
        _incidents.clear()

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