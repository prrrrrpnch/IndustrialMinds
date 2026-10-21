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
import ipaddress
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

from core.interfaces import MACHINES, STAGES  # noqa: E402
from core import attack_log, forensics, netconfig  # noqa: E402

app = Flask(__name__)

MAX_EVENTS = 100

_lock = threading.Lock()

_START_TIME = time.time()

# Optional shared-token auth for the state-changing POST endpoints. Default
# unset -> no auth (loopback-only demo, unchanged). Set IM_DASHBOARD_TOKEN on
# BOTH the dashboard and the middleware when the dashboard is bound to a network
# (IM_DASHBOARD_BIND_HOST=0.0.0.0) so only the middleware can post to it.
_DASHBOARD_TOKEN = os.environ.get("IM_DASHBOARD_TOKEN", "").strip()


def is_loopback_bind(host: str) -> bool:
    """Is this bind address reachable only from this machine?"""
    host = (host or "").strip()
    if host in ("localhost", ""):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False           # a hostname we cannot resolve to loopback is treated as exposed


def check_bind_is_safe(host: str) -> Optional[str]:
    """AUDIT S3: an open dashboard must never be put on a network.

    The token has been supported for a while but was purely opt-in, so the documented multi-laptop setup
    (IM_DASHBOARD_BIND_HOST=0.0.0.0) came up with every state-changing POST endpoint unauthenticated - /api/reset,
    /api/security-event, /api/delivery - i.e. anyone on the lab network could erase the operator's record of an attack or
    fabricate one. Binding off loopback now REQUIRES IM_DASHBOARD_TOKEN. Returns an error message, or None if the
    combination is safe. Loopback is unchanged: no token needed for the one-laptop demo."""
    if is_loopback_bind(host) or _DASHBOARD_TOKEN:
        return None
    return (
        f"refusing to start: the dashboard would listen on {host}, which is reachable from the network, with NO "
        f"authentication on its POST endpoints - anyone who can reach it could reset the operator's record of an attack "
        f"or fabricate events.\n"
        f"  Fix: set IM_DASHBOARD_TOKEN to the same value on the dashboard AND the middleware\n"
        f"       (see GETTING_STARTED.md / config/lab.env.example), or bind to 127.0.0.1 for a one-laptop demo."
    )


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
    """Liveness of THIS process, plus what it knows about the rest of the system (GET, unauthenticated).

    AUDIT A5: this used to answer `ok` with the PLC dead and commands silently failing to deliver. It still cannot probe the
    PLC itself - only the middleware talks to it - but it can report what the middleware has told it, so `status` degrades
    instead of lying."""
    with _lock:
        n_traces = len(_traces)
        undelivered = _metrics["undelivered"]
        last_event = _scada_to_plc[0]["timestamp"] if _scada_to_plc else None
        model = dict(_model_card)
        mw = dict(_middleware_health)
    status = "ok"
    degraded = []
    if undelivered and (time.time() - _last_undelivered_at) < UNDELIVERED_RECENT_S:
        status = "degraded"
        degraded.append(f"{undelivered} command(s) approved but never delivered to the PLC "
                        f"(latest {time.time() - _last_undelivered_at:.0f}s ago)")
    if model and model.get("status") not in (None, "OK"):
        status = "degraded"
        degraded.append(f"physical model status {model.get('status')}")

    # AUDIT A6/N6: the PLC leg. Only the middleware talks to the PLC, so the dashboard reports what the middleware last
    # told it - and says so when the middleware itself has gone quiet, rather than implying a healthy plant.
    age = (time.time() - mw["received_at"]) if mw.get("received_at") else None
    if mw.get("received_at") is None:
        plc = "not reported"
        if _scada_to_plc:
            status = "degraded"
            degraded.append("the middleware has never reported its health")
    elif age > MIDDLEWARE_HEALTH_STALE_S:
        plc = "unknown"
        status = "degraded"
        degraded.append(f"no health report from the middleware for {age:.0f}s - is it still running?")
    elif not mw.get("plc_connected"):
        plc = "unreachable"
        status = "degraded"
        degraded.append(f"the middleware cannot reach the PLC "
                        f"({mw.get('consecutive_poll_failures', 0)} consecutive failed polls)")
    else:
        plc = "connected"
    if mw.get("dropped_forwards"):
        status = "degraded"
        degraded.append(f"{mw['dropped_forwards']} approved command(s) dropped - the forward queue overflowed")

    return jsonify({
        "status": status,
        "degraded": degraded,
        "uptime_seconds": round(time.time() - _START_TIME, 1),
        "traces": n_traces,
        "undelivered_commands": undelivered,
        "last_command_at": last_event,
        "physical_model": model.get("status") if model else "not reported",
        "plc": plc,
        "dropped_forwards": mw.get("dropped_forwards", 0),
        "forward_backlog": mw.get("forward_backlog", 0),
        "middleware_report_age_s": round(age, 1) if age is not None else None,
        "forensics": "on" if forensics.enabled() else "off",
        "auth": "token" if _DASHBOARD_TOKEN else "open",
    })


# AUDIT (found by the three-laptop rehearsal): health must describe the system NOW. An undelivered command is a permanent
# entry in the record (the count stays on the overview and survives a restart), but it must not keep the header on DEGRADED
# for ever after the PLC has come back - the audience would watch a healthy system say "degraded" until someone pressed Reset.
UNDELIVERED_RECENT_S = float(os.environ.get("IM_UNDELIVERED_RECENT_S", "60"))
_last_undelivered_at = 0.0

# How long a middleware health report stays meaningful. The middleware posts one every
# MIDDLEWARE_HEALTH_INTERVAL (5 s), so three missed reports means something is wrong with the middleware itself.
MIDDLEWARE_HEALTH_STALE_S = 20.0

_middleware_health: Dict[str, Any] = {"received_at": None}


@app.route("/api/middleware-health", methods=["POST"])
def post_middleware_health() -> Response:
    """Middleware -> dashboard heartbeat (AUDIT A6/N6): PLC reachability, dropped forwards, forward backlog.

    The dashboard cannot reach the PLC itself, so without this /api/health could only ever answer for the Flask process.
    A missing heartbeat is itself a degraded state (see health())."""
    data = request.get_json(silent=True) or {}
    with _lock:
        _middleware_health.clear()
        _middleware_health.update({
            "plc_connected": bool(data.get("plc_connected")),
            "consecutive_poll_failures": int(data.get("consecutive_poll_failures") or 0),
            "dropped_forwards": int(data.get("dropped_forwards") or 0),
            "undelivered": int(data.get("undelivered") or 0),
            "forward_backlog": int(data.get("forward_backlog") or 0),
            "received_at": time.time(),
        })
    return jsonify({"success": True})

_scada_to_plc = deque(maxlen=MAX_EVENTS)
_plc_to_scada = deque(maxlen=MAX_EVENTS)

_cpu_history = deque(maxlen=60)

# Phase 9 packet-tracer: one hop-by-hop trace per command, newest first (full tx_id -> trace).
MAX_TRACES = 300
_traces: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
_investigations: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()   # investigator findings, newest last
MAX_INVESTIGATIONS = 50
_model_card: Dict[str, Any] = {}                                 # the live physical model's card, pushed by the middleware
_incidents: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()   # correlated incidents from the middleware (id -> latest state)
MAX_INCIDENTS = 100
_trace_seq = 0                 # increases with every trace received; the Network Flow view asks for "everything after seq N"


def _replay_forensics() -> None:
    """Rebuild the in-memory views from the on-disk record at startup (AUDIT A4).

    Traces, incidents, investigations and the event feed used to exist ONLY here, so restarting this process - or it dying -
    destroyed the whole record of an incident. They are now appended to JSONL under IM_LOG_DIR as they arrive and replayed
    on boot, so the forensic record outlives the thing that draws it."""
    global _trace_seq, _event_counter
    if not forensics.enabled():
        return
    try:
        for t in forensics.load("traces", MAX_TRACES):
            tx = str(t.get("tx_id") or "")
            if tx:
                _trace_seq += 1
                t["seq"] = _trace_seq           # re-sequence: the Network Flow view asks for "everything after seq N"
                _traces[tx] = t
        for i in forensics.load("incidents", MAX_INCIDENTS):
            _incidents[str(i["id"])] = i
        for v in forensics.load("investigations", MAX_INVESTIGATIONS):
            _investigations[str(v["incident_id"])] = v

        # The event feed is newest-first in memory and oldest-first on disk. Only the latest line per tx_id is kept, so a
        # PASS later corrected to UNDELIVERED replays as UNDELIVERED - the correction survives the restart too.
        # No pop before the re-insert here (unlike the keyed stores above): the key keeps its FIRST position so the feed
        # replays in ARRIVAL order, while the value is the latest line - a PASS later corrected to UNDELIVERED comes back
        # as UNDELIVERED, in the place the command actually arrived.
        latest = {}
        for e in forensics.load("events", None):
            latest[str(e.get("tx_id") or id(e))] = e
        for e in list(latest.values())[-MAX_EVENTS:]:
            _scada_to_plc.appendleft(e)
            _metrics["total"] += 1
            v = e.get("verdict")
            if v in ("PASS", "ALERT"):
                _metrics["pass"] += 1
            elif v == "DROP":
                _metrics["drop"] += 1
            elif v == "UNDELIVERED":
                _metrics["undelivered"] += 1
        if _scada_to_plc or _traces or _incidents:
            print(f"[DASHBOARD] recovered from {forensics.log_dir()}: "
                  f"{len(_scada_to_plc)} event(s), {len(_traces)} trace(s), {len(_incidents)} incident(s), "
                  f"{len(_investigations)} investigation(s)")
    except Exception as exc:                                   # a damaged record must not stop the dashboard starting
        print(f"[DASHBOARD] could not fully replay the forensic record ({exc}); continuing with what loaded")




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
    verdict, reason = t.get("verdict"), t.get("reason")
    # AUDIT C1, in THIS view too. A downstream command the agents approved but the PLC never took used to show here as a
    # plain PASS/ALERT with no sign it never arrived - only the events table had been corrected. The trace is published by the
    # forwarder AFTER the write was attempted, so forwarded=False on an approved command means exactly "never reached the PLC".
    if verdict in ("PASS", "ALERT") and t.get("direction", "downstream") == "downstream" and not out_vals.get("forwarded_to_plc"):
        reason = f"PLC_UNREACHABLE: approved ({verdict}) but the PLC did not accept the write"
        verdict = "UNDELIVERED"
    return {"seq": t.get("seq"), "tx": t.get("short_id"), "time": _format_time(t.get("time")), "source_ip": ip,
            "trusted": None if "source_whitelist" not in checks else checks["source_whitelist"] == "PASS",
            "verdict": verdict, "reason": reason, "stopped_at": stopped,
            "forwarded": bool(out_vals.get("forwarded_to_plc")), "command": arr.get("register"), "value": arr.get("requested_value"),
            "model_flag": bool((hop.get("physical_model", {}).get("values") or {}).get("threat_flag"))}

_metrics = {
    "total": 0,
    "pass": 0,
    "drop": 0,
    "undelivered": 0,          # AUDIT C1: approved by the agents, but the PLC never took it
}

# One entry per configured machine (core/interfaces.MACHINES).
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
        forensics.append("events", event)                      # AUDIT A4: outlive this process

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
    forensics.append("traces", data)                           # AUDIT A4
    return jsonify({"success": True})


@app.route("/api/delivery", methods=["POST"])
def post_delivery() -> Response:
    """Middleware -> dashboard: a command that was approved but never reached the PLC (AUDIT C1).

    The event was already published as PASS before the forward was attempted. Rewrite it to UNDELIVERED so the operator is
    not shown a green verdict for a setpoint that was never applied."""
    data = request.get_json(silent=True) or {}
    tx = _short_tx_id(data.get("tx_id"))
    if not tx or data.get("delivered", True):
        return jsonify({"success": False}), 400
    reason = str(data.get("reason") or "the PLC did not accept the write")
    with _lock:
        for event in _scada_to_plc:
            if event.get("tx_id") == tx and event.get("verdict") in ("PASS", "ALERT"):
                if event["verdict"] in ("PASS", "ALERT"):
                    _metrics["pass"] = max(0, _metrics["pass"] - 1)
                _metrics["undelivered"] += 1
                global _last_undelivered_at
                _last_undelivered_at = time.time()
                event["verdict"] = "UNDELIVERED"
                event["reason"] = reason
                # A NEW line, not an edit: the record keeps both the PASS and its correction, with timestamps.
                forensics.append("events", event)
                return jsonify({"success": True, "corrected": tx})
    return jsonify({"success": False, "error": "no matching forwarded event"}), 404


@app.route("/api/investigation", methods=["POST"])
def post_investigation() -> Response:
    """Middleware -> dashboard: one investigator finding. An analysis for a human; nothing here has been applied."""
    data = request.get_json(silent=True) or {}
    if not data.get("incident_id") or not data.get("headline"):
        return jsonify({"success": False}), 400
    with _lock:
        _investigations.pop(data["incident_id"], None)
        _investigations[data["incident_id"]] = data
        while len(_investigations) > MAX_INVESTIGATIONS:
            _investigations.popitem(last=False)
    forensics.append("investigations", data)                   # AUDIT A4
    return jsonify({"success": True})


@app.route("/api/investigations")
def list_investigations() -> Response:
    """Newest first."""
    with _lock:
        return jsonify(list(_investigations.values())[::-1])


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
    forensics.append("incidents", data)                        # AUDIT A4
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

                "undelivered":
                    _metrics["undelivered"],
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

def _last_undelivered_at_reset() -> None:
    global _last_undelivered_at
    _last_undelivered_at = 0.0


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
        _metrics["undelivered"] = 0
        _last_undelivered_at_reset()

        for m in MACHINES:
            _telemetry[m["name"]] = float(m["initial"])

        _event_counter = 0
        _tx_id_map.clear()
        _traces.clear()
        _incidents.clear()
        _investigations.clear()

    # AUDIT A4: Reset clears the VIEW. The record is renamed aside, not deleted - pressing Reset mid-demo must not be able
    # to destroy the evidence of what just happened, which is exactly what the in-memory-only version did.
    forensics.clear()

    print(
        "[DASHBOARD] Reset (the forensic record was set aside, not deleted)"
    )

    return jsonify({
        "success": True
    })


# Rebuild the view from the on-disk record. Called here, at the bottom, because it touches state defined throughout this
# module (_metrics, _traces, _incidents, the event deques).
_replay_forensics()


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

    _unsafe = check_bind_is_safe(args.host)
    if _unsafe:
        print(f"\n [FATAL] {_unsafe}\n")
        raise SystemExit(2)

    print(
        f" Dashboard listening on: http://{args.host}:{args.port}"
    )
    print(
        f" POST /api/* auth: "
        + ("shared token (IM_DASHBOARD_TOKEN)" if _DASHBOARD_TOKEN else "open (loopback only)")
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