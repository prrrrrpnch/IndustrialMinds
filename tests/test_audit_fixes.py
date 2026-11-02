"""
tests/test_audit_fixes.py - the four defects found by the adversarial audit (final-results/AUDIT.md), each pinned so it cannot
come back silently.

These are OPERATOR-LEVEL requirements, not component specifications. The audit's own finding A10/N5 was that 688 green checks
coexisted with a critical bug precisely because every test asserted a component against its own spec and none asserted what an
operator needs. These do the latter.

    python -m tests.test_audit_fixes
"""

from __future__ import annotations

import io
import logging
import os
import tempfile
import time

os.environ.setdefault("IM_LOG_DIR", tempfile.mkdtemp(prefix="im-audit-"))

from core.interfaces import MACHINES  # noqa: E402
from middleware import forwarding as fwd  # noqa: E402
from middleware import middleware_server as mw  # noqa: E402
from middleware import orchestrator  # noqa: E402

fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global fails
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    fails += 0 if cond else 1


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

print("C1 - a command the PLC never took must not be reported as a success")
sent = []
orchestrator._enqueue = lambda path, payload: sent.append((path, payload))
orchestrator.forward_delivery_failure("tx-abc", "P101", 72.0, "PLC_UNREACHABLE: test")
check("the middleware has a channel to correct an already-published PASS",
      sent and sent[0][0] == "/api/delivery", str(sent[:1]))
check("the correction names the command and says it was not delivered",
      sent[0][1]["delivered"] is False and sent[0][1]["tx_id"] == "tx-abc" and sent[0][1]["command"] == "P101")

# AUDIT A1 split the middleware into runtime/forwarding/ingest/polling + the transport. These checks are about what the
# MIDDLEWARE does, not about which file it is in, so they read the package.
import glob  # noqa: E402
MW_FILES = sorted(glob.glob(os.path.join(ROOT, "middleware", "*.py")))
src = "\n".join(io.open(f).read() for f in MW_FILES)
check("the forward's return value is used, not discarded", "success = _forward_to_plc(" in src and "if not success:" in src)
check("a failed forward logs UNDELIVERED with the transaction id",
      "UNDELIVERED" in src and "forward_delivery_failure(" in src)

from dashboard import app as dash  # noqa: E402
c = dash.app.test_client()
c.post("/api/reset")
c.post("/api/security-event", json={"tx_id": "uuid-1", "direction": "scada_to_plc", "verdict": "PASS",
                                    "reason": "OK", "latency_ms": 1.0, "command": "P101 -> 72.0"})
d = c.get("/api/dashboard").get_json()
check("a forwarded command starts life as PASS", d["scada_to_plc"][0]["verdict"] == "PASS" and d["overview"]["pass"] == 1)
r = c.post("/api/delivery", json={"tx_id": "uuid-1", "delivered": False, "command": "P101", "value": 72.0,
                                  "reason": "PLC_UNREACHABLE: approved, but the PLC did not accept the write"})
check("the dashboard accepts the correction", r.status_code == 200 and r.get_json()["success"])
d = c.get("/api/dashboard").get_json()
check("THE OPERATOR IS NO LONGER TOLD PASS", d["scada_to_plc"][0]["verdict"] == "UNDELIVERED",
      d["scada_to_plc"][0]["verdict"])
check("the row says why", "PLC" in d["scada_to_plc"][0]["reason"], d["scada_to_plc"][0]["reason"])
check("it is not counted as a pass any more", d["overview"]["pass"] == 0 and d["overview"]["undelivered"] == 1,
      str(d["overview"]))
check("a delivery report that succeeded is rejected (nothing to correct)",
      c.post("/api/delivery", json={"tx_id": "uuid-1", "delivered": True}).status_code == 400)
check("an unknown transaction is a 404, not a silent no-op",
      c.post("/api/delivery", json={"tx_id": "nope", "delivered": False}).status_code == 404)
check("a correction is not applied twice",
      c.post("/api/delivery", json={"tx_id": "uuid-1", "delivered": False}).status_code == 404
      and c.get("/api/dashboard").get_json()["overview"]["undelivered"] == 1)

# The Network Flow view reads TRACES, not the events table, so it needs the same correction.
# (No reset here: the A5 section below still needs the undelivered counter from the C1 checks above.)
def _trace(tx, verdict, forwarded):
    return {"tx_id": tx, "verdict": verdict, "reason": "OK", "direction": "downstream", "time": 1.0, "hops": [
        {"hop": "arrival", "values": {"source": "127.0.0.4:5555", "register": "P101", "requested_value": 72.0}},
        {"hop": "cyber_rules", "outcome": "PASS", "checks": [{"check": "source_whitelist", "result": "PASS"}]},
        {"hop": "outcome", "values": {"forwarded_to_plc": forwarded, "dropped": False}}]}
c.post("/api/trace", json=_trace("tx-delivered", "PASS", True))
c.post("/api/trace", json=_trace("tx-lost", "PASS", False))
c.post("/api/trace", json=_trace("tx-lost-alert", "ALERT", False))
flow = {e["tx"]: e for e in c.get("/api/flow").get_json()["events"]}
check("flow view: a delivered command stays PASS", [e["verdict"] for e in flow.values()][0] == "PASS", str([e["verdict"] for e in flow.values()]))
check("FLOW VIEW: an approved command the PLC never took is UNDELIVERED, not a green PASS",
      sorted(e["verdict"] for e in flow.values()) == ["PASS", "UNDELIVERED", "UNDELIVERED"], str([e["verdict"] for e in flow.values()]))
check("...for an advisory ALERT too, and the reason says why", any("PLC_UNREACHABLE" in str(e["reason"]) for e in flow.values()))
flow_js = io.open(os.path.join(ROOT, "dashboard", "static", "flow.js")).read()
check("the flow view marks the PLC node as unreachable when a command never arrived", '":5020 unreachable"' in flow_js and "plc-down" in flow_js)

print("\nA5 - /api/health must be able to report ill health")
h = c.get("/api/health").get_json()
check("health degrades when commands went undelivered", h["status"] == "degraded" and h["degraded"], str(h["status"]))
check("health says how many", h["undelivered_commands"] == 1)
# Health describes the system NOW: once the PLC has been back for a while, an old undelivered command stays in the record
# (the count) but must stop holding the header on DEGRADED.
c.post("/api/middleware-health", json={"plc_connected": True, "consecutive_poll_failures": 0, "dropped_forwards": 0})   # the PLC is back
dash._last_undelivered_at = time.time() - (dash.UNDELIVERED_RECENT_S + 5)
h_old = c.get("/api/health").get_json()
check("AN OLD undelivered command no longer holds health on DEGRADED (the system recovered)",
      h_old["status"] == "ok" and not any("never delivered" in d for d in h_old["degraded"]), f"{h_old['status']} {h_old['degraded']}")
check("...but the record keeps the count", h_old["undelivered_commands"] == 1 and c.get("/api/dashboard").get_json()["overview"]["undelivered"] == 1)
dash._last_undelivered_at = time.time()
check("a RECENT one still degrades it", c.get("/api/health").get_json()["status"] == "degraded")
c.post("/api/reset")
check("health is ok again once the record is cleared", c.get("/api/health").get_json()["status"] == "ok")
check("reset clears the undelivered counter too", c.get("/api/dashboard").get_json()["overview"]["undelivered"] == 0)

print("\n31 Oct regression - Reset must actually empty the Network Flow and the Blocked IPs panel for a fresh demo")
# A user ran a real attack, pressed Reset, and the attacker's box stayed drawn on the Network Flow, and its row stayed
# in the Blocked IPs panel. Root causes, both silent (every number elsewhere on the page DID go back to 0):
#   (a) /api/flow's "last_seq" came from the module-level _trace_seq counter, which reset_dashboard() never reset even
#       though it cleared _traces itself - so a browser tab that had already seen seq N got told "nothing new since N"
#       forever after, never "N doesn't exist any more", so flow.js's own reset-detection (data.last_seq < lastSeq)
#       could never fire;
#   (b) the Blocked IPs panel reads logs/blocked_attacks.jsonl directly (written by the middleware, not through
#       _traces at all) and reset_dashboard() never touched that file.
c.post("/api/reset")
c.post("/api/trace", json=_trace("tx-attacker", "DROP", False))
flow_before = c.get("/api/flow?since=0").get_json()
check("the attacker's command is on the flow before Reset", len(flow_before["events"]) == 1, str(flow_before))
seq_before = flow_before["last_seq"]
check("...with a real sequence number", seq_before > 0, seq_before)

from core import attack_log  # noqa: E402
ATTACKER_IP = "127.0.0.9"                   # loopback alias standing in for the attacker laptop; see CLAUDE.md hook rule 3
attack_log.log_blocked_attack({"source_ip": ATTACKER_IP, "orchestrator": {"reason": "HMAC_INVALID:x"}})
blocked_before = c.get("/api/blocked-ips").get_json()
check("the attacker is on the Blocked IPs panel before Reset",
      any(s["source_ip"] == ATTACKER_IP for s in blocked_before["sources"]), str(blocked_before["sources"]))

c.post("/api/reset")
flow_after = c.get(f"/api/flow?since={seq_before}").get_json()           # what an already-open browser tab would ask
check("REGRESSION: last_seq actually rolls back below what an open tab already saw (not stuck at the old high-water mark)",
      flow_after["last_seq"] < seq_before, f"{flow_after['last_seq']} should be < {seq_before}")
check("...so the Network Flow reports nothing left to draw", flow_after["events"] == [], str(flow_after["events"]))
blocked_after = c.get("/api/blocked-ips").get_json()
check("REGRESSION: the attacker is OFF the Blocked IPs panel after Reset", blocked_after["sources"] == [],
      str(blocked_after["sources"]))
check("...but its record was set aside, not deleted (same policy as every other forensic file)",
      any(f.startswith("blocked_attacks.jsonl.cleared-") for f in os.listdir(os.environ["IM_LOG_DIR"])),
      str(os.listdir(os.environ["IM_LOG_DIR"])))

flow_js = io.open(os.path.join(ROOT, "dashboard", "static", "flow.js")).read()
check("the client forgets a source's drawn box on the SAME rollback signal (sources.clear comes after removing its DOM node)",
      "sources.clear()" in flow_js and flow_js.index("s.node.group.remove()") < flow_js.index("sources.clear()"))

print("\nC2 - PLC I/O must be bounded, so one dead PLC cannot stall the proxy")
check("the PLC client has an explicit timeout, not the 3 s library default",
      "timeout=PLC_IO_TIMEOUT_S" in src and fwd.PLC_IO_TIMEOUT_S <= 1.0, f"{fwd.PLC_IO_TIMEOUT_S}s")
check("retries are pinned, so a timeout cannot be multiplied by the library default of 3",
      "retries=PLC_IO_RETRIES" in src and fwd.PLC_IO_RETRIES <= 2, f"{fwd.PLC_IO_RETRIES}")
check("both are tunable for a slow link", "IM_PLC_TIMEOUT_S" in src and "IM_PLC_RETRIES" in src)

print("\nC3 - a library must not be able to flood the operator's log")
f = mw._RateLimitFilter(("pymodbus",), interval_s=5.0)


def rec(name, msg):
    return logging.LogRecord(name, logging.ERROR, __file__, 1, msg, None, None)


burst = [f.filter(rec("pymodbus.logging", "Connection to (host, 502) failed")) for _ in range(40)]
check("40 identical library errors become 1 line", sum(burst) == 1, f"{sum(burst)} passed")
check("the filter reaches the CHILD logger that actually emits (a logger filter would not)",
      f.filter(rec("pymodbus.logging", "another message")) is True)
check("our own logs are never rate limited",
      all(f.filter(rec("industrialmind.middleware", "same line")) for _ in range(10)))
f2 = mw._RateLimitFilter(("pymodbus",), interval_s=5.0)
MSG = "Connection to (host, 502) failed"
f2.filter(rec("pymodbus.logging", MSG))                       # the one that gets through
for _ in range(7):
    f2.filter(rec("pymodbus.logging", MSG))                   # swallowed
for k in list(f2._last):
    f2._last[k] = time.monotonic() - 99                       # the interval elapses
later = rec("pymodbus.logging", MSG)
f2.filter(later)
check("when it lets one through again it says how many it swallowed",
      "suppressed" in str(later.msg) and "+7" in str(later.msg), str(later.msg)[-80:])
check("the filter is attached to the HANDLER, not to the pymodbus logger",
      "_handler.addFilter(_noise)" in src and 'logging.getLogger("pymodbus").addFilter' not in src)

print("\nN2 - the dashboard must not need the internet")
html = io.open(os.path.join(ROOT, "dashboard", "templates", "index.html")).read()
check("no external stylesheet, script or font is referenced", "https://" not in html,
      [l.strip()[:60] for l in html.splitlines() if "https://" in l])
check("the chart ships with the app", os.path.exists(os.path.join(ROOT, "dashboard", "static", "vendor", "microchart.js"))
      and "vendor/microchart.js" in html)
check("the icons ship with the app", os.path.exists(os.path.join(ROOT, "dashboard", "static", "vendor", "icons.css"))
      and "vendor/icons.css" in html)
icons = io.open(os.path.join(ROOT, "dashboard", "static", "vendor", "icons.css")).read()
used = {t for t in __import__("re").findall(r"fa-[a-z-]+", html)} - {"fa-solid"}
missing = sorted(t for t in used if f".{t}::before" not in icons)
check("every icon the page uses has a glyph", not missing, f"missing: {missing}")
css = io.open(os.path.join(ROOT, "dashboard", "static", "style.css")).read()
check("the page declares an icon, so the browser does not 404 /favicon.ico on every load", 'rel="icon"' in html)
check("fonts are the system stack, not a Google Fonts download",
      "Inter'" not in css and "JetBrains Mono" not in css and "system-ui" in css)
check("the chart canvas is sized by CSS (microchart reads its CSS box)", "#cpuLoadChart" in css and "width: 100%" in css)
js = io.open(os.path.join(ROOT, "dashboard", "static", "script.js")).read()
check("nothing still reaches for Chart.js", "new Chart(" not in js and "Chart.js is not loaded" not in js)
check("a missing chart script is reported on the page, not only in the console", "chart-missing" in js and "chart-missing" in css)

print("\nALL PASS" if fails == 0 else f"\n{fails} CHECK(S) FAILED")
raise SystemExit(1 if fails else 0)
