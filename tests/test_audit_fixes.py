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

print("\nA5 - /api/health must be able to report ill health")
h = c.get("/api/health").get_json()
check("health degrades when commands went undelivered", h["status"] == "degraded" and h["degraded"], str(h["status"]))
check("health says how many", h["undelivered_commands"] == 1)
c.post("/api/reset")
check("health is ok again once the record is cleared", c.get("/api/health").get_json()["status"] == "ok")
check("reset clears the undelivered counter too", c.get("/api/dashboard").get_json()["overview"]["undelivered"] == 0)

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
check("fonts are the system stack, not a Google Fonts download",
      "Inter'" not in css and "JetBrains Mono" not in css and "system-ui" in css)
check("the chart canvas is sized by CSS (microchart reads its CSS box)", "#cpuLoadChart" in css and "width: 100%" in css)
js = io.open(os.path.join(ROOT, "dashboard", "static", "script.js")).read()
check("nothing still reaches for Chart.js", "new Chart(" not in js and "Chart.js is not loaded" not in js)
check("a missing chart script is reported on the page, not only in the console", "chart-missing" in js and "chart-missing" in css)

print("\nALL PASS" if fails == 0 else f"\n{fails} CHECK(S) FAILED")
raise SystemExit(1 if fails else 0)
