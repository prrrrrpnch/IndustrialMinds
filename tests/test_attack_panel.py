"""
tests/test_attack_panel.py - the menu-driven attack panel (attacker/control_panel.py): what the buttons may start, who may press them.

The launcher is replaced by a harmless command, so no attack is sent. The HTTP server is the real one.

    python -m tests.test_attack_panel
"""

from __future__ import annotations

import json
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from attacker import control_panel as cp

fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global fails
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    fails += 0 if cond else 1


# every button maps to a real attack name the attacker accepts
import attacker.attacker as atk  # noqa: E402
known = set(atk.ATTACKS) | {"random"}
check("every button starts an attack the attacker knows", all(a["args"][0] in known for a in cp.ATTACKS),
      str([a["args"][0] for a in cp.ATTACKS if a["args"][0] not in known]))
check("button ids are unique", len({a["id"] for a in cp.ATTACKS}) == len(cp.ATTACKS))
check("the panel port is not one a browser blocks (5060/5061 are SIP)", cp.PORT not in (5060, 5061, 6000, 6665, 6666, 6667, 6668, 6669, 6697))

# harmless launcher: prints two lines, then exits
cp.launcher_command = lambda args: [sys.executable, "-c", "import time;print('line one');print('line two');time.sleep(0.6)"]
slow = lambda args: [sys.executable, "-c", "import time;print('long run',flush=True);time.sleep(30)"]
cp.PAUSE_BETWEEN_S = 0.2

httpd = ThreadingHTTPServer(("127.0.0.1", 0), cp.Handler)
port = httpd.server_address[1]
threading.Thread(target=httpd.serve_forever, daemon=True).start()
base = f"http://127.0.0.1:{port}"


def call(path, method="GET", body=None, headers=None):
    req = urllib.request.Request(base + path, data=json.dumps(body or {}).encode() if method == "POST" else None, method=method,
                                 headers=headers if headers is not None else ({"X-Panel": "1", "Content-Type": "application/json"} if method == "POST" else {}))
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def wait_idle(timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        if not cp.RUNNER.busy():
            return True
        time.sleep(0.05)
    return False


print("page and listing")
with urllib.request.urlopen(base + "/") as r:
    html = r.read().decode()
check("the page is served and has a button container", "id=\"buttons\"" in html and "ATTACK PANEL" in html)
st, d = call("/api/attacks")
check("the attack list is served with the target", st == 200 and len(d["attacks"]) == len(cp.ATTACKS) and "target" in d)

print("who may press a button")
check("a POST without the X-Panel header is refused (a web page on another site cannot set it)",
      call("/api/run", "POST", {"id": "flood"}, headers={})[0] == 403)
req = urllib.request.Request(base + "/api/attacks", headers={"Host": "evil.example"})
try:
    urllib.request.urlopen(req, timeout=5)
    host_refused = False
except urllib.error.HTTPError as e:
    host_refused = e.code == 403
check("a request with a foreign Host header is refused (DNS rebinding)", host_refused)
check("an unknown attack id starts nothing", call("/api/run", "POST", {"id": "rm -rf /"})[0] == 409 and not cp.RUNNER.busy())

print("running an attack")
st, d = call("/api/run", "POST", {"id": "flood"})
check("a button starts its attack", st == 200 and d["started"])
st2, d2 = call("/api/run", "POST", {"id": "replay"})
check("a second click while one runs is refused", st2 == 409 and not d2["started"])
check("the attack finishes", wait_idle())
_, out = call("/api/output?since=0")
texts = [l["text"] for l in out["lines"]]
check("its output was captured, with a header and an exit line", any("line one" in t for t in texts)
      and any(t.startswith(">>> Flood") for t in texts) and any("finished (exit code 0" in t for t in texts), str(texts[:4]))
check("it is recorded in the history", out["history"] and out["history"][-1]["label"] == "Flood" and out["history"][-1]["code"] == 0)
_, later = call(f"/api/output?since={out['last']}")
check("polling with 'since' returns only new lines", later["lines"] == [])

print("stopping")
cp.launcher_command = slow
call("/api/run", "POST", {"id": "flood"})
time.sleep(0.5)
check("a long attack shows as running", call("/api/output?since=0")[1]["running"])
call("/api/stop", "POST")
check("Stop ends it quickly", wait_idle(8))

print("run all")
cp.launcher_command = lambda args: [sys.executable, "-c", "print('x')"]
check("run-all starts", call("/api/run-all", "POST")[1]["started"])
check("run-all runs every attack, one after another", wait_idle(60) and
      sum(1 for l in call("/api/output?since=0")[1]["lines"] if l["text"].startswith(">>> ")) >= len(cp.ATTACKS))
call("/api/clear", "POST")
check("Clear empties the output", call("/api/output?since=0")[1]["lines"] == [])

httpd.shutdown()
print("\nALL PASS" if fails == 0 else f"\n{fails} CHECK(S) FAILED")
raise SystemExit(1 if fails else 0)
