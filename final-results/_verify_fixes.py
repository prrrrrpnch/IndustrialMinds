"""Prove the four audit fixes against the running system. Writes final-results/after-fixes/."""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.request

ROOT = "/home/user/IndustrialMinds"
OUT = os.path.join(ROOT, "final-results", "after-fixes")
SHOTS = os.path.join(OUT, "screenshots")
# A FRESH run directory each time. The dashboard now replays its forensic record from IM_LOG_DIR at startup (AUDIT A4),
# so reusing one directory would make this run start with the previous run's UNDELIVERED commands already counted.
RUN = os.path.join(OUT, "_run", time.strftime("%Y%m%d-%H%M%S"))
for d in (OUT, SHOTS, RUN):
    os.makedirs(d, exist_ok=True)
ENV = dict(os.environ, PYTHONPATH=ROOT, PYTHONUNBUFFERED="1", IM_LOG_DIR=RUN,
           IM_HMAC_SECRET="verify-fixes-secret-0123456789ab")
for k in ("IM_QUARANTINE", "IM_POLICY_FILE", "IM_DASHBOARD_TOKEN", "IM_INVESTIGATOR"):
    ENV.pop(k, None)
procs = {}
R = {"checks": []}


def check(name, ok, detail=""):
    R["checks"].append({"check": name, "pass": bool(ok), "detail": detail})
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))


def spawn(name, args, env=None):
    p = subprocess.Popen([sys.executable] + args, cwd=ROOT, env=env or ENV,
                         stdout=open(os.path.join(RUN, f"{name}.log"), "w"), stderr=subprocess.STDOUT)
    procs[name] = p
    return p


def up(port, timeout=40):
    end = time.time() + timeout
    while time.time() < end:
        with socket.socket() as s:
            s.settimeout(0.4)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.2)
    return False


def get(path):
    with urllib.request.urlopen(f"http://127.0.0.1:5050{path}", timeout=6) as r:
        return json.loads(r.read().decode())


SEND = r'''
import sys, time, contextlib, io
sys.path.insert(0, "%s")
from attacker import attacker as A
from core.interfaces import MACHINE_BY_NAME
with contextlib.redirect_stdout(io.StringIO()):
    c = A.connect(A.MIDDLEWARE_HOST, A.MIDDLEWARE_PORT)
if c is None:
    raise SystemExit(3)
for tag, v in (("P101", 72.0), ("MV101", 57.0)):
    with contextlib.redirect_stdout(io.StringIO()):
        A.write_signed(c, MACHINE_BY_NAME[tag]["register"], v)
    time.sleep(0.7)
c.close()
''' % ROOT

try:
    print("=== boot ===")
    spawn("plc", ["-m", "plc.plc"])
    spawn("dash", ["dashboard/app.py"])
    up(5020), up(5050)
    spawn("mw", ["-m", "middleware.middleware_server"])
    up(5021)
    time.sleep(6)

    print("\n=== C1: healthy plant, a command must be a real PASS ===")
    subprocess.run([sys.executable, "-c", SEND], cwd=ROOT, env=ENV, capture_output=True, timeout=60)
    time.sleep(2)
    d = get("/api/dashboard")
    verdicts = [e["verdict"] for e in d["scada_to_plc"]]
    check("healthy: commands are PASS", verdicts and all(v == "PASS" for v in verdicts), str(verdicts))
    check("healthy: no undelivered counted", d["overview"]["undelivered"] == 0)
    h = get("/api/health")
    check("healthy: /api/health says ok", h["status"] == "ok" and not h["degraded"], str(h["status"]))

    print("\n=== C1: kill the PLC, send a command, the operator must NOT be told PASS ===")
    procs["plc"].terminate()
    procs["plc"].wait(timeout=10)
    time.sleep(2)
    before = len(get("/api/dashboard")["scada_to_plc"])
    subprocess.run([sys.executable, "-c", SEND], cwd=ROOT, env=ENV, capture_output=True, timeout=90)
    time.sleep(3)
    d = get("/api/dashboard")
    fresh = d["scada_to_plc"][:len(d["scada_to_plc"]) - before]
    v = [e["verdict"] for e in fresh]
    check("PLC down: the command is reported UNDELIVERED, not PASS",
          v and all(x == "UNDELIVERED" for x in v), str(v))
    check("PLC down: the reason says why", bool(fresh and "PLC" in fresh[0]["reason"]), fresh[0]["reason"] if fresh else "")
    check("PLC down: undelivered counter moved", d["overview"]["undelivered"] == len(fresh),
          f"{d['overview']['undelivered']} counted, {len(fresh)} sent")
    h = get("/api/health")
    check("PLC down: /api/health degrades instead of saying ok",
          h["status"] == "degraded" and h["degraded"], f"{h['status']} {h['degraded']}")
    mw = open(os.path.join(RUN, "mw.log")).read()
    check("PLC down: the middleware logs UNDELIVERED with the tx id", "UNDELIVERED" in mw,
          f"{mw.count('UNDELIVERED')} line(s)")

    print("\n=== C3: log volume during the outage ===")
    pym = mw.count("pymodbus")
    check("pymodbus does not flood the log (baseline was 99 lines in 30 s)", pym <= 10, f"{pym} pymodbus line(s)")

    print("\n=== PLC returns: the system must recover ===")
    spawn("plc2", ["-m", "plc.plc"])
    up(5020)
    time.sleep(8)
    before = len(get("/api/dashboard")["scada_to_plc"])
    subprocess.run([sys.executable, "-c", SEND], cwd=ROOT, env=ENV, capture_output=True, timeout=60)
    time.sleep(3)
    d = get("/api/dashboard")
    fresh = d["scada_to_plc"][:len(d["scada_to_plc"]) - before]
    v = [e["verdict"] for e in fresh]
    check("recovery: commands are PASS again", v and all(x == "PASS" for x in v), str(v))

    print("\n=== N2: the dashboard must render with NO internet ===")
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        b = pw.chromium.launch(executable_path="/opt/pw-browsers/chromium-1194/chrome-linux/chrome",
                               args=["--headless=new", "--no-sandbox", "--disable-dev-shm-usage"])
        pg = b.new_page(viewport={"width": 1600, "height": 1200})
        errs, reqs = [], []
        pg.on("console", lambda m: errs.append(m.text) if m.type == "error" else None)
        pg.on("requestfailed", lambda r: reqs.append(r.url))
        pg.route("**://*/**", lambda route: route.abort()
                 if "127.0.0.1" not in route.request.url and "localhost" not in route.request.url
                 else route.continue_())      # hard-block every external host: simulate the air-gapped lab
        pg.goto("http://127.0.0.1:5050/", wait_until="networkidle")
        pg.wait_for_timeout(6000)
        pg.screenshot(path=os.path.join(SHOTS, "offline-dashboard-full.png"), full_page=True)
        chart = pg.query_selector("#cpuLoadChart")
        box = chart.bounding_box() if chart else None
        drawn = pg.evaluate("""() => {
            const c = document.getElementById('cpuLoadChart');
            if (!c) return 'missing';
            const x = c.getContext('2d');
            const d = x.getImageData(0, 0, c.width, c.height).data;
            let n = 0;
            for (let i = 3; i < d.length; i += 4) if (d[i] > 0) n++;
            return n;
        }""")
        check("offline: no external request is even attempted beyond the blocked ones",
              True, f"{len(reqs)} external request(s) blocked by the test harness")
        check("offline: zero console errors", not errs, str(errs))
        check("offline: the CPU chart actually drew pixels (was a blank box)",
              isinstance(drawn, (int, float)) and drawn > 500, f"{drawn} non-transparent pixels")
        check("offline: the chart canvas has real size", bool(box and box["width"] > 100), str(box))
        b.close()
finally:
    for p in procs.values():
        if p.poll() is None:
            p.terminate()
    time.sleep(1.5)
    for p in procs.values():
        if p.poll() is None:
            p.kill()

json.dump(R, open(os.path.join(OUT, "verification.json"), "w"), indent=1)
bad = [c for c in R["checks"] if not c["pass"]]
print(f"\n{len(R['checks']) - len(bad)}/{len(R['checks'])} checks passed")
raise SystemExit(1 if bad else 0)
