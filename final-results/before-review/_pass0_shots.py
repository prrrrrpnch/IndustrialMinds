"""PASS 0 evidence capture: real dashboard screenshots after real traffic, plus the metric figures."""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time

ROOT = "/home/user/IndustrialMinds"
SHOTS = os.path.join(ROOT, "final-results", "before-review", "screenshots")
RUN = os.path.join(ROOT, "final-results", "before-review", "_raw", "shots")
os.makedirs(SHOTS, exist_ok=True)
os.makedirs(RUN, exist_ok=True)
ENV = dict(os.environ, PYTHONPATH=ROOT, PYTHONUNBUFFERED="1", IM_LOG_DIR=RUN,
           IM_HMAC_SECRET="pass0-audit-secret-0123456789abcdef")
for k in ("IM_QUARANTINE", "IM_POLICY_FILE", "IM_DASHBOARD_TOKEN", "IM_INVESTIGATOR"):
    ENV.pop(k, None)
procs = []


def spawn(name, args):
    p = subprocess.Popen([sys.executable] + args, cwd=ROOT, env=ENV,
                         stdout=open(os.path.join(RUN, f"{name}.log"), "w"), stderr=subprocess.STDOUT)
    procs.append(p)
    return p


def up(port, timeout=40):
    end = time.time() + timeout
    while time.time() < end:
        with socket.socket() as s:
            s.settimeout(0.4)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.3)
    return False


try:
    spawn("plc", ["-m", "plc.plc"])
    spawn("dash", ["dashboard/app.py"])
    up(5020), up(5050)
    spawn("mw", ["-m", "middleware.middleware_server"])
    up(5021)
    time.sleep(6)
    print("stack up; generating traffic")
    sender = r'''
import sys, time
sys.path.insert(0, "%s")
from attacker import attacker as A
from docs.interfaces import MACHINE_BY_NAME
c = A.connect(A.MIDDLEWARE_HOST, A.MIDDLEWARE_PORT)
for tag, v in (("P101", 72.0), ("MV101", 57.0), ("P302", 68.0), ("UV401", 71.0)):
    A.write_signed(c, MACHINE_BY_NAME[tag]["register"], v)
    time.sleep(0.8)
c.close()
''' % ROOT
    subprocess.run([sys.executable, "-c", sender], cwd=ROOT, env=ENV, capture_output=True, timeout=60)
    for a in ("hmac-tamper", "impossible-command", "replay", "flood"):
        subprocess.run([sys.executable, "-m", "attacker.attacker", a], cwd=ROOT, env=ENV, capture_output=True, timeout=90)
        time.sleep(1)
    time.sleep(4)

    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        b = pw.chromium.launch(executable_path="/opt/pw-browsers/chromium-1194/chrome-linux/chrome", args=["--headless=new", "--no-sandbox", "--disable-dev-shm-usage"])
        pg = b.new_page(viewport={"width": 1600, "height": 1200})
        pg.goto("http://127.0.0.1:5050/", wait_until="networkidle")
        pg.wait_for_timeout(5000)
        pg.screenshot(path=os.path.join(SHOTS, "happy-path-dashboard-full.png"), full_page=True)
        print("captured full dashboard")
        for sel, name in ((".tracer-card", "happy-path-packet-tracer"),
                          (".incident-card", "error-path-incidents"),
                          (".model-strip", "integration-model-card"),
                          (".investigation-card", "integration-investigations")):
            try:
                el = pg.query_selector(sel)
                if el:
                    el.scroll_into_view_if_needed()
                    pg.wait_for_timeout(600)
                    el.screenshot(path=os.path.join(SHOTS, f"{name}.png"))
                    print("captured", name)
                else:
                    print("MISSING section:", sel)
            except Exception as exc:
                print("shot failed", sel, exc)
        errs = []
        pg.on("console", lambda m: errs.append(m.text) if m.type == "error" else None)
        pg.reload(wait_until="networkidle")
        pg.wait_for_timeout(4000)
        json.dump({"console_errors": errs}, open(os.path.join(RUN, "console.json"), "w"), indent=1)
        print("browser console errors:", errs or "none")
        b.close()
finally:
    for p in procs:
        p.terminate()
    time.sleep(1.5)
    for p in procs:
        if p.poll() is None:
            p.kill()
print("done")
