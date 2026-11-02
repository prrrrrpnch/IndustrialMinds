#!/usr/bin/env python3
"""
tools/live_invariants_check.py - prove the physical-invariant rules work on the REAL running stack, in about two minutes.

    python -m tools.live_invariants_check [--invariants <file>] [--attack ro_deadhead] [--quiet-s 100]

Starts the real PLC twin, dashboard and middleware on free loopback ports with IM_INVARIANTS=1, waits for the monitor's history to fill, and
checks that the HEALTHY plant raises no invariant alert; then applies one synthetic actuator attack straight to the PLC (the PLC's allow-list
admits the middleware's host, which on one machine is this one) and checks that the middleware logs an upstream invariant ALERT and that the
dashboard shows it. Uses the twin-fitted file by default (config/invariants_twin.json): a SWaT-fitted file does not describe the twin.

This is a smoke test of the wiring (telemetry -> monitor -> ALERT -> dashboard), not a performance measurement.
Exit status 0 = every check passed. Nothing is written to the repo; the logs stay in the temp folder it prints.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from typing import Any, Dict, List

ROOT = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from core.interfaces import MACHINE_BY_NAME  # noqa: E402
from core.netconfig import LOOPBACK  # noqa: E402
from tools.twin_domain_gap import SCENARIOS  # noqa: E402

DEFAULT_FILE = os.path.join(ROOT, "config", "invariants_twin.json")
MARK = "physical invariant violated"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind((LOOPBACK, 0))
        return s.getsockname()[1]


def _wait_port(port: int, timeout: float = 40.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        with socket.socket() as s:
            s.settimeout(0.5)
            if s.connect_ex((LOOPBACK, port)) == 0:
                return True
        time.sleep(0.3)
    return False


def _log(path: str) -> str:
    try:
        return open(path, errors="replace").read()
    except OSError:
        return ""


def main() -> int:
    ap = argparse.ArgumentParser(description="Live check of the physical-invariant rules on the real stack (loopback).")
    ap.add_argument("--invariants", default=DEFAULT_FILE)
    ap.add_argument("--attack", default="ro_deadhead", help="a prefix of a twin_domain_gap scenario name")
    ap.add_argument("--quiet-s", type=float, default=100.0, help="seconds of healthy operation to observe before the attack (must exceed the lookback)")
    ap.add_argument("--attack-s", type=float, default=45.0, help="seconds to wait for the alert after the attack")
    a = ap.parse_args()
    name = next((n for n in SCENARIOS if n.startswith(a.attack)), None)
    if name is None:
        raise SystemExit(f"unknown attack {a.attack!r}; choose from: {', '.join(n.split(' ')[0] for n in SCENARIOS)}")
    if not os.path.exists(a.invariants):
        raise SystemExit(f"no invariant file at {a.invariants} (python -m tools.fit_invariants --twin)")

    tmp = tempfile.mkdtemp(prefix="im-live-inv-")
    plc, mw, dash = _free_port(), _free_port(), _free_port()
    env = dict(os.environ, IM_LOG_DIR=tmp, IM_PLC_PORT=str(plc), IM_PLC_LISTEN_PORT=str(plc), IM_MIDDLEWARE_PORT=str(mw), IM_LISTEN_PORT=str(mw),
               IM_DASHBOARD_PORT=str(dash), IM_HMAC_SECRET=os.urandom(24).hex(), IM_TRUSTED_SOURCES=LOOPBACK, IM_POLICY_FILE=os.path.join(tmp, "no-policy.json"),
               IM_INVARIANTS="1", IM_INVARIANTS_FILE=a.invariants, IM_INVARIANT_ALERT_SECONDS="5", PYTHONUNBUFFERED="1", PYTHONPATH=ROOT)
    for k in ("IM_QUARANTINE", "IM_HMAC_KEYS", "IM_HMAC_KEYS_FILE", "IM_DASHBOARD_TOKEN", "IM_INVARIANT_THETA"):
        env.pop(k, None)
    procs: List[subprocess.Popen] = []
    results: List[Dict[str, Any]] = []

    def check(label: str, ok: bool, detail: str = "") -> None:
        results.append({"check": label, "pass": bool(ok), "detail": detail})
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f"  ({detail})" if detail else ""))

    def spawn(args: List[str], log: str) -> None:
        procs.append(subprocess.Popen([sys.executable] + args, cwd=ROOT, env=env, stdout=open(os.path.join(tmp, log), "w"), stderr=subprocess.STDOUT))

    print(f"live invariant check: logs in {tmp}; ports PLC {plc}, middleware {mw}, dashboard {dash}; attack = {name}")
    try:
        spawn(["-m", "plc.plc"], "plc.log")
        spawn(["dashboard/app.py"], "dashboard.log")
        if not (_wait_port(plc) and _wait_port(dash)):
            check("PLC and dashboard start", False, "see " + tmp)
            return 1
        spawn(["-m", "middleware.middleware_server"], "middleware.log")
        check("middleware starts with the invariants enabled", _wait_port(mw))
        time.sleep(2.0)
        mwlog = lambda: _log(os.path.join(tmp, "middleware.log"))
        check("the middleware loaded the invariant file", "physical invariants ON" in mwlog(), next((ln for ln in mwlog().splitlines() if "physical invariants ON" in ln), "")[-120:])

        print(f"  ... observing the healthy plant for {a.quiet_s:.0f} s")
        time.sleep(a.quiet_s)
        healthy_alerts = mwlog().count(MARK)
        check("the healthy plant raised no invariant alert", healthy_alerts == 0, f"{healthy_alerts} alerts")

        from pymodbus.client import ModbusTcpClient
        c = ModbusTcpClient(LOOPBACK, port=plc)
        check("connected to the PLC", c.connect())
        t_attack = time.time()
        for tag, v in SCENARIOS[name].items():
            c.write_register(MACHINE_BY_NAME[tag]["register"], int(round(v * 10)))
        c.close()
        end, seen = time.time() + a.attack_s, False
        while time.time() < end and not seen:
            time.sleep(0.5)
            seen = MARK in mwlog()
        delay = time.time() - t_attack
        line = next((ln for ln in mwlog().splitlines() if MARK in ln), "")
        check("the attack raised an upstream invariant ALERT in the middleware log", seen, f"after {delay:.1f} s: {line[-110:]}")
        time.sleep(2.0)
        try:
            with urllib.request.urlopen(f"http://{LOOPBACK}:{dash}/api/dashboard", timeout=5) as r:
                body = r.read().decode()
        except Exception as exc:
            body = ""
            print("  dashboard read failed:", exc)
        check("the dashboard shows the invariant ALERT", "invariant" in body and "ALERT" in body)
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=8)
            except subprocess.TimeoutExpired:
                p.kill()
    ok = all(r["pass"] for r in results)
    print("\nALL PASS" if ok else "\nSOME CHECKS FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
