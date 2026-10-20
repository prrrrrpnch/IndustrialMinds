"""PASS 0 live harness: start the real stack, trace the happy path, break it on purpose, record everything.

Writes JSON to final-results/before-review/_raw/. Not part of the product; kept with the audit so the baseline is reproducible.
"""
from __future__ import annotations

import json
import os
import signal
import socket
import statistics
import subprocess
import sys
import time
import urllib.request

ROOT = "/home/user/IndustrialMinds"
OUT = os.path.join(ROOT, "final-results", "before-review", "_raw")
RUN = os.path.join(OUT, "run")
os.makedirs(RUN, exist_ok=True)
MW, PLC, DASH = "127.0.0.1", "127.0.0.1", "127.0.0.1"
MW_PORT, PLC_PORT, DASH_PORT = 5021, 5020, 5050
ENV = dict(os.environ, PYTHONPATH=ROOT, PYTHONUNBUFFERED="1", IM_LOG_DIR=RUN,
           IM_HMAC_SECRET="pass0-audit-secret-0123456789abcdef")
for k in ("IM_QUARANTINE", "IM_POLICY_FILE", "IM_DASHBOARD_TOKEN", "IM_INVESTIGATOR", "IM_HMAC_KEYS"):
    ENV.pop(k, None)

procs = {}
R = {"started": time.time(), "flows": [], "integrations": [], "anomalies": [], "perf": {}}


def spawn(name, args, env=None):
    p = subprocess.Popen([sys.executable] + args, cwd=ROOT, env=env or ENV,
                         stdout=open(os.path.join(RUN, f"{name}.log"), "w"), stderr=subprocess.STDOUT)
    procs[name] = p
    return p


def up(host, port, timeout=40):
    end = time.time() + timeout
    while time.time() < end:
        with socket.socket() as s:
            s.settimeout(0.4)
            if s.connect_ex((host, port)) == 0:
                return True
        time.sleep(0.3)
    return False


def get(path, base=None):
    t = time.perf_counter()
    with urllib.request.urlopen(f"{base or f'http://{DASH}:{DASH_PORT}'}{path}", timeout=6) as r:
        body = json.loads(r.read().decode())
    return body, (time.perf_counter() - t) * 1000


def flow(name, status, detail, evidence=None):
    R["flows"].append({"flow": name, "status": status, "detail": detail, "evidence": evidence})
    print(f"[{status:10s}] {name} - {detail}")


def integ(name, status, detail):
    R["integrations"].append({"integration": name, "status": status, "detail": detail})
    print(f"  ({status}) {name}: {detail}")


def anomaly(sev, where, what):
    R["anomalies"].append({"severity": sev, "where": where, "what": what})
    print(f"  !! {sev} {where}: {what}")


SEND = r'''
import sys, time, json
sys.path.insert(0, "%s")
from attacker import attacker as A
from docs.interfaces import MACHINE_BY_NAME
spec = json.loads(sys.argv[1])
c = A.connect(A.MIDDLEWARE_HOST, A.MIDDLEWARE_PORT)
if c is None:
    print("CONNECT_FAILED"); raise SystemExit(3)
for tag, v in spec:
    ok = A.write_signed(c, MACHINE_BY_NAME[tag]["register"], v)
    print("SENT", tag, v, ok)
    time.sleep(0.6)
c.close()
''' % ROOT


def send(pairs, timeout=60):
    return subprocess.run([sys.executable, "-c", SEND, json.dumps(pairs)], cwd=ROOT, env=ENV,
                          capture_output=True, text=True, timeout=timeout)


# ============================================================ boot
print("\n=== BOOT ===")
t_boot = time.perf_counter()
spawn("plc", ["-m", "plc.plc"])
spawn("dashboard", ["dashboard/app.py"])
ok_plc, ok_dash = up(PLC, PLC_PORT), up(DASH, DASH_PORT)
spawn("middleware", ["-m", "middleware.middleware_server"])
ok_mw = up(MW, MW_PORT)
R["perf"]["cold_start_s"] = round(time.perf_counter() - t_boot, 1)
integ("PLC Modbus server :5020", "CONNECTED" if ok_plc else "BROKEN", f"listening={ok_plc}")
integ("Dashboard HTTP :5050", "CONNECTED" if ok_dash else "BROKEN", f"listening={ok_dash}")
integ("Middleware Modbus :5021", "CONNECTED" if ok_mw else "BROKEN", f"listening={ok_mw}")
if not (ok_plc and ok_dash and ok_mw):
    json.dump(R, open(os.path.join(OUT, "live.json"), "w"), indent=1)
    raise SystemExit("stack did not start")
time.sleep(6)

health, ms = get("/api/health")
integ("GET /api/health", "CONNECTED", f"{health} in {ms:.0f} ms")
mc, _ = get("/api/model")
integ("Model card published by middleware", "CONNECTED" if mc.get("model") else "MISSING",
      f"{mc.get('model')} status={mc.get('status')} threshold={mc.get('threshold')}")
if not mc.get("model"):
    anomaly("HIGH", "middleware._publish_model_card", "model card never reached the dashboard")

# ============================================================ happy path
print("\n=== HAPPY PATH ===")
seq0 = get("/api/flow")[0]["last_seq"]
r = send([["P101", 72.0], ["MV101", 57.0], ["P302", 68.0]])
time.sleep(3)
ev = get(f"/api/flow?since={seq0}")[0]["events"]
passed = [e for e in ev if e["verdict"] == "PASS"]
forwarded = [e for e in ev if e["forwarded"]]
flow("happy path: SCADA -> middleware -> PLC -> response",
     "PASS" if len(passed) == 3 and len(forwarded) == 3 else "FAIL",
     f"{len(ev)} commands seen, {len(passed)} PASS, {len(forwarded)} forwarded",
     {"events": ev, "sender_stdout": r.stdout[-600:]})
dash, dash_ms = get("/api/dashboard")
R["perf"]["dashboard_ms"] = round(dash_ms, 1)
R["dashboard_keys"] = sorted(dash)[:20]
traces, _ = get("/api/traces")
full, _ = get(f"/api/trace/{traces[0]['tx_id']}") if traces else ({}, 0)
hops = [h["hop"] for h in full.get("hops", [])]
flow("packet tracer records all seven hops", "PASS" if len(hops) == 7 else "PARTIAL", f"hops={hops}")
mwlog = open(os.path.join(RUN, "middleware.log")).read()
flow("PLC confirms the forwarded write (feedback loop closes)",
     "PASS" if "PLC RESPONSE" in mwlog else "FAIL",
     f"{mwlog.count('PLC RESPONSE')} PLC RESPONSE line(s) in the middleware log")

# ============================================================ edge case 1: the PLC dies mid-operation
print("\n=== EDGE 1: PLC KILLED MID-RUN ===")
procs["plc"].terminate()
procs["plc"].wait(timeout=10)
time.sleep(3)
seq1 = get("/api/flow")[0]["last_seq"]
r1 = send([["P101", 73.0]])
time.sleep(6)
ev1 = get(f"/api/flow?since={seq1}")[0]["events"]
mwlog = open(os.path.join(RUN, "middleware.log")).read()
reach_err = mwlog.count("cannot reach the PLC") + mwlog.count("Connection refused") + mwlog.count("PLC unreachable")
verdicts1 = [e["verdict"] for e in ev1]
flow("edge: command sent while the PLC is down",
     "PARTIAL" if verdicts1 else "FAIL",
     f"verdicts={verdicts1}; middleware logged a reachability error {reach_err} time(s)",
     {"events": ev1, "sender_rc": r1.returncode})
if verdicts1 and verdicts1[0] == "PASS":
    anomaly("HIGH", "middleware_server._handle_downstream_write",
            "a command is answered PASS to SCADA even though the PLC is unreachable; the operator is told the write "
            "succeeded and only learns otherwise from the telemetry going stale")
h_down, _ = get("/api/health")
integ("GET /api/health while the PLC is down", "CONNECTED",
      f"{h_down} - health does NOT report PLC reachability")
anomaly("MEDIUM", "dashboard.health", "/api/health returns ok with the PLC dead: it is a liveness probe for the "
                                      "dashboard process only and cannot be used to gate a demo or a deployment")

print("\n=== EDGE 1b: PLC COMES BACK ===")
spawn("plc2", ["-m", "plc.plc"])
up(PLC, PLC_PORT)
time.sleep(8)
seq2 = get("/api/flow")[0]["last_seq"]
send([["P101", 74.0]])
time.sleep(4)
ev2 = get(f"/api/flow?since={seq2}")[0]["events"]
mwlog = open(os.path.join(RUN, "middleware.log")).read()
flow("edge: middleware reconnects to the PLC by itself",
     "PASS" if ev2 and ev2[-1]["forwarded"] else "FAIL",
     f"verdicts={[e['verdict'] for e in ev2]} forwarded={[e['forwarded'] for e in ev2]}")

# ============================================================ edge case 2: malformed / hostile input
print("\n=== EDGE 2: MALFORMED AND HOSTILE INPUT ===")
cases = [("unsigned write", ["-m", "attacker.attacker", "hmac-missing"]),
         ("tampered frame", ["-m", "attacker.attacker", "hmac-tamper"]),
         ("out of bounds", ["-m", "attacker.attacker", "impossible-command"]),
         ("write to a read-only sensor", ["-m", "attacker.attacker", "sensor-write"])]
for label, args in cases:
    s0 = get("/api/flow")[0]["last_seq"]
    subprocess.run([sys.executable] + args, cwd=ROOT, env=ENV, capture_output=True, text=True, timeout=90)
    time.sleep(2)
    e = get(f"/api/flow?since={s0}")[0]["events"]
    dropped = [x for x in e if x["verdict"] == "DROP"]
    flow(f"edge: {label}", "PASS" if dropped else "FAIL",
         f"{len(dropped)}/{len(e)} dropped; reasons={[x['reason'].split(':')[0] for x in dropped]}")

# garbage straight at the frame registers
print("\n--- raw garbage at the signed-frame window ---")
GARBAGE = r'''
import sys
sys.path.insert(0, "%s")
from pymodbus.client import ModbusTcpClient
from docs.interfaces import FRAME_BASE
c = ModbusTcpClient("127.0.0.1", port=5021, timeout=3)
print("connected", c.connect())
for name, vals in (("short frame", [1, 2, 3]),
                   ("all zeros", [0] * 27),
                   ("max ints", [65535] * 27)):
    r = c.write_registers(address=FRAME_BASE, values=vals, slave=1)
    print(name, "error" if r.isError() else "accepted")
c.close()
''' % ROOT
s0 = get("/api/flow")[0]["last_seq"]
g = subprocess.run([sys.executable, "-c", GARBAGE], cwd=ROOT, env=ENV, capture_output=True, text=True, timeout=60)
time.sleep(2)
eg = get(f"/api/flow?since={s0}")[0]["events"]
alive = up(MW, MW_PORT, timeout=5)
flow("edge: raw garbage written to the frame registers",
     "PASS" if alive else "FAIL",
     f"middleware still listening={alive}; verdicts={[x['verdict'] for x in eg]}; client saw: {g.stdout.strip()[:200]}")

# ============================================================ edge case 3: dashboard dies
print("\n=== EDGE 3: DASHBOARD KILLED ===")
procs["dashboard"].terminate()
procs["dashboard"].wait(timeout=10)
time.sleep(2)
t = time.perf_counter()
r3 = send([["P101", 71.0], ["MV101", 56.0]])
elapsed = time.perf_counter() - t
mwlog = open(os.path.join(RUN, "middleware.log")).read()
flow("edge: commands keep flowing with the dashboard dead",
     "PASS" if r3.returncode == 0 else "FAIL",
     f"sender rc={r3.returncode}, {elapsed:.1f}s for 2 commands (no stall = forwarding is non-blocking)")
if "Traceback" in mwlog.split("DASHBOARD")[-1][:4000]:
    anomaly("HIGH", "orchestrator._forward_loop", "dashboard outage produced a traceback in the middleware")

# ============================================================ perf: endpoint latency under repetition
print("\n=== PERF: dashboard endpoints ===")
spawn("dashboard2", ["dashboard/app.py"])
up(DASH, DASH_PORT)
time.sleep(3)
for ep in ("/api/health", "/api/dashboard", "/api/traces", "/api/flow", "/api/incidents", "/api/model", "/api/blocked-ips", "/"):
    times = []
    codes = {}
    for _ in range(30):
        try:
            import urllib.request as _u, time as _t
            _a = _t.perf_counter()
            with _u.urlopen(f"http://{DASH}:{DASH_PORT}{ep}", timeout=6) as _r:
                _r.read()
                codes[str(_r.status)] = codes.get(str(_r.status), 0) + 1
            times.append((_t.perf_counter() - _a) * 1000)
        except Exception as exc:
            codes[type(exc).__name__] = codes.get(type(exc).__name__, 0) + 1
    if times:
        times.sort()
        R["perf"].setdefault("endpoints", {})[ep] = {
            "n": len(times), "mean_ms": round(statistics.mean(times), 2), "p50_ms": round(times[len(times) // 2], 2),
            "p95_ms": round(times[int(len(times) * 0.95)], 2), "p99_ms": round(times[-1], 2), "codes": codes}
        print(f"  {ep:22s} p50 {times[len(times)//2]:6.1f}  p95 {times[int(len(times)*0.95)]:6.1f}  max {times[-1]:6.1f} ms")

# ============================================================ resource usage
print("\n=== PERF: process footprint ===")
try:
    import psutil
    for name in ("plc2", "dashboard2", "middleware"):
        p = procs.get(name)
        if p and p.poll() is None:
            pr = psutil.Process(p.pid)
            pr.cpu_percent(interval=None)
            time.sleep(2.0)
            R["perf"].setdefault("processes", {})[name] = {
                "rss_mb": round(pr.memory_info().rss / 1e6, 1),
                "cpu_pct_2s": round(pr.cpu_percent(interval=None), 1),
                "threads": pr.num_threads(), "open_fds": pr.num_fds()}
            print(f"  {name:12s} {R['perf']['processes'][name]}")
except Exception as exc:
    print("  psutil unavailable:", exc)

# ============================================================ sustained load
print("\n=== PERF: sustained command load ===")
LOAD = r'''
import sys, time, json
sys.path.insert(0, "%s")
from attacker import attacker as A
from docs.interfaces import MACHINE_BY_NAME
reg = MACHINE_BY_NAME["P101"]["register"]
c = A.connect(A.MIDDLEWARE_HOST, A.MIDDLEWARE_PORT)
lat = []
t0 = time.time()
n = 0
import contextlib, io
while time.time() - t0 < 12:
    a = time.perf_counter()
    with contextlib.redirect_stdout(io.StringIO()):
        A.write_signed(c, reg, 70.0 + (n %% 5) * 0.1)
    lat.append((time.perf_counter() - a) * 1000)
    n += 1
    time.sleep(0.25)
c.close()
lat.sort()
print(json.dumps({"n": n, "seconds": round(time.time() - t0, 1), "p50": round(lat[len(lat)//2], 2),
                  "p95": round(lat[int(len(lat)*0.95)], 2), "max": round(lat[-1], 2)}))
''' % ROOT
lo = subprocess.run([sys.executable, "-c", LOAD], cwd=ROOT, env=ENV, capture_output=True, text=True, timeout=120)
try:
    R["perf"]["round_trip_under_load"] = json.loads(lo.stdout.strip().splitlines()[-1])
    print(" ", R["perf"]["round_trip_under_load"])
except Exception:
    print("  load probe failed:", lo.stdout[-300:], lo.stderr[-300:])

# ============================================================ logs / silent failure sweep
print("\n=== LOG SWEEP ===")
mwlog = open(os.path.join(RUN, "middleware.log")).read()
for pat, sev, note in (("Traceback", "HIGH", "unhandled exception in the middleware"),
                       ("ERROR", "MEDIUM", "error-level log line"),
                       ("AGENT_ERROR", "HIGH", "an agent failed and the command was dropped")):
    c = mwlog.count(pat)
    if c:
        anomaly(sev, "middleware.log", f"{c} x '{pat}' - {note}")
R["log_counts"] = {k: mwlog.count(k) for k in ("PASS", "DROP", "ALERT", "FORWARDED TO PLC", "PLC RESPONSE",
                                               "Traceback", "ERROR", "WARNING")}
print(" ", R["log_counts"])
blocked = os.path.join(RUN, "blocked_attacks.jsonl")
R["blocked_log_records"] = sum(1 for _ in open(blocked)) if os.path.exists(blocked) else 0
integ("Blocked-attack log file", "CONNECTED" if R["blocked_log_records"] else "MISSING",
      f"{R['blocked_log_records']} records at {blocked}")

for name, p in procs.items():
    if p.poll() is None:
        p.terminate()
time.sleep(1.5)
for p in procs.values():
    if p.poll() is None:
        p.kill()

R["finished"] = time.time()
json.dump(R, open(os.path.join(OUT, "live.json"), "w"), indent=1, default=str)
print(f"\nwrote {OUT}/live.json")
