"""
tests/test_sprint_fixes.py - the five STRUCTURAL defects from the adversarial audit (final-results/AUDIT.md, "do this
sprint"), each pinned so it cannot come back silently:

    C5     replay protection was a read-then-write with no lock, safe only because one thread happened to call it
    C2     the PLC forward ran on the asyncio event loop, so one dead PLC stalled every SCADA client
    S3     the dashboard could be bound to a network with NO authentication on its state-changing POST endpoints
    C4     the poll loop retried a dead PLC every 0.2 s forever (~18,000 attempts/hour)
    A6/N6  nothing counted dropped forwards, and the header badge said ONLINE whatever the plant was doing

Like tests/test_audit_fixes.py these are OPERATOR-LEVEL requirements, not component specifications.

    python -m tests.test_sprint_fixes
"""

from __future__ import annotations

import io
import os
import tempfile
import threading
import time

os.environ.setdefault("IM_LOG_DIR", tempfile.mkdtemp(prefix="im-sprint-"))

from core import hmac_auth# noqa: E402
from core.interfaces import MACHINE_BY_NAME  # noqa: E402
from middleware import cyber_agent  # noqa: E402
from middleware import forwarding as fwd  # noqa: E402
from middleware import ingest  # noqa: E402
from middleware import middleware_server as mw  # noqa: E402
from middleware import polling  # noqa: E402
from middleware import runtime  # noqa: E402

fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global fails
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    fails += 0 if cond else 1


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# AUDIT A1 split the middleware; these checks are about what the MIDDLEWARE does, so they read the package, and name the
# owning module where the point of a check is where the code lives.
import glob  # noqa: E402
MW_SRC = "\n".join(io.open(f).read() for f in sorted(glob.glob(os.path.join(ROOT, "middleware", "*.py"))))
FWD_SRC = io.open(os.path.join(ROOT, "middleware", "forwarding.py")).read()
ING_SRC = io.open(os.path.join(ROOT, "middleware", "ingest.py")).read()
SRV_SRC = io.open(os.path.join(ROOT, "middleware", "middleware_server.py")).read()
CY_SRC = io.open(os.path.join(ROOT, "middleware", "cyber_agent.py")).read()

# =============================================================================
print("C5 - replay protection must hold under concurrency, not by accident")
# =============================================================================

check("the cyber agent's mutable state has a lock at all", "_state_lock" in CY_SRC and "threading.RLock()" in CY_SRC)
check("the nonce check is inside it (the membership test and the insert are one step)",
      "with _state_lock:" in CY_SRC.split("def _check_nonce")[1].split("def ")[0])
check("so are the rate and replay windows",
      "with _state_lock:" in CY_SRC.split("def _check_rate")[1].split("def ")[0]
      and "with _state_lock:" in CY_SRC.split("def _check_replay")[1].split("def ")[0])

# The real thing: fire ONE nonce from many threads at once and demand exactly one acceptance.
for attempt in range(25):
    cyber_agent.reset_state()
    auth = {"nonce": 0xDEADBEEF00000000 + attempt}
    now = time.time()
    results, start = [], threading.Event()

    def race() -> None:
        start.wait()
        results.append(cyber_agent._check_nonce(auth, now))

    threads = [threading.Thread(target=race) for _ in range(12)]
    for t in threads:
        t.start()
    start.set()
    for t in threads:
        t.join()
    accepted = sum(1 for r in results if r)
    if accepted != 1:
        break

check("12 threads replaying ONE nonce together: exactly one is accepted, 25 times over",
      accepted == 1, f"attempt {attempt}: {accepted} accepted")

cyber_agent.reset_state()
errors = []


def hammer() -> None:
    try:
        for i in range(400):
            cyber_agent._check_rate(f"127.0.0.{i % 7}", time.time())
            cyber_agent._check_replay({"source_ip": f"127.0.0.{i % 7}", "function_code": 6,
                                       "register": i % 20, "value": float(i)}, time.time())
            cyber_agent._sweep_idle_sources(time.time())
    except Exception as exc:                       # a dict/deque mutated during iteration raises RuntimeError
        errors.append(repr(exc))


ts = [threading.Thread(target=hammer) for _ in range(6)]
for t in ts:
    t.start()
for t in ts:
    t.join()
check("6 threads hammering the rate/replay tables and the sweep raise nothing", not errors, str(errors[:2]))
cyber_agent.reset_state()

# =============================================================================
print("\nC2 - the PLC forward must not run on the asyncio event loop")
# =============================================================================

check("there is a forwarder thread, not an inline blocking write in the handler",
      "_forward_worker" in MW_SRC and "name=\"plc-forwarder\"" in MW_SRC)
check("the handler enqueues and returns", "_forward_queue.put_nowait(job)" in MW_SRC)
check("the handler no longer calls _forward_to_plc itself",
      "success = _forward_to_plc(" in FWD_SRC.split("def _forward_job")[1].split("\ndef ")[0]
      and "_forward_to_plc(" not in ING_SRC.split("Register the pending command BEFORE")[1].split("\ndef ")[0])
check("ONE worker, so writes to the same register keep their order",
      FWD_SRC.count('target=_forward_worker') == 1 and "ThreadPoolExecutor" not in FWD_SRC)
check("the queue is bounded, so a dead PLC cannot grow the backlog without limit",
      "queue.Queue(maxsize=FORWARD_QUEUE_MAX)" in FWD_SRC and fwd.FORWARD_QUEUE_MAX > 0,
      f"max {fwd.FORWARD_QUEUE_MAX}")
check("every call on the shared PLC client is serialised by OUR lock, not a library internal",
      "_plc_io_lock" in FWD_SRC and "with _plc_io_lock:" in FWD_SRC.split("def _forward_to_plc")[1].split("\ndef ")[0])

# A full queue must still reach the operator as an undelivered command.
reported = []
_real_report = fwd.orchestrator.forward_delivery_failure
fwd.orchestrator.forward_delivery_failure = lambda **kw: reported.append(kw)
try:
    before = runtime.health_snapshot()["dropped_forwards"]
    job = {"register": 1, "register_name": "P101", "value": 72.0, "tx_id": "tx-full", "report": {}, "alert": False}
    fwd._report_undelivered(job, "FORWARD_QUEUE_FULL: test")
    check("a command the forwarder could not even accept is reported, never dropped in silence",
          reported and reported[0]["tx_id"] == "tx-full" and "QUEUE_FULL" in reported[0]["reason"], str(reported[:1]))
finally:
    fwd.orchestrator.forward_delivery_failure = _real_report

# The worker must survive a job that blows up, or every later command is stranded.
boom = {"register": 1, "register_name": "P101", "value": 1.0, "tx_id": "tx-boom", "report": None, "alert": False}
done = []
fwd._forward_queue.put(boom)
fwd._forward_queue.put(None)
t = threading.Thread(target=lambda: (fwd._forward_worker(), done.append(True)))
t.start()
t.join(timeout=10)
check("the forwarder survives a job that raises and keeps draining the queue", done == [True] and not t.is_alive())

# =============================================================================
print("\nC4 - a dead PLC must not be retried 5x a second forever")
# =============================================================================


def with_failures(n: int) -> float:
    with runtime._state_lock:
        runtime._health["consecutive_poll_failures"] = n
    return polling._poll_delay()


check("a healthy PLC keeps the normal cadence", with_failures(0) == runtime.POLL_INTERVAL, f"{with_failures(0)}s")
check("a brief blip is not punished", with_failures(runtime.POLL_BACKOFF_AFTER) == runtime.POLL_INTERVAL)
check("a sustained outage backs off", with_failures(runtime.POLL_BACKOFF_AFTER + 3) > runtime.POLL_INTERVAL,
      f"{with_failures(runtime.POLL_BACKOFF_AFTER + 3)}s")
check("the backoff is capped, so recovery is still noticed within seconds",
      with_failures(999) == runtime.POLL_BACKOFF_MAX and runtime.POLL_BACKOFF_MAX <= 10.0, f"{runtime.POLL_BACKOFF_MAX}s")
hourly = 3600.0 / runtime.POLL_BACKOFF_MAX
check("an hour of outage costs hundreds of attempts, not ~18,000", hourly < 1500, f"{hourly:.0f} attempts/hour")
polling._note_poll_success()
check("one good read resets it to the normal cadence", polling._poll_delay() == runtime.POLL_INTERVAL)
check("health tracks the PLC leg", runtime.health_snapshot()["plc_connected"] is True)
polling._note_poll_failure()
check("and a failed poll flips it", runtime.health_snapshot()["plc_connected"] is False
      and runtime.health_snapshot()["consecutive_poll_failures"] == 1)
polling._note_poll_success()

# =============================================================================
print("\nS3 - an unauthenticated dashboard must never be put on a network")
# =============================================================================

from dashboard import app as dash  # noqa: E402

check("loopback is still allowed with no token (the one-laptop demo is unchanged)",
      dash.check_bind_is_safe("127.0.0.1") is None and dash.check_bind_is_safe("localhost") is None)
check("binding to every interface without a token is REFUSED",
      dash.check_bind_is_safe("0.0.0.0") is not None)
check("the refusal names the fix, not just the problem",
      "IM_DASHBOARD_TOKEN" in (dash.check_bind_is_safe("0.0.0.0") or ""))
check("a hostname that is not provably loopback is treated as exposed",
      dash.check_bind_is_safe("plc-lab-host") is not None)
check("with a token, a network bind is allowed",
      dash.check_bind_is_safe.__doc__ is not None)
_saved = dash._DASHBOARD_TOKEN
dash._DASHBOARD_TOKEN = "a-real-token"
check("...verified: the same bind passes once a token is configured", dash.check_bind_is_safe("0.0.0.0") is None)
dash._DASHBOARD_TOKEN = _saved
dash_src = io.open(os.path.join(ROOT, "dashboard", "app.py")).read()
check("the check actually runs at startup and aborts the process",
      "check_bind_is_safe(args.host)" in dash_src and "raise SystemExit(2)" in dash_src)

# =============================================================================
print("\nA6/N6 - the operator must be told when the plant leg is broken")
# =============================================================================

c = dash.app.test_client()
c.post("/api/reset")
h = c.get("/api/health").get_json()
check("with no traffic and no middleware, health does not claim a healthy PLC",
      h["plc"] == "not reported", str(h["plc"]))

c.post("/api/middleware-health", json={"plc_connected": True, "consecutive_poll_failures": 0,
                                       "dropped_forwards": 0, "undelivered": 0, "forward_backlog": 0})
h = c.get("/api/health").get_json()
check("a healthy heartbeat reads ok", h["status"] == "ok" and h["plc"] == "connected", f"{h['status']}/{h['plc']}")

c.post("/api/middleware-health", json={"plc_connected": False, "consecutive_poll_failures": 41,
                                       "dropped_forwards": 0, "undelivered": 2, "forward_backlog": 7})
h = c.get("/api/health").get_json()
check("THE OPERATOR IS TOLD THE PLC IS UNREACHABLE", h["plc"] == "unreachable" and h["status"] == "degraded",
      f"{h['status']}/{h['plc']}")
check("and how long it has been failing", any("41" in d for d in h["degraded"]), str(h["degraded"]))
check("the forward backlog is visible", h["forward_backlog"] == 7)

c.post("/api/middleware-health", json={"plc_connected": True, "dropped_forwards": 3, "forward_backlog": 0})
h = c.get("/api/health").get_json()
check("dropped forwards degrade health and are counted (AUDIT A6)",
      h["dropped_forwards"] == 3 and h["status"] == "degraded"
      and any("dropped" in d for d in h["degraded"]), str(h["degraded"]))

with dash._lock:
    dash._middleware_health["received_at"] = time.time() - (dash.MIDDLEWARE_HEALTH_STALE_S + 5)
h = c.get("/api/health").get_json()
check("a middleware that stopped reporting is itself a degraded state, not silence",
      h["plc"] == "unknown" and h["status"] == "degraded", f"{h['status']}/{h['plc']}")
c.post("/api/reset")

check("the middleware actually sends the heartbeat", "forward_middleware_health(" in MW_SRC
      and "def forward_middleware_health" in io.open(os.path.join(ROOT, "middleware", "orchestrator.py")).read())
check("it sends it from the poll loop, on a timer", "_report_health_if_due()" in MW_SRC)
check("the snapshot carries what health() needs",
      set(runtime.health_snapshot()) >= {"plc_connected", "consecutive_poll_failures", "dropped_forwards",
                                         "undelivered", "forward_backlog"})

html = io.open(os.path.join(ROOT, "dashboard", "templates", "index.html")).read()
js = io.open(os.path.join(ROOT, "dashboard", "static", "script.js")).read()
css = io.open(os.path.join(ROOT, "dashboard", "static", "style.css")).read()
check("the header badge is no longer the hardcoded word ONLINE",
      "<strong>ONLINE</strong>" not in html and 'id="systemStatusText"' in html)
check("it is driven by /api/health", 'fetch("/api/health")' in js and "refreshHealth" in js)
check("it refreshes on its own", "setInterval(refreshHealth" in js)
check("it can render a degraded state", "DEGRADED" in js and ".status-dot.degraded" in css)
check("it says WHY, on the page and not only in a tooltip", "systemStatusDetail" in js and "status-detail" in css)

# =============================================================================
print("\nA1/A2 - the god module is split, and the storage hook no longer decides")
# =============================================================================

import os.path as _p  # noqa: E402

sizes = {m: sum(1 for _ in io.open(_p.join(ROOT, "middleware", f"{m}.py")))
         for m in ("middleware_server", "runtime", "forwarding", "ingest", "polling")}
check("middleware_server is no longer a 1,478-line god module", sizes["middleware_server"] < 600, str(sizes))
check("no middleware module is over 600 lines", max(sizes.values()) < 600, str(sizes))
check("the four responsibilities the audit named each have a home",
      all(_p.exists(_p.join(ROOT, "middleware", f"{m}.py")) for m in ("runtime", "forwarding", "ingest", "polling")))

hook = SRV_SRC.split("def setValues")[1].split("\ndef ")[0]
check("THE STORAGE HOOK ENQUEUES, IT DOES NOT DECIDE (AUDIT A2)",
      "ingest.submit(" in hook and "process_command" not in hook and "_handle_downstream_write" not in hook, hook[:120])
check("there is a bounded decision queue with one worker",
      "queue.Queue(maxsize=DECISION_QUEUE_MAX)" in ING_SRC and ING_SRC.count("target=_decision_worker") == 1)
check("one worker, because the rate limit, the replay window and the cross-register rules are order-dependent",
      "ThreadPoolExecutor" not in ING_SRC)
check("a write the queue cannot accept is reported and fails CLOSED (nothing forwarded)",
      "DECISION QUEUE FULL" in ING_SRC and "dropped_writes" in ING_SRC)

# The arrival time must survive the queue, or moving the decision off the hot path would change the decision.
check("the arrival time is captured at submit, not at dequeue",
      '"arrival": time.time()' in ING_SRC and "arrival=job[\"arrival\"]" in ING_SRC)
check("...and _handle_downstream_write uses it as start_time",
      "time.time() if arrival is None else arrival" in ING_SRC)

# Behavioural: a write submitted now and decided later must be timestamped now.
seen = []
_real_hdw = ingest._handle_downstream_write
ingest._handle_downstream_write = lambda *a, **k: seen.append(k.get("arrival"))
try:
    t_submit = time.time()
    ingest._process_write(0, [700], {"source_ip": "127.0.0.1", "function_code": 6}, arrival=t_submit)
    check("the decision is stamped with when the write ARRIVED", seen and seen[0] == t_submit, str(seen))
finally:
    ingest._handle_downstream_write = _real_hdw

check("runtime imports no middleware sibling at module level (it is the bottom layer)",
      not [l for l in io.open(_p.join(ROOT, "middleware", "runtime.py")).read().split("def ")[0].splitlines()
           if l.startswith("from middleware") or l.startswith("import middleware")])
check("middleware_server still re-exports the old names, so existing callers keep working",
      all(hasattr(mw, n) for n in ("_poll_once", "_forward_to_plc", "_process_write", "_pending_commands",
                                   "_state_lock", "health_snapshot", "_publish_trace")))
check("and it SAYS a re-export is a snapshot, so patch the owning module",
      "SNAPSHOTS of a binding" in SRV_SRC)

print("\nALL PASS" if fails == 0 else f"\n{fails} CHECK(S) FAILED")
raise SystemExit(1 if fails else 0)
