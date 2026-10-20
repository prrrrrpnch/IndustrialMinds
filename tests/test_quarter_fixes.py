"""
tests/test_quarter_fixes.py - the architectural findings from the adversarial audit (final-results/AUDIT.md,
"do next quarter"), each pinned so it cannot come back silently:

    S1   anything on the OT segment could write straight to the PLC and move the plant
    A4   traces, incidents and investigations existed ONLY in the Flask process: restart = total forensic loss
    #11  source code lived in a folder called docs/, and ~29% of models/ and swat/ was rejected experiments

S4 (quarantine keyed to authenticated identity) is pinned in tests/test_response_layer.py, next to the rest of the
response layer, and demonstrated end-to-end by benchmark/evidence_pack.py.

Operator-level requirements, not component specifications - see the header of tests/test_audit_fixes.py.

    python -m tests.test_quarter_fixes
"""

from __future__ import annotations

import io
import json
import os
import socket
import subprocess
import sys
import tempfile

os.environ.setdefault("IM_LOG_DIR", tempfile.mkdtemp(prefix="im-quarter-"))

fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global fails
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    fails += 0 if cond else 1


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# =============================================================================
print("S1 - the PLC must not take orders from anything but the middleware")
# =============================================================================

from plc import plc  # noqa: E402

check("there is a write allow-list at all", hasattr(plc, "writer_allowed") and hasattr(plc, "refused_writes"))
check("it defaults to the middleware's address, not to 'off' (the audit's A5: every control shipped opt-in)",
      plc.ALLOWED_WRITERS_ENV and not plc._ALLOW_ANY, f"IM_PLC_ALLOWED_WRITERS={plc.ALLOWED_WRITERS_ENV}")
check("the middleware's own address is allowed", plc.writer_allowed("127.0.0.1"))
check("A DIFFERENT HOST ON THE SEGMENT IS NOT", not plc.writer_allowed("127.0.0.4"))
check("an IPv4-mapped IPv6 peer is resolved, not waved through", plc.writer_allowed("::ffff:127.0.0.1")
      and not plc.writer_allowed("::ffff:127.0.0.4"))
check("a write with no identifiable peer is refused, not allowed by default",
      not plc.writer_allowed(None) and not plc.writer_allowed("unknown") and not plc.writer_allowed("not-an-ip"))
check("the setting lives in core/netconfig like every other address",
      "PLC_ALLOWED_WRITERS" in io.open(os.path.join(ROOT, "core", "netconfig.py")).read())

src = io.open(os.path.join(ROOT, "plc", "plc.py")).read()
check("the check is in the datastore write hook, where the plant is actually commanded",
      "writer_allowed(source_ip)" in src.split("def setValues")[1].split("def ")[0])
check("a refused write never reaches the physics (no super().setValues, no apply_write)",
      src.split("def setValues")[1].split("def ")[0].index("return") <
      src.split("def setValues")[1].split("def ")[0].index("super().setValues"))
check("the peer address is captured per request, like the middleware does it",
      "WriteSourceRequestHandler" in src and "get_extra_info(\"peername\")" in src)
check("a refusal is logged as a bypass attempt, rate limited", "REFUSED direct write" in src
      and "REFUSAL_LOG_INTERVAL" in src)
check("the bypass can still be demonstrated on purpose, explicitly", '"any", "*", "all"' in src)
check("the PLC says at startup which writers it accepts", "writes accepted only from" in src)

n_before = len(plc.refused_writes())
plc._record_refusal("127.0.0.4", 0, 95.0)
rec = plc.refused_writes()
check("refusals are counted and attributed, for the operator and for a report",
      len(rec) == n_before + 1 and rec[-1]["source_ip"] == "127.0.0.4" and rec[-1]["name"] == "MV101", str(rec[-1]))

# The real thing: a live PLC, two writers, one allowed and one not.
RUN = tempfile.mkdtemp(prefix="s1-live-")
LIVE = r'''
import socket, sys, time
sys.path.insert(0, %r)
from pymodbus.client import ModbusTcpClient
from core.interfaces import MACHINE_BY_NAME, to_raw, from_raw
REG = MACHINE_BY_NAME["MV101"]["register"]
def write_from(ip, value):
    c = ModbusTcpClient("127.0.0.1", port=5031, timeout=3, source_address=(ip, 0))
    c.connect(); c.write_register(REG, to_raw(value)); time.sleep(1.5)
    v = from_raw(c.read_holding_registers(REG, count=1).registers[0]); c.close(); return v
print("ALLOWED", write_from("127.0.0.1", 30.0))
time.sleep(2)
print("BYPASS", write_from("127.0.0.4", 95.0))
''' % ROOT

env = dict(os.environ, PYTHONPATH=ROOT, PYTHONUNBUFFERED="1", IM_LOG_DIR=RUN,
           IM_PLC_LISTEN_HOST="0.0.0.0", IM_PLC_LISTEN_PORT="5031", IM_PLC_ALLOWED_WRITERS="127.0.0.1")
proc = subprocess.Popen([sys.executable, "-m", "plc.plc"], cwd=ROOT, env=env,
                        stdout=open(os.path.join(RUN, "plc.log"), "w"), stderr=subprocess.STDOUT)
try:
    import time as _t
    for _ in range(60):
        with socket.socket() as s:
            s.settimeout(0.3)
            if s.connect_ex(("127.0.0.1", 5031)) == 0:
                break
        _t.sleep(0.25)
    _t.sleep(2)
    out = subprocess.run([sys.executable, "-c", LIVE], cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
    vals = {l.split()[0]: float(l.split()[1]) for l in out.stdout.splitlines() if l.startswith(("ALLOWED", "BYPASS"))}
    check("live: the allowed writer moves the valve", "ALLOWED" in vals and vals["ALLOWED"] < 50.0, str(vals))
    check("LIVE: THE BYPASS WRITE DOES NOT MOVE THE PLANT",
          "BYPASS" in vals and vals["BYPASS"] < 50.0, f"{vals} (95.0 would mean the bypass worked)")
    plog = io.open(os.path.join(RUN, "plc.log")).read()
    check("live: the PLC logged the bypass attempt with its source",
          "REFUSED direct write from 127.0.0.4" in plog, plog.count("REFUSED"))
finally:
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except Exception:
        proc.kill()

# =============================================================================
print("\nA4 - the forensic record must outlive the process that draws it")
# =============================================================================

from core import forensics  # noqa: E402

D = tempfile.mkdtemp(prefix="im-forensics-")
os.environ["IM_LOG_DIR"] = D
check("persistence is on by default (it is the record, not a feature)", forensics.enabled())
check("every kind of record has somewhere to go",
      set(forensics.KINDS) == {"traces", "incidents", "investigations", "events"})
forensics.append("incidents", {"id": "INC-1", "severity": "high"})
forensics.append("incidents", {"id": "INC-1", "severity": "critical"})      # the same incident, grown
forensics.append("incidents", {"id": "INC-2", "severity": "low"})
loaded = forensics.load("incidents")
check("an updated record replays as its LATEST state, not duplicated",
      len(loaded) == 2 and [i["severity"] for i in loaded] == ["critical", "low"], str(loaded))
check("but the history is still on disk - append-only, nothing overwritten",
      sum(1 for _ in io.open(forensics.path_for("incidents"))) == 3)
with open(forensics.path_for("incidents"), "a") as fh:
    fh.write('{"id": "INC-3", "sev')                                        # a kill -9 mid-write
check("a truncated last line costs that line and nothing else", len(forensics.load("incidents")) == 2)
forensics.clear("incidents")
check("clearing sets the record ASIDE, it does not destroy it",
      forensics.load("incidents") == [] and any(f.startswith("incidents.jsonl.cleared-") for f in os.listdir(D)),
      str(sorted(os.listdir(D))))
os.environ["IM_FORENSICS"] = "0"
check("it can be turned off for a demo", not forensics.enabled() and forensics.append("events", {"x": 1}) is False)
os.environ["IM_FORENSICS"] = "1"
os.environ["IM_LOG_DIR"] = "/proc/nonexistent-forensics"
check("an unwritable directory degrades to in-memory instead of raising",
      forensics.append("events", {"x": 1}) is False)
os.environ["IM_LOG_DIR"] = D

# The real thing: fill a dashboard, kill it, start a new one, demand the record back.
REPLAY = r'''
import json, os, sys
os.environ["IM_LOG_DIR"] = %r
sys.path.insert(0, %r)
from dashboard import app as d
c = d.app.test_client()
c.post("/api/reset")
for tx, v in (("tx-1", "PASS"), ("tx-2", "DROP"), ("tx-3", "PASS")):
    c.post("/api/security-event", json={"tx_id": tx, "direction": "scada_to_plc", "verdict": v,
                                        "reason": "x", "latency_ms": 1.0, "command": "P101 -> 72.0"})
c.post("/api/trace", json={"tx_id": "tx-1", "hops": [{"hop": "arrival", "values": {"register": "P101"}}]})
c.post("/api/incident", json={"id": "INC-9", "timeline": [{"type": "Forged"}], "source": "127.0.0.2",
                              "severity": "high", "events": 2, "quarantined": False, "summary": "s", "types": []})
c.post("/api/investigation", json={"incident_id": "INC-9", "headline": "a finding"})
c.post("/api/delivery", json={"tx_id": "tx-1", "delivered": False, "reason": "PLC_UNREACHABLE: test"})
dd = c.get("/api/dashboard").get_json()
print(json.dumps({"events": [(e["tx_id"], e["verdict"]) for e in dd["scada_to_plc"]], "overview": dd["overview"]}))
'''
RECOVER = r'''
import json, os, sys
os.environ["IM_LOG_DIR"] = %r
sys.path.insert(0, %r)
from dashboard import app as d
c = d.app.test_client()
dd = c.get("/api/dashboard").get_json()
print(json.dumps({"events": [(e["tx_id"], e["verdict"]) for e in dd["scada_to_plc"]], "overview": dd["overview"],
                  "traces": len(c.get("/api/traces").get_json()), "incidents": len(c.get("/api/incidents").get_json()),
                  "investigations": len(c.get("/api/investigations").get_json())}))
'''
DD = tempfile.mkdtemp(prefix="im-restart-")
envd = dict(os.environ, PYTHONPATH=ROOT)


def run(code: str) -> dict:
    r = subprocess.run([sys.executable, "-c", code % (DD, ROOT)], cwd=ROOT, env=envd,
                       capture_output=True, text=True, timeout=180)
    for line in reversed(r.stdout.splitlines()):
        if line.startswith("{"):
            return json.loads(line)
    raise AssertionError(r.stdout[-400:] + r.stderr[-400:])


before = run(REPLAY)
after = run(RECOVER)                        # a SEPARATE process: the first one is gone
check("the event feed survives the dashboard process dying", after["events"] == before["events"],
      f"{before['events']} -> {after['events']}")
check("so do the counters", after["overview"] == before["overview"], f"{before['overview']} -> {after['overview']}")
check("THE UNDELIVERED CORRECTION SURVIVES TOO (it is not re-read as the original PASS)",
      ("TX-001", "UNDELIVERED") in [tuple(e) for e in after["events"]], str(after["events"]))
check("the packet trace survives", after["traces"] == 1, str(after["traces"]))
check("the incident survives", after["incidents"] == 1, str(after["incidents"]))
check("the investigation survives", after["investigations"] == 1, str(after["investigations"]))
check("the record is plain JSONL an operator can read with grep",
      os.path.exists(os.path.join(DD, "events.jsonl")) and
      json.loads(io.open(os.path.join(DD, "events.jsonl")).readline())["tx_id"].startswith("TX-"))

# =============================================================================
print("\n#11 - source code must not live in a folder called docs/, and experiments must not sit next to the live model")
# =============================================================================

for mod in ("interfaces", "hmac_auth", "attack_log", "netconfig", "forensics"):
    check(f"core/{mod}.py is source and lives in core/", os.path.exists(os.path.join(ROOT, "core", f"{mod}.py")))
    check(f"...and no longer in docs/", not os.path.exists(os.path.join(ROOT, "docs", f"{mod}.py")))
check("docs/ holds documentation only - no .py left at all",
      not [f for f in os.listdir(os.path.join(ROOT, "docs")) if f.endswith(".py")],
      str([f for f in os.listdir(os.path.join(ROOT, "docs")) if f.endswith(".py")]))
check("docs/ is no longer an importable package", not os.path.exists(os.path.join(ROOT, "docs", "__init__.py")))

tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True).stdout.split()
stale = []
for rel in tracked:
    if not rel.endswith(".py") or rel.startswith("final-results/before-review/"):
        continue
    if rel == "tests/test_quarter_fixes.py":
        continue                      # this file contains the patterns it is searching for
    t = io.open(os.path.join(ROOT, rel), encoding="utf-8").read()
    if "from docs import" in t or "from docs." in t or "import docs." in t:
        stale.append(rel)
check("NOTHING still imports from docs", not stale, str(stale))

for mod in ("physical_model_v3", "features_v3", "train_physical_v3", "package_physical_v3",
            "train_fusion_swat", "fusion_scenarios", "train_cyber_swat"):
    check(f"the rejected experiment {mod} lives in research/", os.path.exists(os.path.join(ROOT, "research", f"{mod}.py")))
check("none of them is left in models/ or swat/",
      not [m for m in ("physical_model_v3", "train_physical_v3", "package_physical_v3", "train_fusion_swat",
                       "train_cyber_swat")
           if os.path.exists(os.path.join(ROOT, "models", f"{m}.py"))]
      and not [m for m in ("features_v3", "fusion_scenarios") if os.path.exists(os.path.join(ROOT, "swat", f"{m}.py"))])
check("research/ says what is in it and why it was not promoted",
      "negative result" in io.open(os.path.join(ROOT, "research", "__init__.py")).read())
check("the live model path does NOT import research at module level (v3 is a lazy, opt-in import)",
      "research" not in io.open(os.path.join(ROOT, "models", "physical_model_v2.py")).read().split("def ")[0])
check("the shared live feature code stayed put (train/serve parity beats a tidy label)",
      os.path.exists(os.path.join(ROOT, "swat", "cyber_events.py"))
      and os.path.exists(os.path.join(ROOT, "swat", "physical_features.py"))
      and os.path.exists(os.path.join(ROOT, "swat", "features_v2.py")))

print("\nALL PASS" if fails == 0 else f"\n{fails} CHECK(S) FAILED")
raise SystemExit(1 if fails else 0)
