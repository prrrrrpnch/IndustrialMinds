"""
tests/test_response_layer.py - policy-as-code authorization, auto-quarantine, incident correlation, and their wiring into the real
pipeline and dashboard. Everything is rule-based and deterministic; no model weights are needed.

    python -m tests.test_response_layer
"""

from __future__ import annotations

import json
import os
import tempfile
import time

from docs import hmac_auth
from docs.interfaces import MACHINE_BY_NAME, MACHINES, make_command
from docs.netconfig import LOOPBACK
from middleware import cyber_agent, incidents, policy, quarantine
from pipeline.multi_model_pipeline import MultiModelPipeline

fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global fails
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    fails += 0 if cond else 1


SRC_A, SRC_B, SRC_C = LOOPBACK, "127.0.0.2", "127.0.0.3"            # loopback-range addresses only
import ipaddress  # noqa: E402
cyber_agent._TRUSTED_NETWORKS[:] = [ipaddress.ip_network("127.0.0.0/8")]
REG = {t: m["register"] for t, m in MACHINE_BY_NAME.items()}


def signed(tx: str, ts: float, src: str, reg: int, value: float, fc: int = 16, key=None):
    p = hmac_auth.parse_frame(hmac_auth.build_frame(reg, value, key=key, timestamp_ms=int(ts * 1000)))
    return make_command(tx, ts, src, fc, reg, value, raw_value=p["raw_value"], auth=p["auth"])


def fresh() -> None:
    cyber_agent.reset_state()
    quarantine.reset()
    incidents.reset()
    policy.reset()


def set_env(**kw) -> None:
    for k, v in kw.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


tmp = tempfile.mkdtemp(prefix="im-policy-")
POLICY = os.path.join(tmp, "policy.json")


def write_policy(doc) -> None:
    with open(POLICY, "w") as fh:
        fh.write(doc if isinstance(doc, str) else json.dumps(doc))
    os.utime(POLICY, (time.time() + write_policy.n, time.time() + write_policy.n))   # distinct mtime so the reload sees it
    write_policy.n += 1
    policy.reset()


write_policy.n = 1
set_env(IM_POLICY_FILE=POLICY, IM_POLICY_RELOAD_S="0", IM_QUARANTINE=None)

print("POLICY: authorization")
fresh()
if os.path.exists(POLICY):
    os.remove(POLICY)
t = time.time()
check("no policy file -> unchanged behaviour: an authenticated write passes", cyber_agent.check(signed("p0", t, SRC_A, REG["P101"], 70.0))["pass"])
write_policy({"default_role": "deny",
              "roles": {"operator": {"write": ["P101", "MV101"], "limits": {"P101": [20, 90]}},
                        "engineer": {"write": "*"}, "observer": {"write": []}},
              "sources": {SRC_A: "operator", SRC_B: "engineer", SRC_C: "observer"}})
fresh()
write_policy({"default_role": "deny",
              "roles": {"operator": {"write": ["P101", "MV101"], "limits": {"P101": [20, 90]}},
                        "engineer": {"write": "*"}, "observer": {"write": []}},
              "sources": {SRC_A: "operator", SRC_B: "engineer", SRC_C: "observer"}})
t = time.time()
v = cyber_agent.check(signed("p1", t, SRC_A, REG["P101"], 70.0))
check("operator may write a listed register inside its limits", v["pass"], v["reason"])
v = cyber_agent.check(signed("p2", t + 0.3, SRC_A, REG["P203"], 60.0))
check("operator writing an unlisted register -> UNAUTHORIZED_REGISTER", not v["pass"] and v["reason"].startswith("UNAUTHORIZED_REGISTER"), v["reason"])
v = cyber_agent.check(signed("p3", t + 0.6, SRC_A, REG["P101"], 95.0))
check("operator writing outside its tighter limit -> UNAUTHORIZED_VALUE", not v["pass"] and v["reason"].startswith("UNAUTHORIZED_VALUE"), v["reason"])
v = cyber_agent.check(signed("p4", t + 0.9, SRC_B, REG["P203"], 60.0))
check("engineer ('*') may write any actuator", v["pass"], v["reason"])
v = cyber_agent.check(signed("p5", t + 1.2, SRC_C, REG["P101"], 70.0))
check("observer (no writes) is refused", not v["pass"] and v["reason"].startswith("UNAUTHORIZED_REGISTER"), v["reason"])
v = cyber_agent.check(signed("p6", t + 1.5, SRC_C, REG["P101"], 70.0, fc=3))
check("a READ (function code 3) is never restricted by policy", v["pass"], v["reason"])
cyber_agent._TRUSTED_NETWORKS[:] = [ipaddress.ip_network("127.0.0.0/8")]
v = cyber_agent.check(signed("p7", t + 1.8, "127.0.0.9", REG["P101"], 70.0))
check("an unlisted source falls to default_role deny -> UNAUTHORIZED_SOURCE", not v["pass"] and v["reason"].startswith("UNAUTHORIZED_SOURCE"), v["reason"])
v = cyber_agent.check(signed("p8", t + 2.1, SRC_A, REG["P203"], 60.0, key=b"x" * 32))
check("authentication still comes first: a forged tag from an allowed source is HMAC_INVALID, not a policy result",
      not v["pass"] and v["reason"].startswith("HMAC_INVALID"), v["reason"])

print("\nPOLICY: robustness")
write_policy('{"roles": {"op": {"write": ["NOPE"]}}}')
fresh()
write_policy('{"roles": {"op": {"write": ["NOPE"]}}}')
v = cyber_agent.check(signed("e1", time.time(), SRC_A, REG["P101"], 70.0))
check("a malformed policy FAILS CLOSED for writes (POLICY_ERROR)", not v["pass"] and v["reason"].startswith("POLICY_ERROR"), v["reason"])
v = cyber_agent.check(signed("e2", time.time() + 0.3, SRC_A, REG["P101"], 70.0, fc=3))
check("...but reads still work under a broken policy", v["pass"], v["reason"])
write_policy("{ not json")
v = cyber_agent.check(signed("e3", time.time() + 0.6, SRC_A, REG["P101"], 71.0))
check("unparseable JSON also fails closed", not v["pass"] and v["reason"].startswith("POLICY_ERROR"), v["reason"])
write_policy({"roles": {"op": {"write": "*"}}, "sources": {SRC_A: "ghost"}})
check("a source mapped to an undefined role is rejected at load", policy.status()["error"] is not None and "undefined role" in policy.status()["error"])
write_policy({"roles": {"op": {"write": ["P101"]}}, "sources": {SRC_A: "op"}, "default_role": "allow"})
fresh()
write_policy({"roles": {"op": {"write": ["P101"]}}, "sources": {SRC_A: "op"}, "default_role": "allow"})
check("the corrected file is picked up on reload (no restart)", policy.status()["active"] and policy.status()["error"] is None)
v = cyber_agent.check(signed("e4", time.time(), SRC_B, REG["P203"], 60.0))
check("default_role allow leaves unlisted sources unrestricted", v["pass"], v["reason"])
check("register numbers are accepted as well as tags", policy.parse({"roles": {"r": {"write": [1, "P203"]}}})["roles"]["r"]["write"] == {1, REG["P203"]})
for bad in ({"roles": {"r": {"write": [True]}}}, {"roles": {"r": {"write": [99]}}}, {"roles": {"r": {"write": ["P101"], "limits": {"P101": [50, 10]}}}},
            {"default_role": "nobody"}, []):
    try:
        policy.parse(bad)
        ok = False
    except ValueError:
        ok = True
    check(f"parse rejects {json.dumps(bad)[:60]}", ok)

print("\nQUARANTINE")
fresh()
set_env(IM_POLICY_FILE=os.path.join(tmp, "absent.json"), IM_QUARANTINE=None)
check("off by default: quarantine never triggers", quarantine.record("s", "HMAC_INVALID") is None and not quarantine.is_quarantined("s")[0])
set_env(IM_QUARANTINE="force", IM_QUARANTINE_LIMIT="12", IM_QUARANTINE_WINDOW_S="30", IM_QUARANTINE_HOLD_S="60", IM_QUARANTINE_MAX_S="200")
quarantine.reset()
n = 1000.0
check("one forged command is only a strike", quarantine.record("s", "HMAC_INVALID:x", n) is None and not quarantine.is_quarantined("s", n)[0])
started = quarantine.record("s", "HMAC_INVALID:x", n + 1)
check("two forged commands (6+6 >= 12) quarantine the source", started is not None and started["hold_s"] == 60 and started["offence"] == 1, str(started))
held, rem = quarantine.is_quarantined("s", n + 2)
check("while held, the source is quarantined with time remaining", held and 50 < rem <= 60, f"{rem:.1f}s")
check("commands refused because of the quarantine add no strikes", quarantine.record("s", "SOURCE_QUARANTINED:5s", n + 3) is None)
check("it lifts by itself after the hold", not quarantine.is_quarantined("s", n + 62)[0])
quarantine.record("s", "HMAC_INVALID", n + 70)
second = quarantine.record("s", "HMAC_INVALID", n + 71)
check("a repeat offender is held twice as long (doubling)", second is not None and second["hold_s"] == 120 and second["offence"] == 2, str(second))
quarantine.release("s")
quarantine.record("s", "HMAC_INVALID", n + 300)
third = quarantine.record("s", "HMAC_INVALID", n + 301)
check("the hold is capped (IM_QUARANTINE_MAX_S)", third is not None and third["hold_s"] == 200, str(third))
quarantine.reset()
for i in range(11):
    quarantine.record("slow", "RATE_LIMIT_EXCEEDED", n + i * 4)         # 1 point each, 4 s apart: never 12 inside 30 s
check("slow low-severity noise does not quarantine (sliding window)", not quarantine.is_quarantined("slow", n + 50)[0])
quarantine.reset()
check("a flood of rate-limit drops does quarantine", any(quarantine.record("f", "RATE_LIMIT_EXCEEDED", n + i * 0.05) for i in range(14)))
quarantine.reset()
set_env(IM_QUARANTINE_EXEMPT="s")
check("an exempt source is never quarantined", quarantine.record("s", "HMAC_INVALID", n) is None and quarantine.record("s", "HMAC_INVALID", n + 1) is None)
set_env(IM_QUARANTINE_EXEMPT=None)
check("severity weights: forged tag > flood", quarantine.weight_for("HMAC_INVALID:x") > quarantine.weight_for("RATE_LIMIT_EXCEEDED"))
check("a quarantined source's status is listed", quarantine.status()["enabled"])

print("\nQUARANTINE: single-laptop auto-off")
OTHER = str(ipaddress.IPv4Address(0x0A000007))          # a non-loopback address, built at run time (never written as a literal)
saved_ts = os.environ.get("IM_TRUSTED_SOURCES")
for val in ("1", "auto", "on"):
    set_env(IM_QUARANTINE=val, IM_TRUSTED_SOURCES=LOOPBACK)
    quarantine.reset()
    check(f"IM_QUARANTINE={val} on a loopback-only demo is switched off automatically",
          quarantine.mode() == "auto-off-single-laptop" and not quarantine.enabled() and quarantine.single_laptop())
set_env(IM_QUARANTINE="1", IM_TRUSTED_SOURCES=LOOPBACK)
check("...and then no strikes ever quarantine SCADA", all(quarantine.record(LOOPBACK, "HMAC_INVALID", 10.0 + i) is None for i in range(5))
      and not quarantine.is_quarantined(LOOPBACK, 12.0)[0])
check("the status says why", quarantine.status()["mode"] == "auto-off-single-laptop" and quarantine.status()["single_laptop"])
set_env(IM_QUARANTINE="auto", IM_TRUSTED_SOURCES=f"{LOOPBACK},{OTHER}")
check("one non-loopback trusted source (multi-laptop) turns it on", quarantine.mode() == "on" and quarantine.enabled() and not quarantine.single_laptop())
set_env(IM_QUARANTINE="1", IM_TRUSTED_SOURCES=f"{OTHER}/24")
check("a non-loopback CIDR also counts as multi-laptop", quarantine.enabled())
set_env(IM_QUARANTINE="force", IM_TRUSTED_SOURCES=LOOPBACK)
check("IM_QUARANTINE=force overrides the auto-off", quarantine.enabled())
set_env(IM_QUARANTINE=None, IM_TRUSTED_SOURCES=OTHER)
check("not requested -> off even on multi-laptop (opt-in preserved)", quarantine.mode() == "off")
set_env(IM_QUARANTINE="auto", IM_TRUSTED_SOURCES="not-an-address")
check("an unparseable whitelist is not guessed to be single-laptop", not quarantine.single_laptop())
set_env(IM_TRUSTED_SOURCES=saved_ts, IM_QUARANTINE=None)

print("\nQUARANTINE inside the cyber agent")
fresh()
set_env(IM_QUARANTINE="force")
quarantine.record(SRC_B, "HMAC_INVALID")
quarantine.record(SRC_B, "HMAC_INVALID")
v = cyber_agent.check(signed("q1", time.time(), SRC_B, REG["P101"], 70.0))
check("a quarantined source is refused FIRST, with the time left", not v["pass"] and v["reason"].startswith("SOURCE_QUARANTINED"), v["reason"])
v = cyber_agent.check(signed("q2", time.time() + 0.3, SRC_A, REG["P101"], 70.0))
check("other sources are unaffected", v["pass"], v["reason"])
cyber_agent.reset_state()
check("reset_state clears quarantines (between tests)", not quarantine.is_quarantined(SRC_B)[0])
set_env(IM_QUARANTINE=None)

print("\nINCIDENTS")
fresh()
base = 5000.0


def ev(i, src, reg, verdict, reason, dt):
    return incidents.record(make_command(f"t{i}", base + dt, src, 16, REG[reg], 50.0), {"verdict": verdict, "reason": reason})


check("a PASS creates no incident", ev(0, SRC_A, "P101", "PASS", "OK", 0) is None and incidents.list_incidents() == [])
a1 = ev(1, SRC_A, "P101", "DROP", "RATE_LIMIT_EXCEEDED", 1)
a2 = ev(2, SRC_A, "P101", "DROP", "RATE_LIMIT_EXCEEDED", 2)
check("events from one source join ONE incident", a1["id"] == a2["id"] and a2["events"] == 2 and a2["drops"] == 2)
check("a flood alone is medium severity", a2["severity"] == "medium", a2["severity"])
a3 = ev(3, SRC_A, "P203", "DROP", "HMAC_INVALID:tag mismatch", 3)
check("a forged tag raises the incident to high", a3["severity"] == "high" and a3["id"] == a1["id"], a3["severity"])
a4 = ev(4, SRC_A, "P101", "DROP", "REPLAY_DETECTED:nonce reused", 4)
check("three distinct attack types from one source = critical (multi-stage)", a4["severity"] == "critical", a4["severity"])
check("the incident lists the registers touched and the attack types", set(a4["registers"]) == {"P101", "P203"} and len(a4["types"]) == 3, str(a4["types"]))
check("the summary is one readable line", a4["summary"].startswith(SRC_A) and "event(s)" in a4["summary"], a4["summary"])
b1 = ev(5, SRC_B, "P101", "ALERT", "PHYSICAL_MODEL:stack", 3)
check("another source gets its own incident; an advisory alert alone is low", b1["id"] != a1["id"] and b1["severity"] == "low" and b1["alerts"] == 1)
c1 = incidents.record(make_command("t9", base + 100, SRC_A, 16, REG["P101"], 50.0), {"verdict": "DROP", "reason": "RATE_LIMIT_EXCEEDED"})
check("after the gap (30 s) the next event opens a NEW incident", c1["id"] not in (a1["id"], b1["id"]) and c1["events"] == 1)
check("the earlier incident is now closed", next(i for i in incidents.list_incidents() if i["id"] == a1["id"])["status"] == "closed")
q = incidents.record(make_command("t10", base + 101, SRC_A, 16, REG["P101"], 50.0), {"verdict": "DROP", "reason": "HMAC_INVALID"},
                     {"since": 1.0, "until": 61.0, "hold_s": 60.0, "offence": 1, "trigger": "HMAC_INVALID"})
check("a quarantine marks the incident critical and records the hold", q["quarantined"] and q["severity"] == "critical" and q["quarantine"]["hold_s"] == 60.0)
for i in range(120):
    ev(100 + i, SRC_C, "P101", "DROP", "RATE_LIMIT_EXCEEDED", 200 + i * 0.1)
big = next(i for i in incidents.list_incidents() if i["source"] == SRC_C)
check("a long flood stays ONE incident with a capped timeline but an exact count", big["events"] == 120 and len(big["timeline"]) == incidents.MAX_TIMELINE, f"{big['events']} events, {len(big['timeline'])} kept")
check("the public form carries no private fields", all(not k.startswith("_") for k in big))
incidents.reset()
check("reset empties the store", incidents.list_incidents() == [])

print("\nPIPELINE (the real decision path)")
fresh()
set_env(IM_QUARANTINE="force", IM_QUARANTINE_LIMIT="12", IM_QUARANTINE_HOLD_S="60")
regs = {m["register"]: m["initial"] for m in MACHINES}
state = {"registers": regs, "setpoints": dict(regs), "timestamp": time.time() - 10}
pipe = MultiModelPipeline()
t = time.time()
ok = pipe.process_command(signed("l1", t, SRC_A, REG["P101"], 70.0), state)
check("a legitimate command passes and creates no incident", ok["decision"]["verdict"] in ("PASS", "ALERT") and (ok["incident"] is None or ok["decision"]["verdict"] == "ALERT"))
r1 = pipe.process_command(signed("a1", t + 0.3, SRC_B, REG["P101"], 70.0, key=b"y" * 32), state)
check("a forged command is dropped and opens an incident", r1["decision"]["verdict"] == "DROP" and r1["incident"] and r1["incident"]["severity"] == "high", str(r1["incident"]))
r2 = pipe.process_command(signed("a2", t + 0.6, SRC_B, REG["P101"], 70.0, key=b"y" * 32), state)
check("the second forged command triggers the quarantine, visible in the report", r2["incident"]["quarantined"] and r2["incident"]["severity"] == "critical", str(r2["incident"]))
r3 = pipe.process_command(signed("a3", t + 0.9, SRC_B, REG["P101"], 70.0), state)
check("now even a correctly signed command from that source is refused (SOURCE_QUARANTINED)", r3["decision"]["verdict"] == "DROP" and r3["decision"]["reason"].startswith("SOURCE_QUARANTINED"), r3["decision"]["reason"])
cy = [h for h in r3["trace"]["hops"] if h["hop"] == "cyber_rules"][0]["checks"]
check("the packet tracer shows the quarantine check failing and the rest NOT_RUN", [c["check"] for c in cy if c["result"] == "FAIL"] == ["quarantine"]
      and all(c["result"] == "NOT_RUN" for c in cy[cy.index(next(c for c in cy if c["check"] == "quarantine")) + 1:]))
r4 = pipe.process_command(signed("a4", t + 1.2, SRC_A, REG["P101"], 72.0), state)
check("the legitimate source still works while the other is quarantined", r4["decision"]["verdict"] in ("PASS", "ALERT"), r4["decision"]["reason"])
inc = [i for i in incidents.list_incidents() if i["source"] == SRC_B]
check("all of it is ONE incident for that source", len(inc) == 1 and inc[0]["events"] == 3 and inc[0]["quarantined"], str(inc and inc[0]["events"]))
check("the quarantine-blocked attempt is logged as such in the timeline", any(e["type"] == "Blocked While Quarantined" for e in inc[0]["timeline"]))
write_policy({"default_role": "deny", "roles": {"op": {"write": ["P101"]}}, "sources": {SRC_C: "op"}})
set_env(IM_POLICY_FILE=POLICY, IM_QUARANTINE=None)
policy.reset()
r5 = pipe.process_command(signed("z1", time.time() + 5, SRC_C, REG["P203"], 60.0), state)
c_types = [t["type"] for i in incidents.list_incidents() if i["source"] == SRC_C for t in i["types"]]
check("a policy violation is a DROP with an Unauthorized Write incident", r5["decision"]["verdict"] == "DROP" and r5["decision"]["reason"].startswith("UNAUTHORIZED_REGISTER")
      and "Unauthorized Write (Policy)" in c_types, str(c_types))
set_env(IM_POLICY_FILE=os.path.join(tmp, "absent.json"))

print("\nDASHBOARD")
os.environ["IM_LOG_DIR"] = tmp
from dashboard import app as dash  # noqa: E402
c = dash.app.test_client()
payload = incidents.list_incidents()[0]
check("POST /api/incident stores an incident", c.post("/api/incident", json=payload).status_code == 200)
got = c.get("/api/incidents").get_json()
check("GET /api/incidents returns it, newest first, with the quarantine countdown field", got and got[0]["id"] == payload["id"] and "quarantine_remaining_s" in got[0])
check("a bad body is rejected", c.post("/api/incident", json={"id": "x"}).status_code == 400)
check("the page includes the incidents panel and script", b"incident-list" in c.get("/").data and b"incidents.js" in c.get("/").data)
check("the panel script is served", c.get("/static/incidents.js").status_code == 200)

print("\nALL PASS" if fails == 0 else f"\n{fails} CHECK(S) FAILED")
raise SystemExit(1 if fails else 0)
