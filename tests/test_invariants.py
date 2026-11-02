"""
tests/test_invariants.py - the physical-invariant rules: the array helpers, fitting and validation, detection on a plant whose physics is
exactly known, the live monitor (parity with the offline score), the pipeline and upstream-alert hooks, and the fit tool.

    python -m tests.test_invariants

The plant is SYNTHETIC (tests/invariant_plant.py): these checks prove the code does what it says, not how well the rules do on SWaT -
that is measured by `python -m tools.fit_invariants --data-dir <SWaT>` and `python -m benchmark.swat_protocol --data-dir <SWaT>`.
"""

from __future__ import annotations

import json
import os
import tempfile
import time

os.environ.setdefault("IM_LOG_DIR", tempfile.mkdtemp(prefix="im-inv-"))

import numpy as np  # noqa: E402

from core.interfaces import MACHINES, P203, make_command  # noqa: E402
from middleware import cyber_agent, orchestrator, polling  # noqa: E402
from models import invariant_monitor as IM  # noqa: E402
from pipeline.multi_model_pipeline import MultiModelPipeline  # noqa: E402
from swat import invariants as I  # noqa: E402
from swat.physical_features import ACTUATORS, SENSORS  # noqa: E402
from tests.invariant_plant import AI, SI, make_plant  # noqa: E402

fails = 0
orchestrator._forward_decision_to_dashboard = lambda payload: None


def check(name: str, cond: bool, detail: str = "") -> None:
    global fails
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    fails += 0 if cond else 1


# ------------------------------------------------------------------------------------------------------------- helpers
print("ARRAY HELPERS (causal, never across a chunk boundary)")
x = np.arange(10, dtype=float)
ck = np.array([0] * 6 + [1] * 4)
sc = I.since_start(ck)
check("since_start counts samples since the chunk began", sc.tolist() == [0, 1, 2, 3, 4, 5, 0, 1, 2, 3])
lg = I.lag(x, 2, sc)
check("lag gives x[t-2] and NaN where t-2 is before the chunk start", np.isnan(lg[[0, 1, 6, 7]]).all() and lg[[2, 3, 8, 9]].tolist() == [0, 1, 6, 7])
tm = I.trailing_mean(x, 3, sc)
check("trailing mean of 3 needs three samples inside the chunk", np.isnan(tm[[0, 1, 6, 7]]).all() and tm[[2, 5, 8, 9]].tolist() == [1.0, 4.0, 7.0, 8.0])
xn = x.copy()
xn[4] = np.nan
check("a NaN in the window makes the mean unknown (never a made-up value)", np.isnan(I.trailing_mean(xn, 3, sc)[[4, 5]]).all())
a = np.array([1, 1, 1, 0, 0, 1, 1, np.nan, 1, 1], float)
age = I.state_age(a, I.since_start(np.zeros(10, int)))
check("state age restarts at every change and at a NaN reading", age.tolist() == [0, 1, 2, 0, 1, 0, 1, 0, 0, 1])
e = np.array([0, 3, 3, 3, 0, 3, 3, 3, 3], float)
check("persistence keeps only runs of at least p seconds", I.persist_min(e, 3, I.since_start(np.zeros(9, int))).tolist() == [0, 0, 0, 3, 0, 0, 0, 3, 3])
check("missing evidence counts as no violation", I.persist_min(np.array([np.nan, 5.0, 5.0]), 2, I.since_start(np.zeros(3, int))).tolist() == [0, 0, 5.0])

# ------------------------------------------------------------------------------------------------------------- fit + validation
print("\nFITTING ON A PLANT WHOSE PHYSICS IS KNOWN")
S, A, CH = make_plant(60000, 1)
t0 = time.time()
inv = I.InvariantSet.fit(S, A, CH, label="synthetic plant")
ids = {k["id"] for k in inv.invariants}
rep = inv.meta["report"]
check("fitting 60,000 s takes a moment, not minutes", time.time() - t0 < 30, f"{time.time() - t0:.1f} s")
check("the mass balance of the tank is found, and explains it", "balance:LIT101" in ids and next(k for k in inv.invariants if k["id"] == "balance:LIT101")["fit"]["r2"] > 0.99)
check("the pump -> flow coupling is found for both states", {"state:P101=on:FIT201", "state:P101=off:FIT201"} <= ids)
check("no relation is invented for independent signals (no balance for the other tanks)", not (ids & {"balance:LIT301", "balance:LIT401"}))
check("an actuator nothing depends on gets no band", not any(k["id"].startswith("state:P203") for k in inv.invariants))
check("the tank balance does not list a driver that never varied", "frac:MV302" not in next(k for k in inv.invariants if k["id"] == "balance:LIT101")["drivers"])
flats = {k["sensor"] for k in inv.invariants if k["family"] == "flat"}
check("every noisy sensor gets a flatline rule (a real sensor cannot go perfectly flat)", {"LIT101", "LIT301", "LIT401", "PIT501", "AIT402", "DPIT301"} <= flats, str(sorted(flats)))
S_q, A_q, CH_q = make_plant(60000, 1)
S_q[:, SI["AIT202"]] = np.round(S_q[:, SI["AIT202"]] / 0.1) * 0.1            # quantised coarser than its noise: a flat reading is NORMAL for this sensor
inv_q = I.InvariantSet.fit(S_q, A_q, CH_q, label="quantised")
check("a sensor that is legitimately flat in normal data gets NO flatline rule (it would false-alarm)", not any(k["family"] == "flat" and k["sensor"] == "AIT202" for k in inv_q.invariants))
check("every kept invariant has a plain-language meaning and a stage", all(k["text"] and k["stage"] for k in inv.invariants))
check("the report records what was proposed, kept and held out", rep["rows_holdout"] == 15000 and sum(rep["kept"].values()) == len(inv) and "holdout" in rep)

S2, A2, CH2 = make_plant(40000, 2)
V, arg = inv.score(S2, A2, CH2)
check("a fresh healthy run is (almost) silent at theta 1", (V > 1.0).mean() < 1e-3, f"{(V > 1.0).mean():.2e} of seconds")
check("...and completely silent at theta 1.5", (V > 1.5).sum() == 0, f"max {V.max():.2f}")


def attack(fn, t0=20000):
    S3, A3 = S2.copy(), A2.copy()
    fn(S3, A3, t0)
    V3, a3 = inv.score(S3, A3, CH2)
    hit = np.flatnonzero(V3[t0:] > 1.0)
    return (int(hit[0]) if hit.size else None), (inv.invariants[int(a3[t0 + hit[0]])]["id"] if hit.size else None), int((V3[:t0] > 1.5).sum())


def a_flow0(S, A, t):
    S[t:, SI["FIT201"]] = 0.0


def a_freeze(S, A, t):
    S[t:, SI["LIT101"]] = S[t, SI["LIT101"]]


def a_step(S, A, t):
    S[t:, SI["LIT101"]] += 200.0


def a_bias(S, A, t):
    S[t:, SI["FIT101"]] += 0.8


def a_flip(S, A, t):
    A[t:, AI["P101"]] = 1 - A[t:, AI["P101"]]


def a_ramp(S, A, t):
    S[t:, SI["LIT101"]] += np.arange(len(S) - t) * 0.5


for name, fn, family, limit in [("a flow meter stuck at zero while the pump runs", a_flow0, "state", 30), ("a level sensor frozen", a_freeze, "flat", 40),
                                ("a level sensor jumping by 200 mm", a_step, "rate", 5), ("a flow meter reading 0.8 too high", a_bias, None, 30),
                                ("a pump state reported opposite to what the flow shows", a_flip, None, 120), ("a level sensor creeping 0.5 mm/s", a_ramp, "balance", 120)]:
    first, which, noise = attack(fn)
    check(f"detected: {name}", first is not None and first <= limit and (family is None or which.startswith(family)), f"after {first} s by {which}")
check("nothing fires before the attack starts", attack(a_step)[2] == 0)
first_fz, which_fz, _ = attack(a_freeze)
check("a frozen sensor is caught by the flatline rule within about the window plus persistence (20 s + 5 s)", which_fz.startswith("flat:LIT101") and first_fz <= 30, f"{first_fz} s by {which_fz}")
def a_freeze_other(S, A, t):
    S[t:, SI["AIT202"]] = S[t, SI["AIT202"]]
check("a frozen pH sensor is caught too", attack(a_freeze_other)[0] is not None and attack(a_freeze_other)[0] <= 30, str(attack(a_freeze_other)[:2]))

print("\nVALIDATION DROPS WHAT DOES NOT HOLD")
S3, A3, CH3 = make_plant(60000, 5)
S4, A4, _ = make_plant(60000, 6)
cut = 45000
S3[cut:, SI["FIT201"]] *= 0.55                               # in the last quarter the outflow no longer matches the tank (a drifting relation)
inv_d = I.InvariantSet.fit(S3, A3, CH3, label="drifting")
dropped = {d["id"]: d["reason"] for d in inv_d.meta["report"]["dropped"]}
check("a relation that stops holding on the held-out quarter is dropped, with the reason", "balance:LIT101" in dropped and "misfires" in dropped["balance:LIT101"], str(dropped.get("balance:LIT101")))
check("...and so is the pump-on flow band", any(k.startswith("state:P101=on") for k in dropped))
raised = False
try:
    I.InvariantSet.fit(S[:3000], A[:3000], CH[:3000])
except ValueError:
    raised = True
check("too little normal data is refused, not fitted", raised)

print("\nCHUNKS AND NaN")
joined_S = np.vstack([S2[:3000], S2[3000:6000] + np.array([300.0 if i == SI["LIT101"] else 0.0 for i in range(len(SENSORS))])])
joined_A = np.vstack([A2[:3000], A2[3000:6000]])
V_same, _ = inv.score(joined_S, joined_A, np.zeros(6000, int))
V_gap, _ = inv.score(joined_S, joined_A, np.r_[np.zeros(3000, int), np.ones(3000, int)])
check("a jump ACROSS a telemetry gap is not a rate violation (the gap starts a new chunk)", (V_gap[2990:3012] > 1.0).sum() == 0 and (V_same[2990:3012] > 1.0).sum() > 0)
Sn = S2[:5000].copy()
Sn[1000:1100, SI["FIT201"]] = np.nan
Vn, _ = inv.score(Sn, A2[:5000], np.zeros(5000, int))
check("missing readings raise no error and no violation", np.isfinite(Vn).all() and (Vn[1000:1100] <= 1.0).all())

print("\nSAVING AND LOADING")
d = tempfile.mkdtemp(prefix="inv-save-")
inv.meta["theta"] = 1.25
inv.save(os.path.join(d, "inv.json"))
back = I.InvariantSet.load(os.path.join(d, "inv.json"))
V_back, _ = back.score(S2[:8000], A2[:8000], CH2[:8000])
check("a saved set scores exactly like the original", np.allclose(V_back, inv.score(S2[:8000], A2[:8000], CH2[:8000])[0]) and back.theta == 1.25)
blob = json.load(open(os.path.join(d, "inv.json")))


def _raises(fn) -> bool:
    try:
        fn()
    except Exception:
        return True
    return False


check("a file with a different schema is refused", _raises(lambda: I.InvariantSet.from_json(dict(blob, schema="other"))))
check("a file fitted on a different signal set is refused", _raises(lambda: I.InvariantSet.from_json(dict(blob, signals={"sensors": ["X"], "actuators": []}))))

# ------------------------------------------------------------------------------------------------------------- the live monitor
print("\nLIVE MONITOR (same arrays, same score as offline)")
inv.meta["theta"] = 1.0


def regs(S_, A_, t):
    r = {SENSORS[i]: float(S_[t, i]) for i in range(len(SENSORS))}
    r.update({ACTUATORS[j]: 100.0 * float(A_[t, j]) for j in range(len(ACTUATORS))})
    return r


Sa, Aa = S2[:6000].copy(), A2[:6000].copy()
a_step(Sa, Aa, 3000)
a_flow0(Sa, Aa, 4500)
mon = IM.InvariantMonitor(inv, 1.0, "test")
check("before any data the monitor is warming up and flags nothing", mon.assess()["status"] == "WARMING_UP" and not mon.assess()["threat_flag"])
Voff, _ = inv.score(Sa, Aa, np.zeros(6000, int))
mismatch, flagged, first_ok = 0, 0, None
for t in range(6000):
    mon.update(regs(Sa, Aa, t), timestamp=1000.0 + t)
    rep_m = mon.assess()
    if t == inv.lookback - 2:
        check("one second before the buffer is full it is still warming up", rep_m["status"] == "WARMING_UP")
    if rep_m["status"] != "OK":
        continue
    first_ok = first_ok if first_ok is not None else t
    if rep_m["threat_flag"]:
        last_flag_rep = rep_m
    off_flag = Voff[t] > 1.0
    flagged += int(rep_m["threat_flag"])
    if off_flag != rep_m["threat_flag"] or (off_flag and abs(rep_m["score"] - round(float(Voff[t]), 3)) > 1e-6):
        mismatch += 1
check("the monitor agrees with the offline score on every second after warm-up", mismatch == 0 and flagged > 0, f"{mismatch} mismatches, {flagged} flagged seconds, ready at t={first_ok}")
rep_m = last_flag_rep
check("a flag names its invariants, stage and a sentence", rep_m["threat_flag"] and rep_m["flagged_by"][0].startswith("invariant:") and rep_m["suspect_stage"] and rep_m["explanation"].startswith("physical invariant violated"), rep_m["flagged_by"][0])
mon2 = IM.InvariantMonitor(inv, 1.0)
for t in range(0, 3000):                                              # a 5 Hz feed is decimated to 1 Hz
    for k in range(5):
        mon2.update(regs(S2, A2, t), timestamp=2000.0 + t + 0.2 * k)
check("a 5 Hz feed is decimated to 1 Hz (same readiness as a 1 Hz feed)", mon2.assess()["status"] == "OK" and mon2.assess()["warmup_remaining_s"] == 0)
mon2.update(regs(S2, A2, 3001), timestamp=2000.0 + 3001 + 60.0)      # a hole in telemetry restarts the window, as it does for the model
check("a telemetry gap restarts the window", mon2.assess()["status"] == "WARMING_UP")
mon_none = IM.InvariantMonitor(None)
mon_none.update(regs(S2, A2, 0), timestamp=1.0)
check("with no invariants the monitor reports NO_MODEL and never flags", mon_none.assess()["status"] == "NO_MODEL" and not mon_none.assess()["threat_flag"])
mon3 = IM.InvariantMonitor(inv)
mon3.update({"LIT101": 1.0}, timestamp=1.0)
check("an incomplete telemetry sample is ignored, not guessed", mon3.assess()["status"] == "WARMING_UP")

print("\nMERGING INTO THE PHYSICAL ADVISORY")
merged_src = mon
base = {"model": "PhysicalModelV2", "status": "OK", "plant_state": "NORMAL", "threat_flag": False, "flagged_by": [], "suspect_stage": None}
merged = IM.InvariantMonitor(inv); merged._report = dict(last_flag_rep); merged = merged.merge_into(base)
check("an invariant flag turns the advisory into a flag and keeps the model's own fields", merged["threat_flag"] and merged["plant_state"] == "ALERT" and merged["model"] == "PhysicalModelV2"
      and merged["flagged_by"][0].startswith("invariant:") and merged["invariants"]["threat_flag"])
_m = IM.InvariantMonitor(inv)
_m._report = dict(last_flag_rep)
both = _m.merge_into(dict(base, threat_flag=True, flagged_by=["classifier"], suspect_stage="S3"))
check("when the model flagged too, both sources are named and the model's stage wins", both["flagged_by"][0] == "classifier" and both["flagged_by"][1].startswith("invariant:") and both["suspect_stage"] == "S3")
quiet = IM.InvariantMonitor(inv)
check("a quiet monitor leaves the advisory unflagged (and attaches its status)", quiet.merge_into(base)["threat_flag"] is False and "invariants" in quiet.merge_into(base))
check("merging never raises, whatever it is given (the input comes back unchanged)", IM.InvariantMonitor(inv).merge_into(None) is None)

print("\nSWITCHING IT ON")
old_env = {k: os.environ.get(k) for k in ("IM_INVARIANTS", "IM_INVARIANTS_FILE", "IM_INVARIANT_THETA")}
for k in old_env:
    os.environ.pop(k, None)
check("off by default", IM.load_monitor() is None)
os.environ["IM_INVARIANTS"] = "1"
os.environ["IM_INVARIANTS_FILE"] = os.path.join(d, "missing.json")
check("on but no file: disabled with a warning, no crash", IM.load_monitor() is None)
open(os.path.join(d, "bad.json"), "w").write("{not json")
os.environ["IM_INVARIANTS_FILE"] = os.path.join(d, "bad.json")
check("on but a corrupt file: disabled, no crash", IM.load_monitor() is None)
os.environ["IM_INVARIANTS_FILE"] = os.path.join(d, "inv.json")                     # saved above with theta 1.25
m = IM.load_monitor()
check("on with a good file: a monitor that uses the file's calibrated theta", m is not None and m.theta == 1.25 and len(m.inv) == len(inv))
os.environ["IM_INVARIANT_THETA"] = "2.0"
check("IM_INVARIANT_THETA overrides it", IM.load_monitor().theta == 2.0)
os.environ["IM_INVARIANT_THETA"] = "abc"
check("a nonsense override is ignored", IM.load_monitor().theta == 1.25)
for k, v in old_env.items():
    if v is None:
        os.environ.pop(k, None)
    else:
        os.environ[k] = v

# ------------------------------------------------------------------------------------------------------------- pipeline + upstream
print("\nPIPELINE AND UPSTREAM ALERT")
from core import hmac_auth  # noqa: E402


def signed(reg: int, value: float, tx: str):
    p = hmac_auth.parse_frame(hmac_auth.build_frame(reg, value))
    return make_command(tx, time.time(), "127.0.0.1", 16, reg, p["raw_value"] / 10.0, raw_value=p["raw_value"], auth=p["auth"])


def plant_state(over=None):
    regs_ = {m["register"]: m["initial"] for m in MACHINES}
    regs_.update(over or {})
    return {"registers": regs_, "setpoints": dict(regs_), "timestamp": time.time() - 10}


mon_p = IM.InvariantMonitor(inv, 1.0, "test")
pipe = MultiModelPipeline(invariants=mon_p)
pipe_off = MultiModelPipeline()
check("the pipeline has no monitor unless one is given or enabled", pipe_off.invariants is None)
for t in range(len(Sa) - 1500):
    pipe.ingest_telemetry(regs(Sa, Aa, t), timestamp=5000.0 + t)               # ends inside the +200 mm step
healthy_t = 2900                                                               # before the step
mon_h = IM.InvariantMonitor(inv, 1.0)
pipe_h = MultiModelPipeline(invariants=mon_h)
for t in range(healthy_t):
    pipe_h.ingest_telemetry(regs(Sa, Aa, t), timestamp=7000.0 + t)
cyber_agent.reset_state()
rep_h = pipe_h.process_command(signed(P203, 60.0, "ok"), plant_state())
check("healthy plant: a legitimate command is not made an ALERT by the invariants", rep_h["decision"]["verdict"] in ("PASS", "ALERT") and "invariant:" not in rep_h["decision"]["reason"], rep_h["decision"]["reason"])
for t in range(healthy_t, 3005):                                         # the +200 mm step is at t=3000: its 10 s rate violation is still open
    pipe_h.ingest_telemetry(regs(Sa, Aa, t), timestamp=7000.0 + t)
cyber_agent.reset_state()
rep_a = pipe_h.process_command(signed(P203, 60.0, "attack-window"), plant_state())
check("sensor jump: the same legitimate command is FORWARDED as an ALERT naming the invariant", rep_a["decision"]["verdict"] == "ALERT" and "invariant:rate:LIT101" in rep_a["decision"]["reason"], rep_a["decision"]["reason"])
check("the report carries the invariant detail and the health report merges it", rep_a["physical"]["model"]["invariants"]["threat_flag"] and pipe_h.health_report()["invariants"]["status"] == "OK")
tr = pipe_h._recent_traces.get("attack-window") or {}
phys_hop = next((h for h in tr.get("hops", []) if h["hop"] == "physical_model"), {})
check("the packet trace shows what the invariants saw", bool((phys_hop.get("values", {}).get("invariants") or {}).get("violated")), str(phys_hop.get("values", {}).get("invariants")))
cyber_agent.reset_state()
bad_rule = pipe_h.process_command(signed(P203, 85.0, "x"), plant_state({P203: 75.0, 1: 15.0}))
check("rules still outrank the advisory: a rule violation is a DROP even while an invariant is violated", bad_rule["decision"]["verdict"] == "DROP")

sent = []
orchestrator._forward_decision_to_dashboard = lambda payload: sent.append(payload)
polling._last_invariant_alert.clear()
now = time.time()
polling._check_upstream_invariants(pipe_h, now)
check("upstream: a violated invariant raises one ALERT even with no command flowing", len(sent) == 1 and sent[0]["verdict"] == "ALERT" and "invariant:" in sent[0]["reason"], str(sent[:1]))
polling._check_upstream_invariants(pipe_h, now + 1)
check("...and is rate-limited per invariant", len(sent) == 1)
polling._check_upstream_invariants(pipe_off, now)
check("no monitor configured: nothing is raised", len(sent) == 1)
polling._check_upstream_invariants(pipe, now)
check("a quiet plant (the sensor offset is steady, not changing): nothing is raised", len(sent) == 1, f"V={pipe.invariants.assess()['score']}")
orchestrator._forward_decision_to_dashboard = lambda payload: None

# ------------------------------------------------------------------------------------------------------------- the fit tool
print("\nFIT TOOL (twin and fixture archive)")
from tools import fit_invariants as FT  # noqa: E402

out = tempfile.mkdtemp(prefix="inv-tool-")
res = FT.fit_twin(2.0, 3, os.path.join(out, "t.json"), os.path.join(out, "t_eval.json"), os.path.join(out, "t.md"))
loaded = I.InvariantSet.load(os.path.join(out, "t.json"))
check("the twin fit writes a loadable file with a calibrated theta, a report and a measurement", len(loaded) > 0 and loaded.theta >= 1.0 and os.path.getsize(os.path.join(out, "t.md")) > 1000)
check("the twin report is labelled as a twin measurement, not SWaT performance", "NOT SWaT detection performance" in open(os.path.join(out, "t.md")).read())
check("the calibrated theta is on the ladder", res["nominal"]["calibrated_theta"] in (1.0, 1.25, 1.5, 2.0, 3.0))
check("every synthetic twin attack is reported with its first violation or None", set(res["scenarios"]) and all("first_violation_after_s" in s for s in res["scenarios"].values()))
from tests.swat_fixture import make_swat_archive  # noqa: E402

fx = tempfile.mkdtemp(prefix="inv-fix-")
make_swat_archive(fx, seed=0)
sw = FT.fit_swat(fx, os.path.join(out, "s.json"), os.path.join(out, "s_eval.json"), os.path.join(out, "s.md"))
ev = sw["evaluation"]
check("the SWaT-mode fit scores every attack segment out of sample and every theta", ev["per_theta"]["1.0"]["segments_total"] == 35 and len(ev["per_attack"]) == 35 and set(ev["per_theta"]) == {"1.0", "1.5", "2.0", "3.0"})
check("a higher theta never fires more often", all(ev["per_theta"][a]["alarm_episodes"] >= ev["per_theta"][b]["alarm_episodes"] for a, b in (("1.0", "1.5"), ("1.5", "2.0"), ("2.0", "3.0"))))
check("no weights were written", not [n for n in os.listdir(os.path.join(FT.ROOT, "models", "weights")) if "invariant" in n])
check("the repo's real invariant files were not touched by these runs", not os.path.exists(FT.SWAT_SET) or os.path.getmtime(FT.SWAT_SET) < time.time() - 5)

print("\nALL PASS" if fails == 0 else f"\n{fails} CHECK(S) FAILED")
raise SystemExit(1 if fails else 0)
