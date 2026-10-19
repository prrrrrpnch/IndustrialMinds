"""
tests/test_physical_v3_live.py - the v3 LIVE model: live window == trainer probability, warm-up, abstention, explanation fields, the factory
(v2 must stay the default), packaging safety, and integration with the real pipeline. Uses a candidate trained on the synthetic fixture
(code paths only; its numbers mean nothing).

    python -m tests.test_physical_v3_live
"""

from __future__ import annotations

import os
import tempfile
import time

import joblib
import numpy as np

from docs import hmac_auth
from docs.interfaces import MACHINES, make_command
from docs.netconfig import LOOPBACK
from middleware import cyber_agent
from models import package_physical_v3 as P
from models import physical_model_v2 as V2mod
from models import physical_model_v3 as V3mod
from models import train_physical_v3 as T
from models.physical_model_v3 import PhysicalModelV3
from pipeline.multi_model_pipeline import MultiModelPipeline
from swat import features_v3 as F3
from swat.loader import load_stream
from swat.physical_features import ACTUATORS, SENSORS, Norm, actuator_class_series, compute_bounds
from tests.swat_fixture import make_swat_archive

fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global fails
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    fails += 0 if cond else 1


print("SETUP (train a fixture candidate, package it into a temp folder)")
d = tempfile.mkdtemp(prefix="v3live-fix-")
make_swat_archive(d, seed=0)
stream, _ = load_stream(d, SENSORS + ACTUATORS)
res, final, norm_t, _arrays = T.run(stream, seed=1, folds=3, quick=True, budgets=(1.0, 4.0), recipes=["stack_nl"])
out = tempfile.mkdtemp(prefix="v3live-out-")
cand = T.save_candidate(out, res, final, norm_t, True)
budget = next(b for b in ("4.0", "1.0") if res["alarm_rules"][b]["selected_without_persistence"].get("threshold") is not None)
weights = os.path.join(out, "physical_model_v3.joblib")
rc = P.package(cand, weights, budget, os.path.join(out, "physical_v3_report.json"), check_approval=False, allow_fixture=True)
check("packaging a candidate writes a weights file", rc == 0 and os.path.exists(weights))
check("packaging refuses to overwrite an existing weights file", P.package(cand, weights, budget, check_approval=False, allow_fixture=True) == 1)
check("packaging refuses a fixture candidate unless explicitly allowed (the real CLI never allows it)",
      P.package(cand, os.path.join(out, "other.joblib"), budget, check_approval=False) == 1)
check("packaging refuses a budget that has no valid threshold", P.package(cand, os.path.join(out, "other2.joblib"), "99", check_approval=False, allow_fixture=True) == 1)
blob = joblib.load(weights)
check("the weights carry the schema, the recipe, the held-out numbers and the threshold", blob["schema"] == F3.FEATURE_VERSION and blob["recipe"] == "stack_nl"
      and "held_out_test_block" in blob["metadata"] and 0 < blob["clf_threshold"] < 1)

m = PhysicalModelV3.load(weights)
check("the v3 weights load (status OK, 120 s window, stacked recipe)", m.status == "OK" and m.window_size == 120 and m.recipe == "stack_nl" and m._stack is not None)

print("\nLIVE == TRAINER")
X87, XL, X3, AUX, meta = F3.build_windows_v3(stream, norm_t)
chunk = stream["chunk"].to_numpy()
S = stream[SENSORS].to_numpy(dtype=np.float64)
A = np.column_stack([actuator_class_series(stream[a].to_numpy(dtype=np.float64), a.startswith("MV"), chunk) for a in ACTUATORS])
row_of = {float(e): r for r, e in enumerate(stream["epoch"].to_numpy())}
nm_t, heads_t, stk_t = final["normal_models"]["nl"], final["heads"], final["stacker"]


def trainer_probability(k: int) -> float:
    design = T.design_for(X3[k:k + 1], AUX[k:k + 1], nm_t)
    sc = {h: heads_t[h].predict_proba(design[:, T.head_cols(h)])[:, 1] for h in heads_t}
    return float(stk_t.predict(sc)[0])


def feed(model: PhysicalModelV3, end_row: int, t0: float = 5_000_000.0) -> None:
    for r in range(end_row - 119, end_row + 1):
        regs = {t: float(S[r, i]) for i, t in enumerate(SENSORS)}
        regs.update({t: (100.0 if A[r, i] == 1 else 0.0) for i, t in enumerate(ACTUATORS)})
        model.update(regs, timestamp=t0 + r)


picked = [0, len(meta) // 3, len(meta) // 2, len(meta) - 1]
worst = 0.0
for k in picked:
    live = PhysicalModelV3.load(weights)
    feed(live, row_of[float(meta["epoch"].iloc[k])])
    rep = live.assess()
    worst = max(worst, abs(rep["attack_probability"] - round(trainer_probability(k), 4)))
check("a live 120 s window reproduces the TRAINER's probability for the same seconds", worst < 1.1e-4, f"max diff {worst:.1e} over {len(picked)} windows")
check("the batch (scikit-learn) path equals the single-row (packed) path", np.allclose(m.score_batch(X3[:40], AUX[:40], packed=False)[0],
                                                                                     m.score_batch(X3[:40], AUX[:40], packed=True)[0], atol=1e-9))

print("\nLIVE BEHAVIOUR")
lv = PhysicalModelV3.load(weights)
nominal = {t: float(norm_t.mu[i]) for i, t in enumerate(SENSORS)}
nominal.update({t: 100.0 for t in ACTUATORS})
t0 = 6_000_000.0
for i in range(119):
    lv.update(nominal, timestamp=t0 + i)
check("WARMING_UP until the 120 s window is full", lv.assess()["status"] == "WARMING_UP" and not lv.is_warm)
lv.update(nominal, timestamp=t0 + 119)
r1 = lv.assess()
check("full window -> OK with an attack probability, the v3 model name, no anomaly score",
      r1["status"] == "OK" and r1["attack_probability"] is not None and r1["model"] == "PhysicalModelV3" and r1["anomaly_score"] is None)
check("every head reports its score (the per-stage ones explain where)", set(r1["head_scores"]) == set(final["heads"]) and all(0 <= v <= 1 for v in r1["head_scores"].values()))
check("the PCA monitor reports one normalised SPE per stage", set(r1["stage_spe"]) == {f"S{s}" for s in F3.STAGE_IDS})
check("flag logic: flagged iff probability > threshold; no suspect stage when not flagged",
      r1["threat_flag"] == (r1["attack_probability"] > lv.clf_threshold) and (r1["suspect_stage"] is None) == (not r1["threat_flag"]))
os.environ["IM_PHYSICAL_THRESHOLD"] = "0.0"
try:
    forced = PhysicalModelV3.load(weights)
    for i in range(120):
        forced.update(nominal, timestamp=t0 + i)
    rf = forced.assess()
    check("a threshold override takes effect (and is recorded)", rf["threat_flag"] and forced.metadata.get("operating_point_override") == 0.0)
    check("a flag names its flagging component and the most suspicious stage", rf["flagged_by"] == ["stack"] and rf["suspect_stage"] in {f"S{s}" for s in F3.STAGE_IDS}, str(rf["suspect_stage"]))
    check("a flag gives plant_state ALERT", rf["plant_state"] == "ALERT")
finally:
    os.environ.pop("IM_PHYSICAL_THRESHOLD", None)
lv2 = PhysicalModelV3.load(weights)
for i in range(120):
    lv2.update(nominal, timestamp=t0 + i)
lv2.update(dict(nominal, LIT301=float(norm_t.hi[SENSORS.index("LIT301")]) + 5 * float(norm_t.sd[SENSORS.index("LIT301")])), timestamp=t0 + 120)
r2 = lv2.assess()
check("a sensor outside the measured envelope is reported", any(v["tag"] == "LIT301" for v in r2["bounds_violations"]) and r2["plant_state"] == "ALERT")
lv3 = PhysicalModelV3.load(weights)
for j in range(700):                                                   # 5 Hz polling must be decimated to 1 Hz
    lv3.update(nominal, timestamp=t0 + j * 0.2)
check("5 Hz polling is decimated to 1 Hz (window keeps its size)", len(lv3._buf) == 120)
lv3.update(nominal, timestamp=t0 + 5000.0)
check("a telemetry gap > 5 s restarts the window", len(lv3._buf) == 1 and lv3.assess()["status"] == "WARMING_UP")
tt = []
lv4 = PhysicalModelV3.load(weights)
for i in range(130):
    lv4.update(nominal, timestamp=t0 + i)
for i in range(30):
    lv4.update(nominal, timestamp=t0 + 130 + i)
    a = time.perf_counter()
    lv4.assess()
    tt.append((time.perf_counter() - a) * 1000)
check("assess() is fast enough for the decision path (mean < 8 ms)", float(np.mean(tt)) < 8.0, f"mean {np.mean(tt):.2f} ms, max {np.max(tt):.2f} ms")

print("\nABSTENTION (never raises, never flags)")
check("missing weights -> NO_MODEL", PhysicalModelV3.load("/nonexistent/x.joblib").status == "NO_MODEL")
bad = os.path.join(out, "bad.joblib")
joblib.dump({"schema": "other"}, bad)
check("another schema -> NO_MODEL", PhysicalModelV3.load(bad).status == "NO_MODEL")
wrong = dict(blob)
wrong["feature_names"] = list(reversed(blob["feature_names"]))
wp = os.path.join(out, "wrong.joblib")
joblib.dump(wrong, wp)
check("a feature-schema mismatch -> NO_MODEL", PhysicalModelV3.load(wp).status == "NO_MODEL")
garbage = os.path.join(out, "garbage.joblib")
with open(garbage, "wb") as fh:
    fh.write(b"not a joblib file")
check("a corrupt file -> NO_MODEL (no exception)", PhysicalModelV3.load(garbage).status == "NO_MODEL")
ab = PhysicalModelV3.load("/nonexistent/x.joblib").assess()
check("an abstaining model never flags", ab["threat_flag"] is False and ab["status"] == "NO_MODEL")

print("\nFACTORY (v2 must remain the default)")
saved_default, saved_env = V3mod.DEFAULT_WEIGHTS, os.environ.get("IM_PHYSICAL_MODEL")
try:
    os.environ.pop("IM_PHYSICAL_MODEL", None)
    check("no setting -> the v2 model (v3 is opt-in)", type(V2mod.load_physical_model()).__name__ == "PhysicalModelV2")
    V3mod.DEFAULT_WEIGHTS = weights
    os.environ["IM_PHYSICAL_MODEL"] = "v3"
    check("IM_PHYSICAL_MODEL=v3 with v3 weights present -> the v3 model", type(V2mod.load_physical_model()).__name__ == "PhysicalModelV3")
    check("live_weights_path follows the v3 choice", V2mod.live_weights_path() == weights)
    V3mod.DEFAULT_WEIGHTS = os.path.join(out, "missing.joblib")
    check("IM_PHYSICAL_MODEL=v3 without v3 weights falls back to v2", type(V2mod.load_physical_model()).__name__ == "PhysicalModelV2")
finally:
    V3mod.DEFAULT_WEIGHTS = saved_default
    if saved_env is None:
        os.environ.pop("IM_PHYSICAL_MODEL", None)
    else:
        os.environ["IM_PHYSICAL_MODEL"] = saved_env
check("no v3 weights exist in models/weights from these tests", not os.path.exists(os.path.join(T.WEIGHTS_DIR, "physical_model_v3.joblib")) or saved_default == V3mod.DEFAULT_WEIGHTS)

print("\nPIPELINE INTEGRATION")
live = PhysicalModelV3.load(weights)
for i in range(130):
    live.update(nominal, timestamp=t0 + i)
pipe = MultiModelPipeline(physical_model=live)
cyber_agent.reset_state()
regs = {mm["register"]: mm["initial"] for mm in MACHINES}
state = {"registers": regs, "setpoints": dict(regs), "timestamp": time.time() - 10}
ts = time.time()
parsed = hmac_auth.parse_frame(hmac_auth.build_frame(0, 55.0, timestamp_ms=int(ts * 1000)))
rep = pipe.process_command(make_command("v3-tx", ts, LOOPBACK, 16, 0, 55.0, raw_value=parsed["raw_value"], auth=parsed["auth"]), state)
check("the real pipeline runs with the v3 model and forwards a legitimate command", rep["decision"]["verdict"] in ("PASS", "ALERT"), rep["decision"]["verdict"])
check("the pipeline report carries the v3 assessment", rep["physical"]["model"]["model"] == "PhysicalModelV3" and rep["physical"]["model"]["status"] == "OK")
hop = next((h for h in rep["trace"]["hops"] if h["hop"] == "physical_model"), None)
check("the packet-trace shows the physical-model hop for v3", hop is not None and hop["values"]["status"] == "OK", str(hop and hop["values"].get("status")))

print("\nALL PASS" if fails == 0 else f"\n{fails} CHECK(S) FAILED")
raise SystemExit(1 if fails else 0)
