"""
tests/test_physical_v3.py - physical model v3: features, normal-only models, cross-fitting, weighting, metrics, and the trainer's code
paths on the synthetic SWaT-SHAPED fixture (numbers from the fixture are meaningless; only code paths and invariants are checked).

    python -m tests.test_physical_v3
"""

from __future__ import annotations

import os
import tempfile

import numpy as np

from models import train_physical_v3 as T
from swat import features_v3 as F3
from swat.features_v2 import LONG, build_windows_v2
from swat.loader import load_stream
from swat.physical_features import ACTUATORS, SENSORS, Norm, compute_bounds
from tests.swat_fixture import make_swat_archive

fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global fails
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    fails += 0 if cond else 1


print("FEATURES (known inputs)")
mu, sd = np.full(10, 100.0), np.full(10, 2.0)
norm = Norm.__new__(Norm)
norm.mu, norm.sd, norm.lo, norm.hi = mu, sd, np.full(10, 50.0), np.full(10, 150.0)
t = np.arange(LONG, dtype=np.float64)
S = np.tile(mu, (1, LONG, 1)).astype(np.float64)
S[0, :, 0] = mu[0] + sd[0] * 0.01 * (t - t.mean())                 # sensor 0: a ramp of 0.01 sd per second
A = np.zeros((1, LONG, len(ACTUATORS)))
A[0, -10:, 1] = 1.0                                                  # actuator 1 switched on 10 s ago
A[0, :, 2] = 1.0                                                     # actuator 2 on the whole time
X, aux = F3.base_features(S, A, norm)
col = {n: i for i, n in enumerate(F3.BASE_NAMES)}
check("feature matrix has one column per name", X.shape == (1, len(F3.BASE_NAMES)) and aux.shape == (1, F3.AUX_DIM))
check("a ramp of 0.01 sd/s has slope 0.01 at every scale", all(abs(X[0, col[f"{SENSORS[0]}.slope{s}"]] - 0.01) < 1e-5 for s in (30, 60, 120)))
check("a flat sensor has slope 0 and std 0", abs(X[0, col[f"{SENSORS[1]}.slope120"]]) < 1e-9 and abs(X[0, col[f"{SENSORS[1]}.std30"]]) < 1e-9)
check("curvature of a straight ramp is 0", abs(X[0, col[f"{SENSORS[0]}.curv"]]) < 1e-5)
check("'seconds since the last toggle' counts the samples at the new state (10)", abs(X[0, col[f"{ACTUATORS[1]}.since_toggle"]] - 10) < 1e-6)
check("an actuator that never toggled reports the full window", abs(X[0, col[f"{ACTUATORS[2]}.since_toggle"]] - LONG) < 1e-6 and X[0, col[f"{ACTUATORS[2]}.toggles120"]] == 0)
check("healthy levels inside the envelope give no envelope features", X[0, col["x.sensors_outside_envelope"]] == 0 and X[0, col["x.env_frac120"]] == 0)
S2 = S.copy()
S2[0, -5:, 3] = 200.0                                                # sensor 3 leaves the envelope for the last 5 s
X2, _ = F3.base_features(S2, A, norm)
check("leaving the envelope is reported (count, excess, share of the window)",
      X2[0, col["x.sensors_outside_envelope"]] == 1 and X2[0, col["x.max_envelope_excess"]] > 0 and abs(X2[0, col["x.env_frac120"]] - 5 / LONG) < 1e-6)
check("no absolute sensor level is a classifier input (drift-robust)", not any(n.endswith((".last", ".mean")) for n in F3.BASE_NAMES))

print("\nNORMAL-ONLY MODELS")
rng = np.random.default_rng(0)
N = 6000
latent = rng.normal(size=(N, 5))                                         # a plant has a few common drivers: low-rank structure plus noise
AUXs = (latent @ rng.normal(size=(5, F3.AUX_DIM)) + 0.3 * rng.normal(size=(N, F3.AUX_DIM))).astype(np.float32)
s30 = F3.AUX_SLICES["SL30"].start
AUXs[:, s30 + 0] = 0.8 * AUXs[:, s30 + 1] + 0.05 * rng.normal(size=N)   # a real relationship: sensor 0's trend follows sensor 1's
nm = F3.NormalModels(use_levels=True).fit(AUXs)
R = nm.transform(AUXs)
check("transform has one column per documented name", R.shape == (N, len(F3.NM_NAMES)))
check("in-sample residuals are about unit scale", 0.8 < float(R[:, :20].std(axis=0).mean()) < 1.2)
broken = AUXs[:500].copy()
broken[:, s30 + 0] += 4.0                                               # the relationship breaks (sensor 0's trend no longer follows sensor 1's)
Rb = nm.transform(broken)
check("a broken relationship makes that sensor's residual large", float(np.abs(Rb[:, 0]).mean()) > 5 * float(np.abs(R[:500, 0]).mean()))
check("a broken relationship raises the PCA squared prediction error", float(Rb[:, F3.NM_NAMES.index("nm.spe")].mean()) > 2 * float(R[:, F3.NM_NAMES.index("nm.spe")].mean()))
check("PCA keeps between 3 and 20 components and finds the low-rank structure", 3 <= nm.P.shape[1] <= 20, str(nm.P.shape[1]))
nl = F3.NormalModels(use_levels=False).fit(AUXs)
check("the drift-robust variant never uses level regressors", all(not np.isin(np.arange(F3.AUX_SLICES["M120"].start, F3.AUX_SLICES["M30"].stop), c[0]).any() for c in nl.res))
check("a sensor is never used to predict itself", all((F3.AUX_SLICES["SL30"].start + 0) not in c[0] for c in nl.res[:1]))

print("\nCROSS-FITTING")
y = np.zeros(N, int)
y[2000:2200] = 1
ep = np.arange(N) * 5.0
Fcf, full = F3.crossfit_normal_features(AUXs, y, ep, k=4, use_levels=True)
ref = F3.NormalModels(use_levels=True).fit(AUXs[y == 0])
check("the returned scoring model is the all-benign fit", np.allclose(full.transform(AUXs[:50]), ref.transform(AUXs[:50]), atol=1e-4))
check("attack rows are scored by the all-benign model", np.allclose(Fcf[y == 1], full.transform(AUXs[y == 1]), atol=1e-4))
benign_in_fold = np.flatnonzero((y == 0) & ((ep // 3600).astype(int) % 4 == 0))
check("benign rows get features from a model that did NOT see their hour (differs from in-sample)",
      not np.allclose(Fcf[benign_in_fold], full.transform(AUXs[benign_in_fold]), atol=1e-6))

print("\nSTAGE VIEWS AND STACKING")
for st in F3.STAGE_IDS:
    cols = F3.stage_view(st)
    names = [F3.FEATURE_NAMES[j] for j in cols]
    own = {t for t, s in zip(SENSORS, F3.STAGE_OF_SENSOR) if s == st} | {t for t, s in zip(ACTUATORS, F3.STAGE_OF_ACT) if s == st}
    foreign = {t for t in SENSORS + ACTUATORS if t not in own}
    check(f"stage {st} view holds its own tags and no other stage's", any(n.split('.')[0] in own for n in names) and not any(n.split('.')[0] in foreign for n in names))
    check(f"stage {st} view has only its own per-stage SPE", f"nm.spe_s{st}" in names and sum(n.startswith("nm.spe_s") for n in names) == 1)
P = np.array([[0.1, 0.9, 0.5]])
inp = F3.stack_inputs(P)
check("stack inputs are the logits plus their max", inp.shape == (1, 4) and abs(inp[0, 3] - np.log(0.9 / 0.1)) < 1e-9)
check("stack_predict is a sigmoid of the linear score", abs(F3.stack_predict(inp, np.array([0, 0, 0, 1.0]), -1.0)[0] - 1 / (1 + np.exp(-(np.log(9) - 1)))) < 1e-9)
check("extreme probabilities do not overflow", np.isfinite(F3.stack_inputs(np.array([[0.0, 1.0]]))).all())

print("\nWEIGHTING WITHOUT sample_weight")
w = np.r_[np.ones(1000), np.full(500, 3.0), np.full(500, 0.4)]
idx = T.expand_by_weight(w, 0)
check("integer weights are reproduced exactly", np.all(np.bincount(T.expand_by_weight(np.r_[np.ones(50), np.full(50, 3.0)], 0), minlength=100) == np.r_[np.ones(50), np.full(50, 3)]))
check("fractional weights match in expectation", abs(len(idx) - w.sum()) / w.sum() < 0.03, f"{len(idx)} vs {w.sum():.0f}")
check("the same seed gives the same expansion", np.array_equal(idx, T.expand_by_weight(w, 0)))

print("\nEVENT METRICS AND CONFIDENCE INTERVALS")
epoch = np.arange(0, 3000, 5.0)
yy = np.zeros(len(epoch), bool)
sg = np.zeros(len(epoch), int)
yy[40:60], sg[40:60] = True, 1                                            # attack 1: 200..295 s
yy[300:320], sg[300:320] = True, 2                                        # attack 2: 1500..1595 s
fl = np.zeros(len(epoch), bool)
fl[45:50] = True                                                          # inside attack 1
fl[62:64] = True                                                          # 5-10 s after attack 1 (recovery)
fl[500:502] = True                                                        # a real false alarm
strict = T.event_metrics(fl, yy, sg, epoch, 0.0)
tol = T.event_metrics(fl, yy, sg, epoch, 300.0)
check("strict: 1 of 2 segments detected; of 3 alarm episodes only the one inside an attack is right (the recovery and stray alarms count against)",
      strict["segments_detected"] == 1 and strict["episodes"] == 3 and strict["tp_episodes"] == 1 and abs(strict["episode_precision"] - 1 / 3) < 1e-3, str(strict))
check("recovery-tolerant also accepts the alarm 15 s after the attack ended (2 of 3), but the stray alarm still counts against",
      tol["episodes"] == 3 and tol["tp_episodes"] == 2 and abs(tol["episode_precision"] - 2 / 3) < 1e-3 and tol["segments_detected"] == 1, str(tol))
check("no alarms -> zero episodes and undefined precision, no crash", T.event_metrics(np.zeros(len(epoch), bool), yy, sg, epoch, 0.0)["episode_precision"] is None)
perfect = T.bootstrap_ci(yy.copy(), yy, sg, epoch, B=200)
check("a perfect detector has a [1, 1] interval for precision and recall", perfect["precision"] == [1.0, 1.0] and perfect["recall"] == [1.0, 1.0])
none = T.bootstrap_ci(np.zeros(len(epoch), bool), yy, sg, epoch, B=200)
check("flagging nothing yields no precision interval and a zero recall interval (no crash)", none["precision"] is None and none["recall"] == [0.0, 0.0])
noisy = T.bootstrap_ci(fl, yy, sg, epoch, B=300)
check("intervals contain the point estimate", noisy["recall"][0] <= (fl & yy).sum() / yy.sum() <= noisy["recall"][1] or noisy["recall"][0] == noisy["recall"][1])

print("\nWINDOWS (fixture)")
d = tempfile.mkdtemp(prefix="v3-fix-")
make_swat_archive(d, seed=0)
stream, _ = load_stream(d, SENSORS + ACTUATORS)
nrm = Norm(compute_bounds(stream[(stream["block"] == "train") & ~stream["label"]][SENSORS]))
X87, XL, X3, AUX, meta = F3.build_windows_v3(stream, nrm)
a87, aL, m2 = build_windows_v2(stream, nrm)
check("v3 builds exactly the v2 windows (so a baseline refit is comparable)", len(meta) == len(m2) and bool((meta["epoch"].to_numpy() == m2["epoch"].to_numpy()).all()))
check("the v2 features inside the v3 builder are unchanged", np.allclose(X87, a87, atol=1e-4) and np.allclose(XL, aL, atol=1e-4))
check("all v3 features are finite", bool(np.isfinite(X3).all() and np.isfinite(AUX).all()))

print("\nTRAINER (fixture; recipes stack_nl, code path only)")
res, final, norm_t, arrays = T.run(stream, seed=1, folds=3, quick=True, budgets=(1.0, 4.0), recipes=["stack_nl"])
names = {c["recipe"] for c in res["cv"]}
check("the v2 baseline is always evaluated, plus the requested recipe", names == {"v2ref", "stack_nl"}, str(names))
check("the selected recipe is a v3 recipe and the test block is evaluated for baseline and selected only",
      res["selected_recipe"] == "stack_nl" and set(res["test"]["1.0"]) == {"baseline", "selected_without_persistence", "selected"})
check("the stacker is fitted over the global head and the five stage heads", final["stacker"] is not None and len(final["stack_heads"]) == 6 and len(final["heads"]) == 6)
sel = res["test"]["4.0"]["selected_without_persistence"]
check("test results carry event metrics and bootstrap intervals", "event_strict" in sel and "event_recovery_tolerant" in sel and "bootstrap_95ci" in sel, str(list(sel)[:6]))
check("a promotion checklist is produced with a twin-check item that is never auto-ticked", any(ok is None for _, ok, _ in T.promotion_checklist(res)))
txt = T.render(res, fixture=True)
check("the report says fixture numbers are meaningless and the test block is not blind", "meaningless" in txt and "not blind" in txt)
out = tempfile.mkdtemp(prefix="v3-out-")
cand = T.save_candidate(out, res, final, norm_t, True)
figs = T.render_figures(out, arrays, res)
check("candidate, report json and three figures are written", os.path.exists(cand) and os.path.exists(os.path.join(out, "physical_v3_report.json"))
      and len(figs) == 3 and all(os.path.getsize(f) > 1000 for f in figs))
leaked = [n for n in os.listdir(T.WEIGHTS_DIR) if n.startswith("physical_model_v3") or n.startswith("physical_v3")]
check("no v3 weights were written to models/weights", not leaked, str(leaked))
try:
    T.save_candidate(os.path.join(T.WEIGHTS_DIR, "sub"), res, final, norm_t, True)
    refused = False
except SystemExit:
    refused = True
check("saving into models/weights is refused", refused)

print("\nALL PASS" if fails == 0 else f"\n{fails} CHECK(S) FAILED")
raise SystemExit(1 if fails else 0)
