"""
tests/test_physical_v2.py - the physical-model v2 experiment: alarm logic, features, the trainer on the synthetic fixture (code paths only).

    python -m tests.test_physical_v2
"""

from __future__ import annotations

import os
import tempfile

import numpy as np

from models import train_physical_v2 as T
from swat import alarm_logic as AL
from swat.features_v2 import BASE_COLS, LONG, LONG_NAMES, RESID_NAMES, ResidualModel, assemble, build_windows_v2, feature_names
from swat.loader import load_stream
from swat.physical_features import ACTUATORS, SENSORS, Norm, compute_bounds
from tests.swat_fixture import make_swat_archive

fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global fails
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    fails += 0 if cond else 1


print("ALARM LOGIC")
ep = np.arange(0, 100, 5.0)
f = np.zeros(20, bool)
f[[3, 7, 8, 9]] = True
p = AL.persist(f, ep, 2, 3)
check("k=1,m=1 is the identity", bool((AL.persist(f, ep, 1, 1) == f).all()))
check("an isolated flag is suppressed by 2-of-3", not p[3] and p[8] and p[9] and not p[7], str(np.flatnonzero(p).tolist()))
gap = np.concatenate([ep[:10], ep[10:] + 1000.0])
g = np.zeros(20, bool)
g[9] = g[10] = True
check("a time gap restarts the run (flags on both sides of a gap do not add up)", not AL.persist(g, gap, 2, 2)[10])
check("episodes merge flags closer than 30 s and split distant ones", AL.episodes(np.array([0, 5, 10, 100, 105.0]), np.ones(5, bool)) == 2)
rng = np.random.default_rng(0)
score, y, seg = rng.random(4000), np.zeros(4000, bool), np.zeros(4000, int)
epoch = np.arange(4000) * 5.0
y[1000:1100] = True
seg[1000:1100] = 1
score[1000:1100] += 0.6
thr = AL.threshold_for_budget(score, epoch, y, 1, 1, 2.0)
check("the budget threshold keeps benign alarm episodes within the budget",
      thr is not None and AL.episodes(epoch[~y], (score > thr)[~y]) / AL.benign_hours(epoch, y) <= 2.0)
best = AL.best_alarm_rule(score, epoch, y, seg, 2.0)
check("best_alarm_rule returns a rule that meets the budget and detects the attack", bool(best) and best["segment_balanced_recall"] > 0.5, str(best))
check("segment-balanced recall counts every segment equally",
      abs(AL.segment_balanced_recall(np.r_[np.ones(10), np.zeros(90)].astype(bool), np.ones(100, bool), np.r_[np.ones(10), 2 * np.ones(90)].astype(int)) - 0.5) < 1e-9)

print("\nFEATURES V2 (synthetic fixture)")
d = tempfile.mkdtemp(prefix="v2-fix-")
make_swat_archive(d, seed=0)
stream, _ = load_stream(d, SENSORS + ACTUATORS)
norm = Norm(compute_bounds(stream[(stream["block"] == "train") & ~stream["label"]][SENSORS]))
X87, XL, meta = build_windows_v2(stream, norm)
check("windows carry a full history: shapes align", X87.shape[0] == XL.shape[0] == len(meta) and XL.shape[1] == len(LONG_NAMES) and X87.shape[1] == 87)
check("no NaN or inf in any feature", bool(np.isfinite(X87).all() and np.isfinite(XL).all()))
first_window = meta.groupby("chunk")["epoch"].min()
first_row = stream.groupby("chunk")["epoch"].min()
check("the first window of a chunk needs LONG seconds of history", int((first_window - first_row.loc[first_window.index]).min()) >= LONG - 1)
resid_model = ResidualModel().fit(X87[meta["label"].to_numpy() == 0])
R = resid_model.transform(X87)
check("residual features have the documented shape and are finite", R.shape[1] == len(RESID_NAMES) and bool(np.isfinite(R).all()))
ben = meta["label"].to_numpy() == 0
spread = float(R[ben][:, :10].std(axis=0).mean())
check("residuals are about unit scale on the normal windows they were fitted on", 0.5 < spread < 1.5, "%.2f" % spread)
for fs in ("v1_67", "v1_long", "v1_long_resid"):
    A = assemble(fs, X87, XL, resid_model)
    check(f"feature set {fs}: column count equals feature_names", A.shape[1] == len(feature_names(fs)), str(A.shape[1]))
check("v1_67 is exactly the shipped drift_robust columns", assemble("v1_67", X87, XL, None).shape[1] == len(BASE_COLS) == 67)

print("\nTRAINING WEIGHTS")
yy = np.r_[np.zeros(900), np.ones(100)].astype(int)
ss = np.r_[np.zeros(900), np.ones(90), 2 * np.ones(10)].astype(int)
w = T.training_weights(yy, ss)
check("classes are balanced in total weight", abs(w[yy == 1].sum() - w[yy == 0].sum()) < 1e-6)
check("a large segment cannot drown a small one (per-segment weight ~ sqrt(size))", abs((w[ss == 1].sum() / w[ss == 2].sum()) - np.sqrt(90 / 10)) < 1e-6)
sw = T.segment_balanced_weights(yy, ss)
check("evaluation weights give every attack segment the same total", abs(sw[ss == 1].sum() - sw[ss == 2].sum()) < 1e-9)

print("\nTRAINER (fixture, reduced grid: code path only)")
res, final, _ = T.run(stream, seed=1, folds=3, quick=True, budgets=(1.0,), kinds=["hgb"], fsets=["v1_67", "v1_long_resid"])
check("cross-validation rows for every requested configuration", len(res["cv"]) == 2)
check("a configuration was selected and the test block was evaluated for baseline and selected only",
      res["selected"]["model"] == "hgb" and set(res["test"]["1.0"]) == {"baseline", "selected_without_persistence", "selected"})
leaked = [n for n in os.listdir(T.WEIGHTS_DIR) if n.startswith("physical_v2")]
check("no v2 weights were written to models/weights", not leaked, str(leaked))
txt = T.render(res, fixture=True)
check("the report states that fixture numbers are meaningless and that the test block is not blind", "meaningless" in txt and "not blind" in txt)

print("\nALL PASS" if fails == 0 else f"\n{fails} CHECK(S) FAILED")
raise SystemExit(1 if fails else 0)
