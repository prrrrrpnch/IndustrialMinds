"""
tests/test_swat_protocol.py - the scoring module, the cross-validation folds, the re-scoring of a saved report and the protocol itself
(on the synthetic fixture: code paths only, never real metrics).

    python -m tests.test_swat_protocol
"""

from __future__ import annotations

import json
import os
import tempfile

import numpy as np
import pandas as pd

from benchmark import swat_protocol as P
from swat import scoring as SC
from swat.alarm_logic import episodes as legacy_episodes

fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global fails
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    fails += 0 if cond else 1


# ---------------------------------------------------------------------------------------------------- a hand-checked case
print("SCORING: a case small enough to check by hand")
ep = np.arange(100) * 5.0
y = np.zeros(100, bool)
seg = np.zeros(100, int)
y[10:20], seg[10:20] = True, 1          # attack 1: 10 windows, 1 flagged (late)
y[50:54], seg[50:54] = True, 2          # attack 2: 4 windows, all flagged
fl = np.zeros(100, bool)
fl[[12, 50, 51, 52, 53, 80, 81, 90]] = True
c = SC.counts_from_flags(fl, y, seg, ep)
m = SC.metrics(c)
check("strict counts", (m["tp"], m["fp"], m["fn"], m["tn"]) == (5, 3, 9, 83), str((m["tp"], m["fp"], m["fn"], m["tn"])))
check("strict precision / recall / F1", (m["precision"], m["recall"], m["f1"]) == (0.625, 0.3571, 0.4545))
check("composite: window precision, ATTACK recall (2/2)", (m["event_recall"], m["composite_f1"]) == (1.0, 0.7692))
check("point-adjust credits both whole attacks (14 of 14 windows)", (m["pa_recall"], m["pa_precision"], m["pa_f1"]) == (1.0, 0.8235, 0.9032), str((m["pa_recall"], m["pa_f1"])))
check("PA%K: attack 2 (100 % flagged) is credited, attack 1 (10 % flagged) is not, at K = 20 / 50 / 80", m["pak20_recall"] == m["pak50_recall"] == m["pak80_recall"] == 0.3571)
check("detection delay: attack 1 first flagged 2 windows (10 s) in, attack 2 at once -> median 5 s", m["median_latency_s"] == 5.0)
check("alarm episodes: flags merge within 30 s -> 4 episodes, 2 overlap an attack", (m["alarm_episodes"], m["episode_precision"]) == (4, 0.5))
check("a never-alarm detector's accuracy is reported next to the model's", m["always_benign_accuracy"] == 0.86)
check("per-attack rows carry delay and flagged share", [r["flagged_share"] for r in SC.per_attack(c)] == [0.1, 1.0])
none = SC.metrics(SC.counts_from_flags(np.zeros(100, bool), y, seg, ep))
check("no alarms at all: F1 is 0 (not undefined), nothing detected, no delay", none["f1"] == 0.0 and none["segments_detected"] == 0 and none["median_latency_s"] is None)

print("\nSCORING: properties that must hold on any input")
rng = np.random.default_rng(3)
ok_order, ok_prec, ok_ci, ok_ep = True, True, True, True
for trial in range(25):
    n = 3000
    yy = np.zeros(n, bool)
    sg = np.zeros(n, int)
    for i, (a, L) in enumerate([(300, 120), (900, 40), (1600, 300), (2400, 60)], 1):
        yy[a:a + L], sg[a:a + L] = True, i
    e = np.arange(n) * 5.0
    f = rng.random(n) < rng.uniform(0.01, 0.2)
    mm = SC.metrics(SC.counts_from_flags(f, yy, sg, e))
    ok_order &= mm["pa_recall"] >= mm["pak20_recall"] >= mm["pak50_recall"] >= mm["pak80_recall"] >= mm["recall"] - 1e-9
    ok_prec &= mm["pa_f1"] >= mm["f1"] - 1e-9 and mm["pa_precision"] >= mm["precision"] - 1e-9
    ok_ep &= SC.count_episodes(e[~yy], f[~yy]) == legacy_episodes(e[~yy], f[~yy])
check("point-adjust >= PA%K(20) >= (50) >= (80) >= strict recall, always", ok_order)
check("point-adjust never scores BELOW strict (it only adds credit)", ok_prec)
check("episode counting agrees with swat.alarm_logic.episodes", ok_ep)
from models.train_physical_v2 import confusion_metrics
yy = rng.random(2000) < 0.1
ff = rng.random(2000) < 0.15
legacy = confusion_metrics(yy, ff)
mine = SC.metrics(SC.counts_from_flags(ff, yy, np.where(yy, 1, 0), np.arange(2000) * 5.0))
check("strict numbers equal the trainer's confusion_metrics", all(abs(mine[k] - legacy[k]) < 1e-4 for k in ("precision", "recall", "f1", "accuracy", "balanced_accuracy")))

print("\nBOOTSTRAP AND CHANCE BASELINE")
n = 6000
yy = np.zeros(n, bool)
sg = np.zeros(n, int)
for i, (a, L) in enumerate([(300, 120), (900, 40), (1600, 300), (2400, 60), (3300, 80), (4200, 150), (5000, 200), (5600, 30)], 1):
    yy[a:a + L], sg[a:a + L] = True, i
e = np.arange(n) * 5.0
good = (rng.random(n) < 0.02) | (yy & (sg % 2 == 1) & (rng.random(n) < 0.6))     # catches the odd-numbered attacks only
cg = SC.counts_from_flags(good, yy, sg, e)
mg = SC.metrics(cg)
ci = SC.bootstrap(cg, 400, 1)
check("the 95 % interval brackets the point estimate for F1, recall and detection share", all(ci[k][0] <= mg[k] <= ci[k][1] for k in ("f1", "recall", "event_recall")), str(ci["f1"]))
check("the bootstrap is reproducible for a seed", SC.bootstrap(cg, 400, 1) == ci)
check("with few attacks the interval is wide (that is the honest message)", ci["event_recall"][1] - ci["event_recall"][0] >= 0.2, str(ci["event_recall"]))
check("nothing to resample -> no interval, no crash", SC.bootstrap(SC.counts_from_flags(np.zeros(10, bool), np.zeros(10, bool), np.zeros(10, int), np.arange(10) * 5.0), 50) == {})
yl = np.zeros(20000, bool)
sl = np.zeros(20000, int)
yl[8000:10000], sl[8000:10000] = True, 1               # ONE long attack, like SWaT's 10-hour segment
el = np.arange(20000) * 5.0
rb = SC.random_baseline(rng.random(20000) < 0.05, yl, sl, el, trials=60, seed=2)
check("chance alarms earn almost nothing under strict scoring", rb["recall"]["mean"] < 0.15 and rb["f1"]["mean"] < 0.15, f"recall {rb['recall']['mean']}, F1 {rb['f1']['mean']}")
check("...but point-adjust gives them nearly the whole long attack (the Kim et al. effect)", rb["pa_recall"]["mean"] > 0.9, f"PA recall {rb['pa_recall']['mean']}")
flag_ref = np.zeros(5000, bool)
flag_ref[100:110] = flag_ref[900:910] = flag_ref[3000:3010] = True
fl_rand = SC.random_alarm_flags(200000, flag_ref.mean(), SC.mean_run_length(flag_ref), np.random.default_rng(0))
check("chance alarms are matched to the reference's flagged share and alarm length", abs(fl_rand.mean() - flag_ref.mean()) < 0.003 and abs(SC.mean_run_length(fl_rand) - 10) < 2.5,
      f"share {fl_rand.mean():.4f} vs {flag_ref.mean():.4f}, run {SC.mean_run_length(fl_rand):.1f}")

print("\nRE-SCORING THE SAVED v2 REPORT (no data needed)")
REPORT = os.path.join(P.ROOT, "docs", "reports", "physical_training_report_v2_swat.json")
res = P.rescore_report(REPORT, n_boot=300)
live = res["budgets"]["0.5"]["selected_without_persistence"]["metrics"]
with open(REPORT) as fh:
    rep = json.load(fh)["test"]["0.5"]["selected_without_persistence"]
check("strict numbers re-derived from the per-attack aggregates equal the report's own", (live["precision"], live["recall"], live["f1"], live["accuracy"]) == (rep["precision"], rep["recall"], rep["f1"], rep["accuracy"]))
check("the same 8 of 10 attacks and 57.5 s median delay survive the re-scoring", (live["segments_detected"], live["median_latency_s"]) == (rep["segments_detected"], rep["median_latency_s"]))
check("point-adjust F1 for the live model is the figure quoted in the project docs (0.685)", live["pa_f1"] == 0.6852 and live["composite_f1"] == 0.5846, str((live["pa_f1"], live["composite_f1"])))
check("the false-alarm rate is a property of the alarms, not of the scoring: unchanged", live["false_alarm_episodes_per_hour"] == rep["alarm_episodes_per_benign_hour"])
txt = P.render_rescore(res)
check("the rendered comparison says nothing was retrained and that the interval is attack-side only", "Nothing was retrained" in txt and "benign side fixed" in txt)

print("\nCROSS-VALIDATION FOLDS")
start = 1451296800.0                                      # the loader's ATTACK_PERIOD_START (28 Dec 2015 10:00)
epoch = start - 20000 + np.arange(0, 120000, 5.0)
lab = np.zeros(epoch.size, bool)
sgm = np.zeros(epoch.size, int)
for i in range(1, 13):
    a = 6000 + (i - 1) * 1500
    lab[a:a + 100], sgm[a:a + 100] = True, i
meta = pd.DataFrame({"epoch": epoch, "label": lab, "seg": sgm})
F = P.make_folds(meta, 4, 300.0)
fold = F["fold"]
check("every attack segment is in exactly one test fold, and the groups are in time order", sorted(s for g in F["groups"] for s in g) == list(range(1, 13)) and F["groups"] == sorted(F["groups"]))
check("windows before the first attack are never tested", bool((fold[epoch < start] == -1).all()))
check("an attack's windows all fall in one fold", all(len(set(fold[(sgm == s)])) == 1 for s in range(1, 13)))
check("folds are contiguous in time", all((np.diff(np.flatnonzero(fold == f)) == 1).all() for f in range(4)))
ok = True
for f in range(4):
    te, tr = np.flatnonzero(fold == f), F["train"][f]
    near = (epoch >= epoch[te].min() - 300.0) & (epoch <= epoch[te].max() + 300.0)
    ok &= not tr[te].any() and not tr[near].any() and tr[epoch < start].mean() > 0.9
check("the training part never contains the test fold or its 300 s embargo; the pre-attack normal period still trains", ok)
meta3 = meta.copy()
meta3.loc[meta3["seg"] > 3, "label"] = False
meta3.loc[meta3["seg"] > 3, "seg"] = 0
check("fewer attacks than folds -> fewer folds, not an error", P.make_folds(meta3, 9, 0.0)["k"] == 3)

print("\nATTACK DESCRIPTION (heuristic)")
n = 2400
stream = pd.DataFrame({"seg": 0, "chunk": 0, "label": False, "LIT101": 500 + np.random.default_rng(0).normal(0, 1, n), "P101": 2.0, "AIT501": 7.4 + np.random.default_rng(1).normal(0, .01, n)})
stream.loc[1800:1900, "seg"] = 1
stream.loc[1800:1900, "label"] = True
stream.loc[1800:1900, "LIT101"] += 80.0                   # a live sensor jumps
stream.loc[1800:1900, "AIT501"] += 1.0                    # a NON-live tag moves too (AIT501 is not one of the 18)
d = P.describe_segments(stream, ["LIT101", "P101", "AIT501"], [1])[1]
check("a shifted sensor is reported as moved, an untouched constant actuator is not", d["described"] and "LIT101" in d["live_tags_moved"] and "P101" not in d["live_tags_moved"], str(d))
check("a tag outside the model's 18 is counted as moved but not as live", d["other_tags_moved"] == 1 and d["visible_to_model"] is True)
stream2 = stream.copy()
stream2["LIT101"] = 500 + np.random.default_rng(0).normal(0, 1, n)
stream2["AIT501"] = 7.4 + np.random.default_rng(1).normal(0, .01, n)
stream2.loc[1800:1900, "AIT501"] += 1.0
d2 = P.describe_segments(stream2, ["LIT101", "P101", "AIT501"], [1])[1]
check("an attack that moves only tags the model cannot read is flagged not visible", d2["visible_to_model"] is False and d2["tags_moved"] == 1)

print("\nPROTOCOL ON THE SYNTHETIC FIXTURE (code path only)")
from swat.loader import load_stream
from swat.physical_features import ACTUATORS, SENSORS
from tests.swat_fixture import make_swat_archive
real_outputs = [P.OUT_JSON, P.OUT_MD]
before = [os.path.getmtime(p) if os.path.exists(p) else None for p in real_outputs]
d = tempfile.mkdtemp(prefix="proto-fix-")
make_swat_archive(d, seed=0)
stream, _ = load_stream(d, sorted(set(SENSORS + ACTUATORS + P.all_tags(d))))
r = P.run(stream, 3, 300.0, 1, (0.5, 2.0), True, 100, 20, P.all_tags(d), fast_hgb=True)
r["fixture"] = True
pr = r["protocol"]
check("every attack segment is tested exactly once", pr["attack_segments"] == 35 and len(r["per_attack"]) == 35 and sorted(int(s) for g in pr["fold_groups"] for s in g) == list(range(1, 36)))
check("the pooled attack windows are all the attack windows of the test region", r["pooled"]["v2"]["0.5"]["attack_windows"] == pr["attack_windows"] == sum(a["attack_windows"] for a in r["per_attack"]))
check("pre-attack normal windows are train-only and not scored", pr["normal_period_windows_train_only"] > 0 and pr["windows_tested"] + pr["normal_period_windows_train_only"] <= pr["windows_total"])
check("every method has a result at every budget, plus envelope and never-alarm rows", all(set(r["pooled"][n]) == {"0.5", "2.0"} for n in ("v2", "refit_baseline", "pca", "iforest")) and "fixed" in r["pooled"]["envelope_rule"] and "fixed" in r["pooled"]["never_alarm"])
check("never alarming detects nothing and has F1 0", r["pooled"]["never_alarm"]["fixed"]["segments_detected"] == 0 and r["pooled"]["never_alarm"]["fixed"]["f1"] == 0.0)
check("a looser budget never alarms LESS than a tighter one (pooled flagged windows)", r["pooled"]["v2"]["2.0"]["tp"] + r["pooled"]["v2"]["2.0"]["fp"] >= r["pooled"]["v2"]["0.5"]["tp"] + r["pooled"]["v2"]["0.5"]["fp"])
check("the report carries intervals, a chance baseline, per-fold rows and a visibility bound", bool(r["ci_primary_budget"]["v2"]) and r["chance_baseline"]["trials"] == 20 and len(r["per_fold"]) == 3 and "visibility_bound" in r)
check("realised false-alarm rates are reported per fold next to the budget", all("false_alarm_episodes_per_hour" in f["v2"] for f in r["per_fold"]))
check("the 'without the largest attack' view drops exactly that segment", r["without_largest_segment"]["v2"]["segments_total"] == 34 and r["largest_segment"]["segment"] > 0)
md = P.render(r, fixture=True)
check("the fixture report says its numbers are meaningless and names every section", "meaningless" in md and all(h in md for h in ("## Headline", "## Operating curve", "## Fold by fold", "## Attack by attack", "## Limits that stay", "chance alarms matched")))
figs = P.figures(r, os.path.join(d, "figs"))
check("three figures were drawn", len(figs) == 3 and all(os.path.getsize(os.path.join(d, "figs", f)) > 5000 for f in figs))
check("a fixture run does not touch the real report outputs", before == [os.path.getmtime(p) if os.path.exists(p) else None for p in real_outputs])
leaked = [n for n in os.listdir(os.path.join(P.ROOT, "models", "weights")) if "protocol" in n or "fixture" in n]
check("nothing was written to models/weights", not leaked, str(leaked))
json.dumps(r, default=float)
check("the whole result serialises to JSON (aggregate numbers only)", True)

print("\nALL PASS" if fails == 0 else f"\n{fails} CHECK(S) FAILED")
raise SystemExit(1 if fails else 0)
