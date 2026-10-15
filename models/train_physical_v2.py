"""
models/train_physical_v2.py - EXPERIMENT: can the physical model be made clearly better under an honest protocol?

    python -m models.train_physical_v2 --data-dir "C:\\IndustrialMind\\SWaT_dataset\\archive" --candidate
    python -m models.train_physical_v2 --fixture --candidate --quick        # synthetic SWaT-SHAPED data, code-path check only

Writes ONLY to models/candidates/physical_v2/ (report .md/.json + candidate .joblib). It never touches models/weights/ and the live
middleware does not use it: promotion would need the live model extended to a 120 s history first and the user's approval.

WHAT CHANGES versus the shipped model (each is measured separately, see the ablation tables):
  1. TRAIN ON MORE DAYS: train + validation blocks are both used for fitting (25 attack segments instead of 17), and the validation
     days are the ones closest in time to the test days (less calendar drift).
  2. RICHER FEATURES: 120 s long-context features and cross-sensor consistency residuals (swat/features_v2.py).
  3. BETTER SELECTION: segment-grouped 5-fold cross-validation on train + validation (attack windows folded by SEGMENT, benign by
     hour), choosing the feature set and model by SEGMENT-BALANCED average precision (every attack segment counts equally, so the
     10-hour segment 22 cannot dominate).
  4. ALARM LOGIC: "k of the last m windows" persistence plus a threshold set by a FALSE-ALARM BUDGET on the out-of-fold scores
     (swat/alarm_logic.py), instead of alarming on every single flag.

PROTOCOL HONESTY. Everything is chosen on train + validation only (cross-validated, out-of-fold). The TEST block (1-2 Jan) is
used for exactly TWO fits-and-looks: the refit baseline and the selected configuration. It was already seen once by the shipped
model's revised protocol, so these are held-out, not blind, results; the report says so.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from swat.alarm_logic import STRIDE_S, benign_hours, best_alarm_rule, episodes, persist, segment_balanced_recall, threshold_for_budget
from swat.features_v2 import FEATURE_SETS, ResidualModel, assemble, build_windows_v2, feature_names
from swat.fusion_scenarios import fold_ids
from swat.loader import load_stream
from swat.physical_features import ACTUATORS, SENSORS, Norm, compute_bounds

log = logging.getLogger("industrialmind.train_physical_v2")
HERE = os.path.dirname(os.path.abspath(__file__))
WEIGHTS_DIR = os.path.realpath(os.path.join(HERE, "weights"))
DEFAULT_OUT = os.path.join(HERE, "candidates", "physical_v2")
# False-alarm operating points swept in the report, in episodes per benign hour.
# A wider sweep lets you pick recall vs. false-alarms for YOUR goal: the live
# model ships at 0.5/h but you can run any point with IM_PHYSICAL_THRESHOLD, or
# re-package with `models.package_physical_v2 --budget <b>`. This is reporting
# breadth only; it does not change how the model is trained.
BUDGETS = (0.25, 0.5, 1.0, 2.0, 4.0)


# --------------------------------------------------------------------------- models
class Scorer:
    """A supervised head returning an attack score in [0, 1]. kind: rf6 / rf10 / hgb."""

    def __init__(self, kind: str, seed: int, n_trees: int = 100) -> None:
        self.kind, self.seed, self.n_trees = kind, seed, n_trees
        self.model: Any = None

    def fit(self, X: np.ndarray, y: np.ndarray, w: np.ndarray) -> "Scorer":
        if self.kind == "hgb":
            from sklearn.ensemble import HistGradientBoostingClassifier
            self.model = HistGradientBoostingClassifier(max_depth=3, max_iter=max(40, self.n_trees), learning_rate=0.05, l2_regularization=10.0,
                                                        min_samples_leaf=100, random_state=self.seed).fit(X, y, sample_weight=w)
        else:
            from sklearn.ensemble import RandomForestRegressor
            depth, leaf = (6, 10) if self.kind == "rf6" else (10, 40)
            self.model = RandomForestRegressor(n_estimators=self.n_trees, max_depth=depth, min_samples_leaf=leaf, max_features="sqrt",
                                               random_state=self.seed, n_jobs=-1).fit(X, y.astype(float), sample_weight=w)
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict_proba(X)[:, 1] if self.kind == "hgb" else self.model.predict(X)


def training_weights(y: np.ndarray, seg: np.ndarray) -> np.ndarray:
    """Benign windows weight 1; attack windows weight ~ 1/sqrt(segment size), scaled so attacks and benign carry equal total weight
    (balanced classes, and a huge segment cannot drown the small ones)."""
    w = np.ones(len(y))
    att = y.astype(bool)
    if att.any():
        size = {s: int(((seg == s) & att).sum()) for s in np.unique(seg[att])}
        raw = np.array([1.0 / np.sqrt(size[s]) for s in seg[att]])
        w[att] = raw * ((~att).sum() / raw.sum())
    return w


def segment_balanced_weights(y: np.ndarray, seg: np.ndarray) -> np.ndarray:
    """Evaluation weights: benign 1; each attack segment carries the same total weight (total attack weight unchanged)."""
    w = np.ones(len(y))
    att = y.astype(bool)
    segs = np.unique(seg[att])
    for s in segs:
        m = (seg == s) & att
        w[m] = att.sum() / (len(segs) * m.sum())
    return w


MAX_BENIGN_FIT = 50000       # benign windows per fit (all attack windows are always kept): bounds the cost on the full archive


def fit_fold(fset: str, kind: str, X87: np.ndarray, XL: np.ndarray, y: np.ndarray, seg: np.ndarray, seed: int, n_trees: int
             ) -> Tuple[Scorer, Optional[ResidualModel]]:
    resid = ResidualModel().fit(X87[y == 0]) if fset == "v1_long_resid" else None        # consistency model sees ALL normal windows
    ben = np.flatnonzero(y == 0)
    if ben.size > MAX_BENIGN_FIT:
        keep = np.concatenate([np.flatnonzero(y == 1), np.random.default_rng(seed).choice(ben, MAX_BENIGN_FIT, replace=False)])
        keep.sort()
        X87, XL, y, seg = X87[keep], XL[keep], y[keep], seg[keep]
    X = assemble(fset, X87, XL, resid)
    return Scorer(kind, seed, n_trees).fit(X, y, training_weights(y, seg)), resid


def predict(fset: str, scorer: Scorer, resid: Optional[ResidualModel], X87: np.ndarray, XL: np.ndarray) -> np.ndarray:
    return scorer.score(assemble(fset, X87, XL, resid))


# --------------------------------------------------------------------------- metrics
def confusion_metrics(y: np.ndarray, f: np.ndarray) -> Dict[str, Any]:
    y, f = np.asarray(y, bool), np.asarray(f, bool)
    tp, fp, fn, tn = int((y & f).sum()), int((~y & f).sum()), int((y & ~f).sum()), int((~y & ~f).sum())
    P = tp / (tp + fp) if tp + fp else None
    R = tp / (tp + fn) if tp + fn else None
    F = 2 * P * R / (P + R) if P and R else (0.0 if P is not None and R is not None else None)
    spec = tn / (tn + fp) if tn + fp else None
    r = lambda v: None if v is None else round(float(v), 4)
    n = tp + fp + fn + tn
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": r(P), "recall": r(R), "f1": r(F), "accuracy": r((tp + tn) / n if n else None),
            "balanced_accuracy": r((R + spec) / 2 if R is not None and spec is not None else None), "false_positive_rate": r(1 - spec if spec is not None else None),
            "always_benign_baseline_accuracy": r((tn + fp) / n if n else None)}


def evaluate_alarm(score: np.ndarray, flag: np.ndarray, y: np.ndarray, seg: np.ndarray, epoch: np.ndarray) -> Dict[str, Any]:
    from sklearn.metrics import average_precision_score, roc_auc_score
    y = np.asarray(y, bool)
    out = confusion_metrics(y, flag)
    hrs = benign_hours(epoch, y)
    out["alarm_episodes_per_benign_hour"] = round(episodes(epoch[~y], flag[~y]) / hrs, 3)
    if 0 < y.sum() < len(y):
        out["roc_auc"], out["average_precision"] = round(float(roc_auc_score(y, score)), 4), round(float(average_precision_score(y, score)), 4)
    segs, det, lat = [], 0, []
    for s in np.unique(seg[y]):
        m = (seg == s) & y
        hit = m & flag
        t0 = float(epoch[m].min())
        segs.append({"segment": int(s), "attack_windows": int(m.sum()), "flagged_windows": int(hit.sum()), "detected": bool(hit.any()),
                     "latency_s": float(epoch[hit].min() - t0) if hit.any() else None})
        det += bool(hit.any())
        if hit.any():
            lat.append(float(epoch[hit].min() - t0))
    out["segments_detected"], out["segments_total"] = det, len(segs)
    out["median_latency_s"] = float(np.median(lat)) if lat else None
    out["segment_balanced_recall"] = round(segment_balanced_recall(flag, y, seg), 4)
    out["per_segment"] = segs
    return out


# --------------------------------------------------------------------------- experiment
def run(stream, seed: int, folds: int, quick: bool, budgets: Tuple[float, ...] = BUDGETS,
        kinds: Optional[List[str]] = None, fsets: Optional[List[str]] = None) -> Dict[str, Any]:
    from sklearn.metrics import average_precision_score, roc_auc_score
    t_start = time.time()
    train_norm = stream[(stream["block"] == "train") & ~stream["label"]]
    if len(train_norm) < 2000:
        raise SystemExit("too few train-block normal rows to measure bounds")
    norm = Norm(compute_bounds(train_norm[SENSORS]))
    X87, XL, meta = build_windows_v2(stream, norm)
    y, seg, ep, blk = meta["label"].to_numpy().astype(int), meta["seg"].to_numpy(), meta["epoch"].to_numpy(), meta["block"].to_numpy()
    dev, test = np.flatnonzero(np.isin(blk, ["train", "val"])), np.flatnonzero(blk == "test")
    if dev.size == 0 or test.size == 0 or y[dev].sum() < 5 or y[test].sum() == 0:
        raise SystemExit("need windows (with attacks) in train+val and in test")
    log.info("windows with a full 120 s history: dev %d (attack %d, segments %d), test %d (attack %d, segments %d)", dev.size, y[dev].sum(),
             len(np.unique(seg[dev][y[dev] == 1])), test.size, y[test].sum(), len(np.unique(seg[test][y[test] == 1])))
    fold = fold_ids(meta.iloc[dev].reset_index(drop=True), folds)
    Xd87, Xdl, yd, sd, ed = X87[dev], XL[dev], y[dev], seg[dev], ep[dev]
    esw = segment_balanced_weights(yd, sd)

    fsets = fsets or ["v1_67", "v1_long", "v1_long_resid"]
    kinds = kinds or ["rf6", "hgb"]                    # rf10 only on request: it doubles the cost for little gain
    cv: List[Dict[str, Any]] = []
    oof_by_cfg: Dict[str, np.ndarray] = {}
    for fs in fsets:
        for kind in kinds:
            oof = np.full(len(yd), np.nan)
            for f in range(folds):
                hold, fit = fold == f, fold != f
                if hold.sum() == 0 or yd[fit].sum() < 3:
                    continue
                sc, rs = fit_fold(fs, kind, Xd87[fit], Xdl[fit], yd[fit], sd[fit], seed, 60 if quick else 100)
                oof[hold] = predict(fs, sc, rs, Xd87[hold], Xdl[hold])
            ok = ~np.isnan(oof)
            row = {"feature_set": fs, "model": kind, "oof_windows": int(ok.sum()),
                   "segment_balanced_average_precision": round(float(average_precision_score(yd[ok], oof[ok], sample_weight=esw[ok])), 4),
                   "average_precision": round(float(average_precision_score(yd[ok], oof[ok])), 4),
                   "roc_auc": round(float(roc_auc_score(yd[ok], oof[ok])), 4)}
            cv.append(row)
            oof_by_cfg[f"{fs}/{kind}"] = np.where(ok, oof, 0.0)
            log.info("CV %-14s %-5s segAP %.4f  AP %.4f  AUC %.4f", fs, kind, row["segment_balanced_average_precision"], row["average_precision"], row["roc_auc"])
    best = max(cv, key=lambda r: r["segment_balanced_average_precision"])
    base_key, best_key = f"v1_67/{'rf6' if 'rf6' in kinds else kinds[0]}", f"{best['feature_set']}/{best['model']}"
    if base_key not in oof_by_cfg:                    # a restricted feature-set list without the shipped one: compare against the first config
        base_key = next(iter(oof_by_cfg))

    # alarm rules and thresholds chosen on out-of-fold dev scores only
    rules: Dict[str, Any] = {}
    for b in budgets:
        rules[str(b)] = {"baseline": {"k": 1, "m": 1, "threshold": threshold_for_budget(oof_by_cfg[base_key], ed, yd, 1, 1, b), "budget": b},
                         "selected": best_alarm_rule(oof_by_cfg[best_key], ed, yd, sd, b),
                         "selected_without_persistence": {"k": 1, "m": 1, "threshold": threshold_for_budget(oof_by_cfg[best_key], ed, yd, 1, 1, b), "budget": b}}

    # TEST: exactly two refits (baseline, selected), each fitted on ALL dev windows
    final: Dict[str, Any] = {}
    for label, key in (("baseline", base_key), ("selected", best_key)):
        fs, kind = key.split("/")
        sc, rs = fit_fold(fs, kind, Xd87, Xdl, yd, sd, seed, 80 if quick else 150)
        final[label] = (fs, kind, sc, rs, predict(fs, sc, rs, X87[test], XL[test]))
    yt, st, et = y[test], seg[test], ep[test]
    test_res: Dict[str, Any] = {"windows": int(test.size), "attack_windows": int(yt.sum()), "benign_hours": round(benign_hours(et, yt), 2)}
    for b in budgets:
        per: Dict[str, Any] = {}
        for label, rule_key in (("baseline", "baseline"), ("selected_without_persistence", "selected_without_persistence"), ("selected", "selected")):
            r = rules[str(b)][rule_key]
            if not r or r.get("threshold") is None:
                per[label] = {"status": "no threshold met the budget on the dev out-of-fold scores"}
                continue
            sc_arr = final["baseline" if label == "baseline" else "selected"][4]
            flag = persist(sc_arr > r["threshold"], et, r["k"], r["m"])
            per[label] = {"rule": {"k": r["k"], "m": r["m"], "threshold": round(r["threshold"], 4)}, **evaluate_alarm(sc_arr, flag, yt, st, et)}
        test_res[str(b)] = per
    return {"windows": {"dev": int(dev.size), "test": int(test.size)}, "folds": folds, "cv": cv, "selected": best, "alarm_rules": rules, "test": test_res,
            "feature_names": feature_names(best["feature_set"]), "seconds": round(time.time() - t_start, 1)}, final, norm


def render(res: Dict[str, Any], fixture: bool) -> str:
    L = ["# Physical model v2 - experiment report (CANDIDATE, not promoted)", ""]
    if fixture:
        L += ["**SYNTHETIC FIXTURE: code-path check only. The numbers below are meaningless; never cite them.**", ""]
    L += ["Changes versus the shipped model: (1) fit on train + validation, (2) 120 s long-context features and cross-sensor consistency residuals, "
          "(3) segment-grouped cross-validation with SEGMENT-BALANCED average precision for selection, (4) 'k of the last m windows' persistence with a "
          "false-alarm-budget threshold. Everything is chosen on out-of-fold dev scores. **The test block is used for exactly two refits and looks "
          "(baseline and selected); it was already seen by the shipped model's revised protocol, so this is held-out, not blind.**", "",
          f"Windows with a full 120 s history: dev (train+val) {res['windows']['dev']:,}, test {res['windows']['test']:,}. Folds: {res['folds']}. Run time {res['seconds']} s.", "",
          "## Cross-validation on train + validation (out-of-fold)", "", "| features | model | segment-balanced AP | AP | ROC-AUC |", "|---|---|---|---|---|"]
    for r in sorted(res["cv"], key=lambda r: -r["segment_balanced_average_precision"]):
        mark = " **(selected)**" if (r["feature_set"], r["model"]) == (res["selected"]["feature_set"], res["selected"]["model"]) else ""
        L.append(f"| {r['feature_set']} | {r['model']}{mark} | {r['segment_balanced_average_precision']} | {r['average_precision']} | {r['roc_auc']} |")
    L += ["", "Feature sets: " + "; ".join(f"`{k}` = {v}" for k, v in FEATURE_SETS.items()) + ". Models: rf6 = random forest depth 6, rf10 = depth 10, hgb = gradient boosting.", "",
          "## Alarm rules chosen on dev (out-of-fold)", "", "| budget (episodes per benign hour) | rule | k | m | threshold | dev segment-balanced recall |", "|---|---|---|---|---|---|"]
    for b, d in res["alarm_rules"].items():
        for name in ("baseline", "selected_without_persistence", "selected"):
            r = d[name]
            if r and r.get("threshold") is not None:
                L.append(f"| {b} | {name} | {r['k']} | {r['m']} | {r['threshold']:.4f} | {('%.3f' % r['segment_balanced_recall']) if 'segment_balanced_recall' in r else 'n/a'} |")
    t = res["test"]
    L += ["", "## Held-out TEST block (1-2 Jan)", "", f"{t['windows']:,} windows, {t['attack_windows']:,} attack windows, {t['benign_hours']} benign hours.", ""]
    for b in res["alarm_rules"]:
        L += [f"### False-alarm budget {b} per benign hour (chosen on dev)", "",
              "| variant | precision | recall | F1 | accuracy | balanced acc. | FP rate | false-alarm episodes / h | segments detected | median latency (s) | ROC-AUC | TN / FP / FN / TP |",
              "|---|---|---|---|---|---|---|---|---|---|---|---|"]
        for name, label in (("baseline", "refit baseline (v1 features, rf6, no persistence)"), ("selected_without_persistence", "selected features, no persistence"),
                            ("selected", "selected features + persistence")):
            r = t[b].get(name, {})
            if "precision" not in r:
                L.append(f"| {label} | {r.get('status', 'n/a')} |||||||||||")
                continue
            L.append(f"| {label} | {r['precision']} | {r['recall']} | {r['f1']} | {r['accuracy']} | {r['balanced_accuracy']} | {r['false_positive_rate']} | "
                     f"{r['alarm_episodes_per_benign_hour']} | {r['segments_detected']}/{r['segments_total']} | {r['median_latency_s']} | {r.get('roc_auc')} | "
                     f"{r['tn']:,} / {r['fp']:,} / {r['fn']:,} / {r['tp']:,} |")
        L.append("")
    L += ["The shipped model for reference (held-out test, same block): precision 0.366, recall 0.263, F1 0.306, accuracy 0.955, 1.79 false-alarm episodes per hour, "
          "6/10 segments, ROC-AUC 0.8245 (`benchmarks/swat_accuracy.json`; its window set differs slightly because v2 windows need a 120 s history).", "",
          "Plain accuracy is not the headline: attacks are a few percent of windows, so 'never flag' scores about 0.96. Judge by F1, recall at the false-alarm rate, and segments detected.", ""]
    return "\n".join(L)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s - %(message)s")
    ap = argparse.ArgumentParser(description="Physical model v2 experiment (candidate only).")
    ap.add_argument("--data-dir")
    ap.add_argument("--fixture", action="store_true")
    ap.add_argument("--candidate", action="store_true", help="required acknowledgement: output is a candidate")
    ap.add_argument("--out-dir", default=DEFAULT_OUT)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--quick", action="store_true", help="fewer trees and models (fixture / smoke test)")
    a = ap.parse_args()
    if not a.candidate:
        raise SystemExit("pass --candidate: this script only writes candidates")
    out_real = os.path.realpath(a.out_dir)
    if out_real == WEIGHTS_DIR or out_real.startswith(WEIGHTS_DIR + os.sep):
        raise SystemExit("refusing to write into models/weights")
    if a.fixture:
        from tests.swat_fixture import make_swat_archive
        d = tempfile.mkdtemp(prefix="swat-fixture-")
        make_swat_archive(d, seed=0)
    elif a.data_dir:
        d = a.data_dir
    else:
        ap.error("give --data-dir or --fixture")
    stream, _ = load_stream(d, SENSORS + ACTUATORS)
    res, final, norm = run(stream, a.seed, a.folds, a.quick or a.fixture)
    res["fixture_not_real_results"] = bool(a.fixture)
    os.makedirs(a.out_dir, exist_ok=True)
    import joblib
    fs, kind, sc, rs, _ = final["selected"]
    joblib.dump({"feature_set": fs, "model_kind": kind, "scorer": sc.model, "residual": rs, "norm_stats": {"mu": norm.mu, "sd": norm.sd, "lo": norm.lo, "hi": norm.hi},
                 "alarm_rules": res["alarm_rules"], "feature_names": res["feature_names"], "fixture": bool(a.fixture),
                 "note": "RESEARCH CANDIDATE: needs the live model extended to a 120 s history before it can run live"}, os.path.join(a.out_dir, "physical_v2_candidate.joblib"))
    with open(os.path.join(a.out_dir, "physical_v2_report.json"), "w") as fh:
        json.dump(res, fh, indent=2, default=float)
    txt = render(res, bool(a.fixture))
    with open(os.path.join(a.out_dir, "physical_v2_report.md"), "w") as fh:
        fh.write(txt)
    print(txt)
    print(f"\nWrote {a.out_dir} (models/weights untouched). Paste physical_v2_report.md back for review.")


if __name__ == "__main__":
    main()
