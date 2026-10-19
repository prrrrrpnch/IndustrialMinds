"""
models/train_physical_v3.py - physical model v3 (CANDIDATE trainer; writes only models/candidates/physical_v3/).

    python -m models.train_physical_v3 --data-dir "C:\\IndustrialMind\\SWaT_dataset\\archive" --candidate
    python -m models.train_physical_v3 --fixture --candidate --quick        # synthetic SWaT-SHAPED data, code-path check only

WHAT IS NEW versus the live v2 model (each recipe is cross-validated and scored separately; the report shows all of them):
  1. FEATURES (swat/features_v3.py): multi-scale dynamics, no absolute levels, "seconds since last toggle", and NORMAL-ONLY models as
     features - a ridge consistency model and a PCA process monitor (Hotelling T2 / SPE, also per stage).
  2. CROSS-FITTED normal models: a training window's consistency/PCA features come from a model that never saw its hour, exactly like
     the test block's do. (v2 fitted them in-sample on the training windows: optimistic residuals the classifier then trusted.)
  3. PER-STAGE heads + a STACKER: one gradient-boosted head per treatment stage (its own sensors/actuators, its residuals, its SPE)
     plus global heads, combined by a small logistic regression fitted on out-of-fold scores.
  4. HONEST EVIDENCE built in: segment-grouped CV, the same calendar split as v2 (train+val fit, test looked at exactly twice),
     strict window metrics AND event metrics, bootstrap confidence intervals over attack segments / benign hours, confusion-matrix and
     precision-recall figures, and a promotion checklist.

PROTOCOL. Everything is chosen on train + validation only (out-of-fold). The TEST block is used for exactly two fits-and-looks: the
v2 recipe refit on the same windows (baseline) and the selected v3 recipe. It was already seen by earlier models, so this is held-out,
not blind (the report says so). Nothing is promoted by this script.
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

from models import train_physical_v2 as V2
from swat import features_v3 as F3
from swat.alarm_logic import benign_hours, best_alarm_rule, persist, threshold_for_budget
from swat.fusion_scenarios import fold_ids
from swat.loader import load_stream
from swat.physical_features import ACTUATORS, SENSORS, Norm, compute_bounds

log = logging.getLogger("industrialmind.train_physical_v3")
HERE = os.path.dirname(os.path.abspath(__file__))
WEIGHTS_DIR = os.path.realpath(os.path.join(HERE, "weights"))
DEFAULT_OUT = os.path.join(HERE, "candidates", "physical_v3")
BUDGETS = (0.25, 0.5, 1.0, 2.0, 4.0)
HEADLINE_BUDGET = 0.5
EPISODE_GAP_S = 30.0
RECOVERY_TOLERANCE_S = 300.0

# ----------------------------------------------------------------------------- heads and recipes
HEADS: Dict[str, Dict[str, Any]] = {
    "g_lv_d3": {"variant": "lv", "stage": None, "depth": 3},     # global head, normal models with level regressors
    "g_nl_d3": {"variant": "nl", "stage": None, "depth": 3},     # global head, drift-robust normal models (no levels)
    "g_nl_d5": {"variant": "nl", "stage": None, "depth": 5},
    **{f"s{s}_nl": {"variant": "nl", "stage": s, "depth": 3} for s in F3.STAGE_IDS},
}
STAGE_HEADS = [f"s{s}_nl" for s in F3.STAGE_IDS]
RECIPES: Dict[str, Optional[List[str]]] = {
    "v2ref": None,                                              # the live v2 recipe (v1_long_resid + HGB), refit on the same windows
    "g_lv_d3": ["g_lv_d3"],
    "g_nl_d3": ["g_nl_d3"],
    "g_nl_d5": ["g_nl_d5"],
    "stack_nl": ["g_nl_d3"] + STAGE_HEADS,
    "stack_all": ["g_lv_d3", "g_nl_d3", "g_nl_d5"] + STAGE_HEADS,
}
QUICK_RECIPES = ["v2ref", "g_nl_d3", "stack_nl"]
RECIPE_TEXT = {
    "v2ref": "v2 recipe (v1_long_resid features, one HGB), refit here",
    "g_lv_d3": "v3 features, global HGB depth 3, normal models WITH level regressors",
    "g_nl_d3": "v3 features, global HGB depth 3, drift-robust normal models (no levels)",
    "g_nl_d5": "v3 features, global HGB depth 5, drift-robust normal models",
    "stack_nl": "global head + 5 per-stage heads, drift-robust, stacked (logistic regression)",
    "stack_all": "3 global heads + 5 per-stage heads, stacked (logistic regression)",
}


def expand_by_weight(w: np.ndarray, seed: int) -> np.ndarray:
    """Row indices that reproduce `sample_weight` WITHOUT passing it: each row is repeated floor(w) times, plus once more with probability
    frac(w), so the weighted loss is matched in expectation. Why: in the pinned scikit-learn, HistGradientBoostingClassifier is ~70x slower
    whenever ANY sample_weight is given (even all ones), which made the v2 training run take 13 minutes."""
    w = np.asarray(w, dtype=np.float64)
    base = np.floor(w).astype(np.int64)
    reps = base + (np.random.default_rng(seed).random(len(w)) < (w - base))
    return np.repeat(np.arange(len(w)), reps)


def fit_head(X: np.ndarray, y: np.ndarray, w: np.ndarray, depth: int, iters: int, seed: int):
    from sklearn.ensemble import HistGradientBoostingClassifier
    idx = expand_by_weight(w, seed)
    return HistGradientBoostingClassifier(max_depth=depth, max_iter=max(40, iters), learning_rate=0.05, l2_regularization=10.0,
                                          min_samples_leaf=100 if depth <= 3 else 200, random_state=seed).fit(X[idx], y[idx])


def fit_v2ref(X87: np.ndarray, XL: np.ndarray, y: np.ndarray, seg: np.ndarray, seed: int, iters: int):
    """The live v2 recipe (v1_long_resid features + one HGB depth 3), trained by the SAME weighting mechanism as the v3 heads so the
    comparison is fair. The consistency model sees ALL normal windows, as in v2."""
    from swat.features_v2 import ResidualModel, assemble as assemble_v2
    resid = ResidualModel().fit(X87[y == 0])
    keep = subsample(y, seed)
    X = assemble_v2("v1_long_resid", X87[keep], XL[keep], resid)
    return fit_head(X, y[keep], V2.training_weights(y[keep], seg[keep]), 3, iters, seed), resid


def predict_v2ref(model, resid, X87: np.ndarray, XL: np.ndarray) -> np.ndarray:
    from swat.features_v2 import assemble as assemble_v2
    return model.predict_proba(assemble_v2("v1_long_resid", X87, XL, resid))[:, 1]


def head_cols(name: str) -> np.ndarray:
    st = HEADS[name]["stage"]
    return np.arange(len(F3.FEATURE_NAMES)) if st is None else F3.stage_view(st)


def subsample(y: np.ndarray, seed: int, cap: int = V2.MAX_BENIGN_FIT) -> np.ndarray:
    ben = np.flatnonzero(y == 0)
    if ben.size <= cap:
        return np.arange(len(y))
    keep = np.concatenate([np.flatnonzero(y == 1), np.random.default_rng(seed).choice(ben, cap, replace=False)])
    keep.sort()
    return keep


def make_design(X3: np.ndarray, AUX: np.ndarray, y: np.ndarray, ep: np.ndarray, variant: str) -> Tuple[np.ndarray, F3.NormalModels]:
    """Classifier inputs for a TRAINING set (cross-fitted normal-model features) and the model that scores new data."""
    F, nm = F3.crossfit_normal_features(AUX, y, ep, use_levels=(variant == "lv"))
    return F3.assemble(X3, F), nm


def design_for(X3: np.ndarray, AUX: np.ndarray, nm: F3.NormalModels) -> np.ndarray:
    return F3.assemble(X3, nm.transform(AUX))


# ----------------------------------------------------------------------------- stacker
class Stacker:
    """Logistic regression on the heads' logits (+ their max). Inference is plain NumPy (swat.features_v3.stack_*)."""

    def __init__(self, heads: List[str]) -> None:
        self.heads, self.w, self.b = list(heads), None, 0.0

    def inputs(self, scores: Dict[str, np.ndarray]) -> np.ndarray:
        return F3.stack_inputs(np.stack([scores[h] for h in self.heads], axis=1))

    def fit(self, scores: Dict[str, np.ndarray], y: np.ndarray, w: np.ndarray) -> "Stacker":
        from sklearn.linear_model import LogisticRegression
        lr = LogisticRegression(C=1.0, max_iter=1000).fit(self.inputs(scores), y, sample_weight=w)
        self.w, self.b = lr.coef_[0].astype(np.float64), float(lr.intercept_[0])
        return self

    def predict(self, scores: Dict[str, np.ndarray]) -> np.ndarray:
        return F3.stack_predict(self.inputs(scores), self.w, self.b)


# ----------------------------------------------------------------------------- cross-validation
def cv_oof(D: Dict[str, np.ndarray], dev: np.ndarray, fold: np.ndarray, folds: int, seed: int, iters: int,
           head_names: List[str], include_v2ref: bool) -> Dict[str, np.ndarray]:
    """Out-of-fold scores on train+val for every needed head (and the v2 recipe). Normal-model features are cross-fitted INSIDE each fold."""
    yd, sd, ed = D["y"][dev], D["seg"][dev], D["ep"][dev]
    X87, XL, X3, AUX = D["X87"][dev], D["XL"][dev], D["X3"][dev], D["AUX"][dev]
    oof = {n: np.full(len(dev), np.nan) for n in head_names + (["v2ref"] if include_v2ref else [])}
    variants = sorted({HEADS[h]["variant"] for h in head_names})
    for f in range(folds):
        t0 = time.time()
        hold, fit = np.flatnonzero(fold == f), np.flatnonzero(fold != f)
        if hold.size == 0 or yd[fit].sum() < 3:
            continue
        if include_v2ref:
            m2, rs = fit_v2ref(X87[fit], XL[fit], yd[fit], sd[fit], seed, iters)
            oof["v2ref"][hold] = predict_v2ref(m2, rs, X87[hold], XL[hold])
        for variant in variants:
            design_fit, nm = make_design(X3[fit], AUX[fit], yd[fit], ed[fit], variant)
            design_hold = design_for(X3[hold], AUX[hold], nm)
            keep = subsample(yd[fit], seed)
            wk = V2.training_weights(yd[fit][keep], sd[fit][keep])
            for h in [h for h in head_names if HEADS[h]["variant"] == variant]:
                cols = head_cols(h)
                m = fit_head(design_fit[keep][:, cols], yd[fit][keep], wk, HEADS[h]["depth"], iters, seed)
                oof[h][hold] = m.predict_proba(design_hold[:, cols])[:, 1]
        log.info("CV fold %d/%d done in %.0f s", f + 1, folds, time.time() - t0)
    return oof


def stack_oof(heads: List[str], oof: Dict[str, np.ndarray], y: np.ndarray, seg: np.ndarray, fold: np.ndarray, folds: int) -> np.ndarray:
    """Second-level out-of-fold scores of the stacker (fitted on the other folds' out-of-fold head scores)."""
    out = np.full(len(y), np.nan)
    for f in range(folds):
        hold, fit = fold == f, fold != f
        if hold.sum() == 0 or y[fit].sum() < 3:
            continue
        st = Stacker(heads).fit({h: np.nan_to_num(oof[h][fit]) for h in heads}, y[fit], V2.training_weights(y[fit], seg[fit]))
        out[hold] = st.predict({h: np.nan_to_num(oof[h][hold]) for h in heads})
    return out


# ----------------------------------------------------------------------------- event-level metrics and confidence intervals
def _segments(y: np.ndarray, seg: np.ndarray, epoch: np.ndarray) -> List[Tuple[float, float]]:
    return [(float(epoch[(seg == s) & y].min()), float(epoch[(seg == s) & y].max())) for s in np.unique(seg[y])]


def event_metrics(flag: np.ndarray, y: np.ndarray, seg: np.ndarray, epoch: np.ndarray, tol_s: float) -> Dict[str, Any]:
    """Alarm EPISODES (flags closer than 30 s merged) scored against the labelled attack intervals, with `tol_s` seconds of tolerance after an
    interval ends (tol 0 = strict; 300 s = 'recovery-tolerant': the plant is still displaced right after an attack, so an alarm there is not
    a false alarm in operation). Event recall = share of attack segments with an alarm inside them (+ tolerance)."""
    y = np.asarray(y, bool)
    segs = _segments(y, seg, epoch)
    t = np.sort(epoch[flag])
    if t.size == 0:
        return {"episodes": 0, "tp_episodes": 0, "episode_precision": None, "segments_detected": 0, "segments": len(segs),
                "event_recall": 0.0, "event_f1": None}
    cut = np.diff(t) > EPISODE_GAP_S
    starts, ends = t[np.r_[True, cut]], t[np.r_[cut, True]]
    tp = sum(any(not (e < a or s > b + tol_s) for a, b in segs) for s, e in zip(starts, ends))
    det = sum(bool(((t >= a) & (t <= b + tol_s)).any()) for a, b in segs)
    prec, rec = tp / len(starts), (det / len(segs) if segs else 0.0)
    f1 = 2 * prec * rec / (prec + rec) if prec + rec > 0 else 0.0
    return {"episodes": int(len(starts)), "tp_episodes": int(tp), "episode_precision": round(prec, 4), "segments_detected": int(det),
            "segments": len(segs), "event_recall": round(rec, 4), "event_f1": round(f1, 4)}


def bootstrap_ci(flag: np.ndarray, y: np.ndarray, seg: np.ndarray, epoch: np.ndarray, B: int = 1000, seed: int = 0) -> Dict[str, List[float]]:
    """95% intervals for window-level precision/recall/F1/FPR/balanced accuracy, resampling whole ATTACK SEGMENTS and whole benign HOURS
    (windows inside one are nearly identical, so resampling single windows would be far too optimistic)."""
    y, flag = np.asarray(y, bool), np.asarray(flag, bool)
    rng = np.random.default_rng(seed)
    segs = np.unique(seg[y])
    tp = np.array([(flag & (seg == s) & y).sum() for s in segs], float)
    fn = np.array([(~flag & (seg == s) & y).sum() for s in segs], float)
    hrs = (epoch // 3600).astype(np.int64)
    uh = np.unique(hrs[~y])
    fp = np.array([(flag & ~y & (hrs == h)).sum() for h in uh], float)
    tn = np.array([(~flag & ~y & (hrs == h)).sum() for h in uh], float)
    ia, ib = rng.integers(0, len(segs), (B, len(segs))), rng.integers(0, len(uh), (B, len(uh)))
    TP, FN, FP, TN = tp[ia].sum(1), fn[ia].sum(1), fp[ib].sum(1), tn[ib].sum(1)
    with np.errstate(divide="ignore", invalid="ignore"):
        P, R = TP / (TP + FP), TP / (TP + FN)
        F = 2 * P * R / (P + R)
        spec = TN / (TN + FP)
    out = {"precision": P, "recall": R, "f1": F, "false_positive_rate": 1 - spec, "balanced_accuracy": (R + spec) / 2}
    def interval(v: np.ndarray) -> Optional[List[float]]:
        v = v[~np.isnan(v)]                                   # undefined draws (nothing flagged) are skipped; all undefined -> no interval
        return [round(float(np.percentile(v, 2.5)), 4), round(float(np.percentile(v, 97.5)), 4)] if v.size else None
    return {k: interval(v) for k, v in out.items()}


def evaluate_full(score: np.ndarray, flag: np.ndarray, y: np.ndarray, seg: np.ndarray, epoch: np.ndarray) -> Dict[str, Any]:
    res = V2.evaluate_alarm(score, flag, y, seg, epoch)
    res["event_strict"] = event_metrics(flag, np.asarray(y, bool), seg, epoch, 0.0)
    res["event_recovery_tolerant"] = event_metrics(flag, np.asarray(y, bool), seg, epoch, RECOVERY_TOLERANCE_S)
    res["bootstrap_95ci"] = bootstrap_ci(flag, y, seg, epoch)
    return res


# ----------------------------------------------------------------------------- the experiment
def run(stream, seed: int, folds: int, quick: bool, budgets: Tuple[float, ...] = BUDGETS,
        recipes: Optional[List[str]] = None) -> Tuple[Dict[str, Any], Dict[str, Any], Norm, Dict[str, Any]]:
    from sklearn.metrics import average_precision_score, roc_auc_score
    t_start = time.time()
    train_norm = stream[(stream["block"] == "train") & ~stream["label"]]
    if len(train_norm) < 2000:
        raise SystemExit("too few train-block normal rows to measure bounds")
    norm = Norm(compute_bounds(train_norm[SENSORS]))
    X87, XL, X3, AUX, meta = F3.build_windows_v3(stream, norm)
    y, seg, ep, blk = meta["label"].to_numpy().astype(int), meta["seg"].to_numpy(), meta["epoch"].to_numpy(), meta["block"].to_numpy()
    D = {"X87": X87, "XL": XL, "X3": X3, "AUX": AUX, "y": y, "seg": seg, "ep": ep}
    dev, test = np.flatnonzero(np.isin(blk, ["train", "val"])), np.flatnonzero(blk == "test")
    if dev.size == 0 or test.size == 0 or y[dev].sum() < 5 or y[test].sum() == 0:
        raise SystemExit("need windows (with attacks) in train+val and in test")
    log.info("windows with a full 120 s history: dev %d (attack %d, segments %d), test %d (attack %d, segments %d)", dev.size, y[dev].sum(),
             len(np.unique(seg[dev][y[dev] == 1])), test.size, y[test].sum(), len(np.unique(seg[test][y[test] == 1])))
    fold = fold_ids(meta.iloc[dev].reset_index(drop=True), folds)
    yd, sd, ed = y[dev], seg[dev], ep[dev]
    esw = V2.segment_balanced_weights(yd, sd)
    iters_cv, iters_final = (60, 80) if quick else (100, 150)

    recipes = recipes or (QUICK_RECIPES if quick else list(RECIPES))
    unknown = [r for r in recipes if r not in RECIPES]
    if unknown:
        raise SystemExit(f"unknown recipes {unknown}; known: {list(RECIPES)}")
    if "v2ref" not in recipes:
        recipes = ["v2ref"] + recipes                          # the baseline is always measured
    head_names = sorted({h for r in recipes if RECIPES[r] for h in RECIPES[r]})
    oof_heads = cv_oof(D, dev, fold, folds, seed, iters_cv, head_names, include_v2ref=True)

    cv: List[Dict[str, Any]] = []
    oof_by: Dict[str, np.ndarray] = {}
    for r in recipes:
        oof = oof_heads["v2ref"] if r == "v2ref" else (oof_heads[RECIPES[r][0]] if len(RECIPES[r]) == 1 else stack_oof(RECIPES[r], oof_heads, yd, sd, fold, folds))
        ok = ~np.isnan(oof)
        row = {"recipe": r, "description": RECIPE_TEXT[r], "oof_windows": int(ok.sum()),
               "segment_balanced_average_precision": round(float(average_precision_score(yd[ok], oof[ok], sample_weight=esw[ok])), 4),
               "average_precision": round(float(average_precision_score(yd[ok], oof[ok])), 4), "roc_auc": round(float(roc_auc_score(yd[ok], oof[ok])), 4)}
        cv.append(row)
        oof_by[r] = np.where(ok, oof, 0.0)
        log.info("CV %-10s segAP %.4f  AP %.4f  AUC %.4f", r, row["segment_balanced_average_precision"], row["average_precision"], row["roc_auc"])
    best = max((c for c in cv if c["recipe"] != "v2ref"), key=lambda c: c["segment_balanced_average_precision"], default=None)
    if best is None:
        raise SystemExit("no v3 recipe was evaluated")
    sel = best["recipe"]

    rules: Dict[str, Any] = {}
    for b in budgets:
        rules[str(b)] = {"baseline": {"k": 1, "m": 1, "threshold": threshold_for_budget(oof_by["v2ref"], ed, yd, 1, 1, b), "budget": b},
                         "selected_without_persistence": {"k": 1, "m": 1, "threshold": threshold_for_budget(oof_by[sel], ed, yd, 1, 1, b), "budget": b},
                         "selected": best_alarm_rule(oof_by[sel], ed, yd, sd, b)}

    # ---- TEST: exactly two fits (v2 recipe, selected v3 recipe), each on ALL dev windows
    m2, rs2 = fit_v2ref(X87[dev], XL[dev], yd, sd, seed, iters_final)
    test_v2 = predict_v2ref(m2, rs2, X87[test], XL[test])
    heads_sel = RECIPES[sel]
    variants = sorted({HEADS[h]["variant"] for h in heads_sel})
    nms: Dict[str, Any] = {}
    models: Dict[str, Any] = {}
    head_scores_test: Dict[str, np.ndarray] = {}
    for variant in variants:
        design_dev, nm = make_design(X3[dev], AUX[dev], yd, ed, variant)
        nms[variant] = nm
        design_test = design_for(X3[test], AUX[test], nm)
        keep = subsample(yd, seed)
        wk = V2.training_weights(yd[keep], sd[keep])
        for h in [h for h in heads_sel if HEADS[h]["variant"] == variant]:
            cols = head_cols(h)
            models[h] = fit_head(design_dev[keep][:, cols], yd[keep], wk, HEADS[h]["depth"], iters_final, seed)
            head_scores_test[h] = models[h].predict_proba(design_test[:, cols])[:, 1]
        del design_dev
    stacker = None
    if len(heads_sel) == 1:
        test_v3 = head_scores_test[heads_sel[0]]
    else:
        stacker = Stacker(heads_sel).fit({h: np.nan_to_num(oof_heads[h]) for h in heads_sel}, yd, V2.training_weights(yd, sd))
        test_v3 = stacker.predict(head_scores_test)

    yt, st, et = y[test], seg[test], ep[test]
    test_res: Dict[str, Any] = {"windows": int(test.size), "attack_windows": int(yt.sum()), "benign_hours": round(benign_hours(et, yt), 2)}
    for b in budgets:
        per: Dict[str, Any] = {}
        for label, key, scores in (("baseline", "baseline", test_v2), ("selected_without_persistence", "selected_without_persistence", test_v3),
                                   ("selected", "selected", test_v3)):
            r = rules[str(b)][key]
            if not r or r.get("threshold") is None:
                per[label] = {"status": "no threshold met the budget on the dev out-of-fold scores"}
                continue
            flag = persist(scores > r["threshold"], et, r["k"], r["m"])
            per[label] = {"rule": {"k": r["k"], "m": r["m"], "threshold": round(r["threshold"], 4)}, **evaluate_full(scores, flag, yt, st, et)}
        test_res[str(b)] = per

    head_importance_note = {h: int(models[h].n_iter_) for h in heads_sel}
    headline = str(HEADLINE_BUDGET) if HEADLINE_BUDGET in budgets else str(budgets[0])
    res = {"windows": {"dev": int(dev.size), "test": int(test.size)}, "folds": folds, "quick": bool(quick), "headline_budget": headline, "cv": cv, "selected_recipe": sel,
           "selected": best, "alarm_rules": rules, "test": test_res, "head_iterations": head_importance_note,
           "feature_names": F3.FEATURE_NAMES, "seconds": round(time.time() - t_start, 1)}
    final = {"recipe": sel, "heads": models, "normal_models": nms, "stacker": stacker, "stack_heads": heads_sel}
    arrays = {"y": yt, "seg": st, "epoch": et, "score_v2": test_v2, "score_v3": test_v3, "rules": rules}
    return res, final, norm, arrays


# ----------------------------------------------------------------------------- report and figures
def _row(label: str, r: Dict[str, Any]) -> str:
    if "precision" not in r:
        return f"| {label} | {r.get('status', 'n/a')} |||||||||||"
    return (f"| {label} | {r['precision']} | {r['recall']} | {r['f1']} | {r['accuracy']} | {r['balanced_accuracy']} | {r['false_positive_rate']} | "
            f"{r['alarm_episodes_per_benign_hour']} | {r['segments_detected']}/{r['segments_total']} | {r['median_latency_s']} | {r.get('roc_auc')} | "
            f"{r['tn']:,} / {r['fp']:,} / {r['fn']:,} / {r['tp']:,} |")


def promotion_checklist(res: Dict[str, Any]) -> List[Tuple[str, Optional[bool], str]]:
    b = res.get("headline_budget", str(HEADLINE_BUDGET))
    base, sel = res["test"][b]["baseline"], res["test"][b]["selected_without_persistence"]
    cvb = next(c for c in res["cv"] if c["recipe"] == "v2ref")
    items: List[Tuple[str, Optional[bool], str]] = []
    items.append(("CV segment-balanced AP beats the v2 recipe by at least 0.02", res["selected"]["segment_balanced_average_precision"] >= cvb["segment_balanced_average_precision"] + 0.02,
                  f"{res['selected']['segment_balanced_average_precision']} vs {cvb['segment_balanced_average_precision']}"))
    if "f1" in base and "f1" in sel:
        items.append((f"held-out test F1 at {b} false alarms/h is at least the v2 recipe's", (sel["f1"] or 0.0) >= (base["f1"] or 0.0), f"{sel['f1']} vs {base['f1']}"))
        items.append(("held-out test detects at least as many attack segments", sel["segments_detected"] >= base["segments_detected"], f"{sel['segments_detected']} vs {base['segments_detected']}"))
        items.append(("held-out test false-alarm episodes per hour no worse than 1.5x the budget", sel["alarm_episodes_per_benign_hour"] <= 1.5 * float(b),
                      f"{sel['alarm_episodes_per_benign_hour']} per hour"))
    items.append(("healthy-twin false alarms acceptable (run tools/twin_domain_gap.py on the packaged candidate)", None, "not measurable in this script"))
    return items


def render(res: Dict[str, Any], fixture: bool) -> str:
    L = ["# Physical model v3 - candidate report (NOT promoted)", ""]
    if fixture:
        L += ["**SYNTHETIC FIXTURE: code-path check only. The numbers below are meaningless; never cite them.**", ""]
    L += ["What is new versus the live v2 model: multi-scale features without absolute levels; cross-fitted normal-only consistency and PCA (T2 / SPE) "
          "features; per-stage heads combined by a stacker. Everything is chosen on out-of-fold train + validation scores. **The test block is used for "
          "exactly two fits and looks (the v2 recipe refit on the same windows, and the selected v3 recipe); earlier models also saw it, so this is "
          "held-out, not blind.**", "",
          f"Windows with a full 120 s history: dev (train+val) {res['windows']['dev']:,}, test {res['windows']['test']:,}. Folds: {res['folds']}. Run time {res['seconds']} s.", "",
          "## Cross-validation on train + validation (out-of-fold)", "", "| recipe | what | segment-balanced AP | AP | ROC-AUC |", "|---|---|---|---|---|"]
    for r in sorted(res["cv"], key=lambda r: -r["segment_balanced_average_precision"]):
        mark = " **(selected)**" if r["recipe"] == res["selected_recipe"] else ""
        L.append(f"| {r['recipe']}{mark} | {r['description']} | {r['segment_balanced_average_precision']} | {r['average_precision']} | {r['roc_auc']} |")
    L += ["", "Segment-balanced AP counts every attack segment equally, so the 10-hour segment cannot dominate the choice.", "",
          "## Alarm thresholds chosen on dev (out-of-fold)", "", "| budget (episodes per benign hour) | rule | k | m | threshold |", "|---|---|---|---|---|"]
    for b, d in res["alarm_rules"].items():
        for name in ("baseline", "selected_without_persistence", "selected"):
            r = d[name]
            if r and r.get("threshold") is not None:
                L.append(f"| {b} | {name} | {r['k']} | {r['m']} | {r['threshold']:.4f} |")
    t = res["test"]
    L += ["", "## Held-out TEST block (1-2 Jan)", "", f"{t['windows']:,} windows, {t['attack_windows']:,} attack windows, {t['benign_hours']} benign hours. Window-level numbers are STRICT: "
          "the labelled attack seconds are the only positives.", ""]
    for b in res["alarm_rules"]:
        L += [f"### False-alarm budget {b} per benign hour (threshold chosen on dev)", "",
              "| variant | precision | recall | F1 | accuracy | balanced acc. | FP rate | false-alarm episodes / h | segments detected | median latency (s) | ROC-AUC | TN / FP / FN / TP |",
              "|---|---|---|---|---|---|---|---|---|---|---|---|",
              _row("v2 recipe, refit (baseline)", t[b].get("baseline", {})),
              _row(f"v3 selected ({res['selected_recipe']})", t[b].get("selected_without_persistence", {})),
              _row(f"v3 selected + persistence", t[b].get("selected", {})), ""]
    hb = res.get("headline_budget", str(HEADLINE_BUDGET))
    if hb in t:
        L += [f"## Headline operating point ({hb} false-alarm episodes per benign hour): event-level view and uncertainty", "",
              "Alarm EPISODES (flags closer than 30 s merged) scored against the labelled attack intervals. 'Strict' = the alarm must fall inside the labelled interval. "
              f"'Recovery-tolerant' also accepts an alarm up to {int(RECOVERY_TOLERANCE_S)} s after an interval ends, because the plant is still displaced then (SWaT labels the attack, "
              "not the aftermath).", "",
              "| variant | view | alarm episodes | episode precision | attack segments detected | event recall | event F1 |", "|---|---|---|---|---|---|---|"]
        for label, key in (("v2 recipe (baseline)", "baseline"), (f"v3 {res['selected_recipe']}", "selected_without_persistence")):
            r = t[hb].get(key, {})
            for view, name in (("strict", "event_strict"), ("recovery-tolerant", "event_recovery_tolerant")):
                e = r.get(name)
                if e:
                    L.append(f"| {label} | {view} | {e['episodes']} | {e['episode_precision']} | {e['segments_detected']}/{e['segments']} | {e['event_recall']} | {e['event_f1']} |")
        L += ["", "95% bootstrap intervals (resampling whole attack segments and whole benign hours), window level:", "",
              "| variant | precision | recall | F1 | false-positive rate | balanced accuracy |", "|---|---|---|---|---|---|"]
        for label, key in (("v2 recipe (baseline)", "baseline"), (f"v3 {res['selected_recipe']}", "selected_without_persistence")):
            ci = t[hb].get(key, {}).get("bootstrap_95ci")
            if ci:
                L.append(f"| {label} | " + " | ".join((f"{ci[m][0]} to {ci[m][1]}" if ci.get(m) else "n/a") for m in ("precision", "recall", "f1", "false_positive_rate", "balanced_accuracy")) + " |")
        L += ["", "With only a handful of held-out attack segments these intervals are wide: a difference smaller than the interval is not evidence of improvement.", ""]
    L += ["## Promotion checklist (nothing is promoted by this script)", ""]
    for text, ok, detail in promotion_checklist(res):
        L.append(f"- [{'x' if ok else ' '}] {text} ({detail})" if ok is not None else f"- [ ] {text} ({detail})")
    L += ["", "Reference (live v2, held-out test, same block): precision 0.461, recall 0.513, F1 0.485, 1.17 false-alarm episodes per hour, 8/10 segments, ROC-AUC 0.836.", "",
          "Plain accuracy is not the headline: attacks are a few percent of windows, so 'never flag' scores about 0.96. Judge by F1, balanced accuracy, recall at the false-alarm rate, "
          "episode precision and segments detected. Figures: `physical_v3_confusion.png`, `physical_v3_pr_curve.png`, `physical_v3_segments.png`.", ""]
    return "\n".join(L)


def render_figures(out_dir: str, arrays: Dict[str, Any], res: Dict[str, Any]) -> List[str]:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from sklearn.metrics import precision_recall_curve

    y, seg, ep = arrays["y"].astype(bool), arrays["seg"], arrays["epoch"]
    b = res.get("headline_budget", str(HEADLINE_BUDGET))
    paths: List[str] = []
    variants = [("v2 recipe (baseline)", arrays["score_v2"], arrays["rules"][b]["baseline"]),
                (f"v3 {res['selected_recipe']}", arrays["score_v3"], arrays["rules"][b]["selected_without_persistence"])]

    fig, axes = plt.subplots(1, 2, figsize=(10, 4.4))
    for ax, (name, score, rule) in zip(axes, variants):
        if not rule or rule.get("threshold") is None:
            ax.axis("off")
            ax.set_title(f"{name}: no threshold met the budget")
            continue
        flag = score > rule["threshold"]
        cm = np.array([[(~y & ~flag).sum(), (~y & flag).sum()], [(y & ~flag).sum(), (y & flag).sum()]], float)
        ax.imshow(cm / cm.sum(axis=1, keepdims=True), cmap="Blues", vmin=0, vmax=1)
        for i in range(2):
            for j in range(2):
                pct = 100 * cm[i, j] / cm[i].sum()
                ax.text(j, i, f"{int(cm[i, j]):,}\n({pct:.1f}% of row)", ha="center", va="center", color="white" if cm[i, j] / cm[i].sum() > 0.5 else "black", fontsize=9)
        ax.set_xticks([0, 1], ["no alarm", "alarm"])
        ax.set_yticks([0, 1], ["benign", "attack"])
        ax.set_xlabel("predicted")
        ax.set_ylabel("true (rows)")
        tp, fp, fn = cm[1, 1], cm[0, 1], cm[1, 0]
        p, r = tp / max(tp + fp, 1), tp / max(tp + fn, 1)
        ax.set_title(f"{name}\nP {p:.2f}  R {r:.2f}  F1 {2 * p * r / max(p + r, 1e-9):.2f}", fontsize=10)
    fig.suptitle(f"Held-out SWaT test block, {b} false-alarm episodes/h operating point (window level, strict labels)", fontsize=10)
    fig.tight_layout()
    paths.append(os.path.join(out_dir, "physical_v3_confusion.png"))
    fig.savefig(paths[-1], dpi=150)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(6, 4.4))
    for name, score, rule in variants:
        pr, rc, _ = precision_recall_curve(y, score)
        ax.plot(rc, pr, label=name)
        if rule and rule.get("threshold") is not None:
            fl = score > rule["threshold"]
            ax.scatter([(y & fl).sum() / max(y.sum(), 1)], [(y & fl).sum() / max(fl.sum(), 1)], zorder=3)
    ax.axhline(y.mean(), color="grey", ls=":", lw=1, label="chance (attack share)")
    ax.set_xlabel("recall")
    ax.set_ylabel("precision")
    ax.set_title("Precision-recall on the held-out test block (dots = chosen operating point)", fontsize=9)
    ax.legend(fontsize=8)
    fig.tight_layout()
    paths.append(os.path.join(out_dir, "physical_v3_pr_curve.png"))
    fig.savefig(paths[-1], dpi=150)
    plt.close(fig)

    segs = np.unique(seg[y])
    fig, ax = plt.subplots(figsize=(8, 4))
    w = 0.38
    for k, (name, score, rule) in enumerate(variants):
        if not rule or rule.get("threshold") is None:
            continue
        fl = score > rule["threshold"]
        frac = [float(fl[(seg == s) & y].mean()) for s in segs]
        ax.bar(np.arange(len(segs)) + (k - 0.5) * w, frac, w, label=name)
    ax.set_xticks(np.arange(len(segs)), [str(int(s)) for s in segs])
    ax.set_xlabel("attack segment")
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("share of the segment's windows flagged")
    ax.set_title("Detection per attack segment (a bar above zero = the segment was detected)", fontsize=9)
    ax.legend(fontsize=8)
    fig.tight_layout()
    paths.append(os.path.join(out_dir, "physical_v3_segments.png"))
    fig.savefig(paths[-1], dpi=150)
    plt.close(fig)
    return paths


def save_candidate(out_dir: str, res: Dict[str, Any], final: Dict[str, Any], norm: Norm, fixture: bool) -> str:
    """Write the candidate bundle and the JSON report. Returns the candidate path. Never writes into models/weights."""
    import joblib
    out_real = os.path.realpath(out_dir)
    if out_real == WEIGHTS_DIR or out_real.startswith(WEIGHTS_DIR + os.sep):
        raise SystemExit("refusing to write into models/weights")
    os.makedirs(out_dir, exist_ok=True)
    stk = final["stacker"]
    path = os.path.join(out_dir, "physical_v3_candidate.joblib")
    joblib.dump({"schema": F3.FEATURE_VERSION, "recipe": final["recipe"], "heads": final["heads"],
                 "head_meta": {h: {"variant": HEADS[h]["variant"], "stage": HEADS[h]["stage"], "cols": head_cols(h)} for h in final["heads"]},
                 "normal_models": final["normal_models"],
                 "stacker": None if stk is None else {"heads": stk.heads, "w": stk.w, "b": stk.b},
                 "norm_stats": {"mu": norm.mu, "sd": norm.sd, "lo": norm.lo, "hi": norm.hi}, "alarm_rules": res["alarm_rules"],
                 "feature_names": F3.FEATURE_NAMES, "fixture": fixture,
                 "note": "CANDIDATE: package with models.package_physical_v3 only after review and approval"}, path)
    with open(os.path.join(out_dir, "physical_v3_report.json"), "w") as fh:
        json.dump(res, fh, indent=2, default=float)
    return path


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s - %(message)s")
    ap = argparse.ArgumentParser(description="Physical model v3 candidate trainer (candidate only).")
    ap.add_argument("--data-dir")
    ap.add_argument("--fixture", action="store_true")
    ap.add_argument("--candidate", action="store_true", help="required acknowledgement: output is a candidate")
    ap.add_argument("--out-dir", default=DEFAULT_OUT)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--quick", action="store_true", help="fewer trees and recipes (fixture / smoke test)")
    ap.add_argument("--recipes", default=None, help=f"comma list of recipes to evaluate (default all; known: {','.join(RECIPES)})")
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
    quick = a.quick or a.fixture
    res, final, norm, arrays = run(stream, a.seed, 3 if a.fixture else a.folds, quick, recipes=a.recipes.split(",") if a.recipes else None)
    res["fixture_not_real_results"] = bool(a.fixture)
    save_candidate(a.out_dir, res, final, norm, bool(a.fixture))
    txt = render(res, bool(a.fixture))
    with open(os.path.join(a.out_dir, "physical_v3_report.md"), "w") as fh:
        fh.write(txt)
    figs = render_figures(a.out_dir, arrays, res)
    print(txt)
    print(f"\nWrote {a.out_dir} (report .md/.json, candidate .joblib, {len(figs)} figures; models/weights untouched). Send back physical_v3_report.md and the PNGs.")


if __name__ == "__main__":
    main()
