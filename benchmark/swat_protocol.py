"""
benchmark/swat_protocol.py - the evaluation protocol that backs the physical model's numbers (real SWaT, aggregate output only).

    python -m benchmark.swat_protocol --data-dir "<SWaT archive>"      # ~20-40 min on a laptop; writes the report, JSON and figures
    python -m benchmark.swat_protocol --fixture --quick                 # synthetic SWaT-SHAPED data: code path only, numbers meaningless
    python -m benchmark.swat_protocol --from-report docs/reports/physical_training_report_v2_swat.json
                                                                        # no data needed: re-score the SAVED v2 test result under every scheme

Why this exists. The v2 report is ONE calendar split with 10 test attacks and no error bars; one attack more or less moves segment recall by
ten points. This protocol tests on ALL attacks instead:

  * ROLLING BLOCKED CROSS-VALIDATION. The attack segments, in time order, are cut into K contiguous groups. Each group (with the benign time
    between its first and last neighbour) is the test fold once; every other window trains the model, minus an EMBARGO of `--embargo-s` seconds
    around the test fold so a window's 120 s history and the alarm logic cannot straddle the boundary. The 22-28 Dec normal period never
    tests (it holds no attacks) but always trains. Every attack is scored exactly once, by a model that never saw it or its neighbours.
  * THRESHOLDS NEVER SEE THE TEST FOLD. Per fold, the operating threshold is set for a false-alarm BUDGET on out-of-fold scores of the
    training part (inner blocked CV). The realised false-alarm rate on the test fold is then REPORTED next to the budget (it is usually
    higher: the budget was met on the days the model trained on, not on the next ones).
  * FIVE SCORING SCHEMES on the same alarms (swat/scoring.py): strict, composite, PA%K (K = 20/50/80), point-adjust, event level.
  * CLUSTER BOOTSTRAP 95 % intervals (attacks and benign hours are the resampling unit, not windows).
  * BASELINES on the same folds: never alarm; CHANCE alarms matched to the model's alarm rate and alarm length (scored under every scheme -
    this is the proof of what point-adjust rewards); the envelope rule alone; PCA reconstruction error and Isolation Forest trained on benign
    windows only; the refit baseline of the v2 experiment (67 shipped features + random forest).
  * ATTACK-BY-ATTACK table with a heuristic description (which of the 51 SWaT tags moved, which of the 18 tags our model can see). SWaT ships
    no attack list, so this is derived from the data and labelled so. An attack that moves none of the 18 live tags cannot be detected by
    this model: that bounds recall and explains misses without blaming the model.

Disclosed limits: the feature set and model family were chosen on the v2 experiment, whose dev set overlaps these folds, so the model
column is slightly optimistic; the baselines are not tuned. 35 attacks is all SWaT offers. The plant is a simulation of SWaT, not SWaT.
Nothing here writes to models/weights; nothing raw leaves the archive folder (counts, durations and tag names only).
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

from benchmark.env import ROOT, environment
from swat import scoring as SC
from swat.alarm_logic import STRIDE_S, threshold_for_budget
from swat.features_v2 import BASE_COLS, build_windows_v2
from swat.loader import ATTACK_PERIOD_START, load_stream
from swat.physical_features import ACTUATORS, FEATURE_NAMES, SENSORS, Norm, compute_bounds

log = logging.getLogger("industrialmind.swat_protocol")

OUT_JSON = os.path.join(ROOT, "benchmarks", "swat_protocol.json")
OUT_MD = os.path.join(ROOT, "docs", "reports", "swat_evaluation_protocol.md")
FIG_DIR = os.path.join(ROOT, "docs", "reports", "figures")
RESCORE_JSON = os.path.join(ROOT, "benchmarks", "swat_scoring_comparison.json")
RESCORE_MD = os.path.join(ROOT, "docs", "reports", "swat_scoring_comparison.md")

# (name, feature set, model kind, label). The first is the shipped design (v2); the second is the v2 experiment's own refit baseline.
CONFIGS: List[Tuple[str, str, str, str]] = [
    ("v2", "v1_long_resid", "hgb", "v2 design: 120 s long-context + consistency-residual features, gradient boosting (supervised)"),
    ("refit_baseline", "v1_67", "rf6", "refit baseline: the 67 shipped features, random forest depth 6 (supervised)"),
]
BUDGETS = (0.25, 0.5, 1.0, 2.0, 4.0)
PRIMARY_BUDGET = 0.5
INNER_BLOCK_S = 6 * 3600
CAL_HOUR_MOD = 6
MAX_FIT = 50000
LIVE_TAGS = SENSORS + ACTUATORS
_ENV_COL = FEATURE_NAMES.index("sensors_outside_envelope")


# --------------------------------------------------------------------------------------------- folds
def make_folds(meta, k: int, embargo_s: float) -> Dict[str, Any]:
    """fold[i] in 0..k-1 for windows in the test region, -1 before the first attack. train_mask[f] excludes fold f and its embargo."""
    ep = meta["epoch"].to_numpy().astype(float)
    y = meta["label"].to_numpy().astype(bool)
    seg = meta["seg"].to_numpy()
    segs = np.unique(seg[y])
    if segs.size < 2:
        raise SystemExit("need at least two attack segments for cross-validation")
    k = int(min(k, segs.size))
    first = {int(s): float(ep[(seg == s) & y].min()) for s in segs}
    last = {int(s): float(ep[(seg == s) & y].max()) for s in segs}
    order = sorted(first, key=first.get)
    groups = [list(g) for g in np.array_split(np.array(order), k)]
    bounds = [(last[g_prev[-1]] + first[g[0]]) / 2.0 for g_prev, g in zip(groups[:-1], groups[1:])]
    start = min(first.values(), default=0.0)
    start = min(start, (ATTACK_PERIOD_START - __import__("datetime").datetime(1970, 1, 1)).total_seconds())
    fold = np.where(ep < start, -1, np.searchsorted(bounds, ep, side="right")).astype(int)
    lo = [start] + bounds
    hi = bounds + [float("inf")]
    train = []
    for f in range(k):
        train.append((fold != f) & ~((ep >= lo[f] - embargo_s) & (ep < hi[f] + embargo_s)))
    return {"k": k, "fold": fold, "train": train, "groups": [[int(s) for s in g] for g in groups], "bounds": bounds, "start": start}


# --------------------------------------------------------------------------------------------- scorers
def _cap(idx: np.ndarray, y: np.ndarray, seed: int) -> np.ndarray:
    """All attack windows plus at most MAX_FIT benign ones (the same cap models.train_physical_v2 uses)."""
    ben = idx[~y[idx]]
    if ben.size <= MAX_FIT:
        return idx
    keep = np.concatenate([idx[y[idx]], np.random.default_rng(seed).choice(ben, MAX_FIT, replace=False)])
    keep.sort()
    return keep


def _fit_fold(fs: str, kind: str, X87, XL, y, seg, seed: int, n_trees: int, fast: bool):
    """models.train_physical_v2.fit_fold, or - with `fast` - the same fit with the sample weights realised as REPLICATED ROWS for the gradient-boosting
    head. HistGradientBoosting with sample_weight is 15-70x slower than without it on some machines (measured here: 21 s vs 0.3 s on 13k windows);
    integer replication gives the same class and segment balance. Used for the fixture/smoke run; real runs use the exact trainer."""
    from models.train_physical_v2 import Scorer, fit_fold, training_weights
    if not (fast and kind == "hgb"):
        return fit_fold(fs, kind, X87, XL, y, seg, seed, n_trees)
    from sklearn.ensemble import HistGradientBoostingClassifier
    from swat.features_v2 import ResidualModel, assemble
    resid = ResidualModel().fit(X87[y == 0]) if fs == "v1_long_resid" else None
    A = assemble(fs, X87, XL, resid)
    w = training_weights(y, seg)
    reps = np.maximum(1, np.rint(w / w.min()).astype(np.int64))
    idx = np.repeat(np.arange(len(y)), reps)
    sc = Scorer(kind, seed, n_trees)
    sc.model = HistGradientBoostingClassifier(max_depth=3, max_iter=max(40, n_trees), learning_rate=0.05, l2_regularization=10.0, min_samples_leaf=100,
                                              random_state=seed).fit(A[idx], y[idx])
    return sc, resid


def inner_oof(fs: str, kind: str, W: Dict[str, np.ndarray], tr: np.ndarray, k_in: int, seed: int, n_trees: int, fast: bool = False) -> np.ndarray:
    """Out-of-fold scores for the training windows: attacks folded by segment, benign by 6-hour block (blocks, not rows: a day drifts)."""
    from models.train_physical_v2 import predict
    y, seg, ep = W["y"], W["seg"], W["ep"]
    fid = np.where(y[tr], seg[tr] % k_in, (ep[tr] // INNER_BLOCK_S).astype(np.int64) % k_in)
    oof = np.zeros(tr.size)
    for f in range(k_in):
        hold, fit = tr[fid == f], tr[fid != f]
        if hold.size == 0 or y[fit].sum() < 3:
            continue
        fit = _cap(fit, y, seed + f)
        sc, rs = _fit_fold(fs, kind, W["X87"][fit], W["XL"][fit], y[fit].astype(int), seg[fit], seed, n_trees, fast)
        oof[fid == f] = predict(fs, sc, rs, W["X87"][hold], W["XL"][hold])
    return oof


def supervised_fold(fs: str, kind: str, W: Dict[str, np.ndarray], tr: np.ndarray, te: np.ndarray, budgets: Tuple[float, ...], seed: int,
                    quick: bool, fast: bool = False) -> Dict[str, Any]:
    from models.train_physical_v2 import predict
    y, seg, ep = W["y"], W["seg"], W["ep"]
    oof = inner_oof(fs, kind, W, tr, 3, seed, 60 if quick else 100, fast)
    thr = {b: threshold_for_budget(oof, ep[tr], y[tr], 1, 1, b) for b in budgets}
    fit = _cap(tr, y, seed)
    sc, rs = _fit_fold(fs, kind, W["X87"][fit], W["XL"][fit], y[fit].astype(int), seg[fit], seed, 80 if quick else 150, fast)
    return {"score": predict(fs, sc, rs, W["X87"][te], W["XL"][te]), "threshold": thr}


def _unsup_score(kind: str, Z_fit: np.ndarray, Z: np.ndarray, seed: int) -> np.ndarray:
    if kind == "pca":
        from sklearn.decomposition import PCA
        p = PCA(n_components=min(10, Z_fit.shape[1] - 1), random_state=seed).fit(Z_fit)
        return ((Z - p.inverse_transform(p.transform(Z))) ** 2).sum(axis=1)
    from sklearn.ensemble import IsolationForest
    return -IsolationForest(n_estimators=100, random_state=seed, n_jobs=-1).fit(Z_fit).score_samples(Z)


def unsupervised_fold(kind: str, W: Dict[str, np.ndarray], tr: np.ndarray, te: np.ndarray, budgets: Tuple[float, ...], seed: int) -> Dict[str, Any]:
    """Benign-only detector. Fit on benign training windows; the threshold comes from benign training windows it did NOT see (every 6th hour)."""
    y, ep = W["y"], W["ep"]
    ben = tr[~y[tr]]
    hrs = (ep[ben] // 3600).astype(np.int64)
    cal_mask = np.isin(hrs, np.unique(hrs)[::CAL_HOUR_MOD])            # every 6th benign hour present in the training part
    cal, fit = ben[cal_mask], ben[~cal_mask]
    if fit.size > MAX_FIT:
        fit = np.sort(np.random.default_rng(seed).choice(fit, MAX_FIT, replace=False))
    X = W["X87"][:, BASE_COLS]
    mu, sd = X[fit].mean(axis=0), np.maximum(X[fit].std(axis=0), 1e-6)
    Z = (X - mu) / sd
    s_cal = _unsup_score(kind, Z[fit], Z[cal], seed)
    thr = {b: threshold_for_budget(s_cal, ep[cal], np.zeros(cal.size, bool), 1, 1, b) for b in budgets}
    return {"score": _unsup_score(kind, Z[fit], Z[te], seed), "threshold": thr}


# --------------------------------------------------------------------------------------------- describing attacks
def _stage(tag: str) -> int:
    digits = [c for c in tag if c.isdigit()]
    return int(digits[0]) if digits else 0


def describe_segments(stream, tags: List[str], seg_ids: List[int], ref_s: int = 600, z_mean: float = 6.0, z_max: float = 12.0) -> Dict[int, Dict[str, Any]]:
    """HEURISTIC description of each attack from the data (SWaT ships no attack list): a tag 'moved' if its mean during the segment is more than
    z_mean reference-sd from the preceding benign minutes, or any sample is more than z_max sd away. Descriptive only: never used to train or score."""
    values = stream[tags].to_numpy(dtype=np.float64)
    seg, chunk, lab = stream["seg"].to_numpy(), stream["chunk"].to_numpy(), stream["label"].to_numpy()
    live = {t: i for i, t in enumerate(tags) if t in LIVE_TAGS}
    out: Dict[int, Dict[str, Any]] = {}
    for sid in seg_ids:
        pos = np.flatnonzero(seg == sid)
        a = int(pos[0])
        ref = np.arange(max(0, a - ref_s), a)
        ref = ref[(chunk[ref] == chunk[a]) & ~lab[ref]]
        d: Dict[str, Any] = {"duration_s": int(pos.size), "described": False}
        if ref.size >= 60:
            g, r = values[pos], values[ref]
            mu, sd = np.nanmean(r, axis=0), np.nanstd(r, axis=0)
            scale = np.maximum(sd, 1e-6 + 1e-3 * np.abs(mu))
            dev_mean = np.abs(np.nanmean(g, axis=0) - mu) / scale
            dev_max = np.nanmax(np.abs(g - mu), axis=0) / scale
            moved = np.flatnonzero(np.nan_to_num((dev_mean > z_mean) | (dev_max > z_max), nan=False))
            names = [tags[i] for i in moved]
            d.update({"described": True, "tags_moved": len(names), "stages_moved": sorted({_stage(t) for t in names if _stage(t)}),
                      "live_tags_moved": [t for t in names if t in live], "other_tags_moved": len([t for t in names if t not in live]),
                      "visible_to_model": any(t in live for t in names)})
        out[int(sid)] = d
    return out


# --------------------------------------------------------------------------------------------- the run
def _fold_auc(y: np.ndarray, score: np.ndarray) -> Dict[str, Optional[float]]:
    from sklearn.metrics import average_precision_score, roc_auc_score
    if 0 < y.sum() < y.size:
        return {"roc_auc": round(float(roc_auc_score(y, score)), 4), "average_precision": round(float(average_precision_score(y, score)), 4)}
    return {"roc_auc": None, "average_precision": None}


def run(stream, k: int, embargo_s: float, seed: int, budgets: Tuple[float, ...], quick: bool, n_boot: int, trials: int,
        tags_for_description: Optional[List[str]] = None, fast_hgb: bool = False) -> Dict[str, Any]:
    t0 = time.time()
    norm_rows = stream[(stream["period"] == "normal_period") & ~stream["label"]]
    if len(norm_rows) < 2000:
        raise SystemExit("too few pre-attack normal rows to measure bounds without touching the test region")
    norm = Norm(compute_bounds(norm_rows[SENSORS]))
    X87, XL, meta = build_windows_v2(stream, norm)
    W = {"X87": X87, "XL": XL, "y": meta["label"].to_numpy().astype(bool), "seg": meta["seg"].to_numpy(), "ep": meta["epoch"].to_numpy().astype(float)}
    F = make_folds(meta, k, embargo_s)
    fold, k = F["fold"], F["k"]
    y, seg, ep = W["y"], W["seg"], W["ep"]
    pool = np.flatnonzero(fold >= 0)
    pos_in_pool = {f: np.flatnonzero(fold[pool] == f) for f in range(k)}
    log.info("windows %d (attack %d, segments %d); test region %d windows in %d folds; groups %s", len(y), y.sum(), np.unique(seg[y]).size, pool.size, k, F["groups"])

    methods: Dict[str, Dict[str, Any]] = {}          # name -> {"label", "score": pooled|None, "thr": {fold: {b: thr}}, "fixed": bool}
    jobs: List[Tuple[str, str, Any]] = [(n, "sup", (fs, kd)) for n, fs, kd, _ in CONFIGS] + [("pca", "unsup", "pca"), ("iforest", "unsup", "iforest")]
    labels = {n: lab for n, _, _, lab in CONFIGS}
    labels.update({"pca": "PCA reconstruction error on the 67 shipped features (benign-only, unsupervised)",
                   "iforest": "Isolation Forest on the 67 shipped features (benign-only, unsupervised)"})
    for name, kind, spec in jobs:
        methods[name] = {"label": labels[name], "score": np.zeros(pool.size), "thr": {}}
    for f in range(k):
        te = pool[pos_in_pool[f]]
        tr = np.flatnonzero(F["train"][f])
        log.info("fold %d/%d: test %d windows (%d attack), train %d windows (%d attack)", f + 1, k, te.size, y[te].sum(), tr.size, y[tr].sum())
        for name, kind, spec in jobs:
            r = (supervised_fold(spec[0], spec[1], W, tr, te, budgets, seed + f, quick, fast_hgb) if kind == "sup"
                 else unsupervised_fold(spec, W, tr, te, budgets, seed + f))
            methods[name]["score"][pos_in_pool[f]] = r["score"]
            methods[name]["thr"][f] = r["threshold"]
            log.info("  %-15s done (%.0f s elapsed)", name, time.time() - t0)

    yp, sp, ep_p = y[pool], seg[pool], ep[pool]

    def flags_for(name: str, b: float) -> np.ndarray:
        fl = np.zeros(pool.size, bool)
        for f in range(k):
            t = methods[name]["thr"][f][b]
            fl[pos_in_pool[f]] = methods[name]["score"][pos_in_pool[f]] > (np.inf if t is None else t)     # no feasible threshold -> never alarm
        return fl

    flags: Dict[str, Dict[float, np.ndarray]] = {n: {b: flags_for(n, b) for b in budgets} for n in methods}
    env_flag = X87[pool, _ENV_COL] > 0
    nothing = np.zeros(pool.size, bool)
    primary_flags = flags["v2"][PRIMARY_BUDGET] if PRIMARY_BUDGET in budgets else flags["v2"][budgets[0]]
    pb = PRIMARY_BUDGET if PRIMARY_BUDGET in budgets else budgets[0]

    def counts_of(fl: np.ndarray, mask: Optional[np.ndarray] = None) -> SC.Counts:
        m = np.ones(pool.size, bool) if mask is None else mask
        return SC.counts_from_flags(fl[m], yp[m], sp[m], ep_p[m])

    res: Dict[str, Any] = {"protocol": {"folds": k, "embargo_s": embargo_s, "seed": seed, "budgets": list(budgets), "primary_budget": pb, "inner_folds": 3,
                                        "inner_benign_block_s": INNER_BLOCK_S, "windows_total": int(len(y)), "windows_tested": int(pool.size),
                                        "attack_windows": int(yp.sum()), "attack_segments": int(np.unique(sp[yp]).size), "benign_hours_tested": round(float((~yp).sum() * STRIDE_S / 3600), 2),
                                        "fold_groups": F["groups"], "stride_s": STRIDE_S, "window_s": 120, "bootstrap": n_boot, "random_trials": trials,
                                        "normal_period_windows_train_only": int((fold == -1).sum()), "fast_hgb_row_replication": bool(fast_hgb)},
                           "methods": {n: m["label"] for n, m in methods.items()}}
    # ---- every method at every budget, pooled over all test folds
    table: Dict[str, Dict[str, Any]] = {}
    for n in methods:
        table[n] = {str(b): SC.metrics(counts_of(flags[n][b])) for b in budgets}
    table["envelope_rule"] = {"fixed": SC.metrics(counts_of(env_flag))}
    table["never_alarm"] = {"fixed": SC.metrics(counts_of(nothing))}
    res["pooled"] = table
    # ---- confidence intervals for the primary budget
    res["ci_primary_budget"] = {n: SC.bootstrap(counts_of(flags[n][pb]), n_boot, seed) for n in methods}
    res["ci_primary_budget"]["envelope_rule"] = SC.bootstrap(counts_of(env_flag), n_boot, seed)
    # ---- chance alarms matched to v2 (the point-adjust proof)
    res["chance_baseline"] = SC.random_baseline(primary_flags, yp, sp, ep_p, trials, seed)
    # ---- operating curve (budget sweep): event recall vs realised false alarms per hour
    res["operating_curve"] = {n: [{"budget": b, "event_recall": table[n][str(b)]["event_recall"], "segments_detected": table[n][str(b)]["segments_detected"],
                                   "segment_balanced_recall": table[n][str(b)]["segment_balanced_recall"],
                                   "false_alarm_episodes_per_hour": table[n][str(b)]["false_alarm_episodes_per_hour"], "f1": table[n][str(b)]["f1"],
                                   "pa_f1": table[n][str(b)]["pa_f1"]} for b in budgets] for n in methods}
    # ---- per fold (v2 and the refit baseline), with ranking quality
    per_fold: List[Dict[str, Any]] = []
    for f in range(k):
        pf = pos_in_pool[f]
        row: Dict[str, Any] = {"fold": f + 1, "attack_segments": [int(s) for s in F["groups"][f]], "windows": int(pf.size), "attack_windows": int(yp[pf].sum())}
        for n in ("v2", "refit_baseline"):
            m = SC.metrics(SC.counts_from_flags(flags[n][pb][pf], yp[pf], sp[pf], ep_p[pf]))
            row[n] = {**{key: m[key] for key in ("precision", "recall", "f1", "composite_f1", "pa_f1", "segments_detected", "segments_total", "false_alarm_episodes_per_hour")},
                      **_fold_auc(yp[pf], methods[n]["score"][pf]), "threshold": None if methods[n]["thr"][f][pb] is None else round(float(methods[n]["thr"][f][pb]), 4)}
        per_fold.append(row)
    res["per_fold"] = per_fold
    aucs = [r["v2"]["roc_auc"] for r in per_fold if r["v2"]["roc_auc"] is not None]
    res["v2_roc_auc_over_folds"] = {"mean": round(float(np.mean(aucs)), 4), "sd": round(float(np.std(aucs)), 4), "n": len(aucs)} if aucs else None
    # ---- with and without the one huge attack
    sizes = {int(s): int(((sp == s) & yp).sum()) for s in np.unique(sp[yp])}
    big = max(sizes, key=sizes.get)
    keep = sp != big
    res["largest_segment"] = {"segment": big, "attack_windows": sizes[big], "share_of_attack_windows": round(sizes[big] / max(int(yp.sum()), 1), 4)}
    res["without_largest_segment"] = {n: SC.metrics(counts_of(flags[n][pb], keep)) for n in ("v2", "refit_baseline", "pca", "iforest")}
    res["without_largest_segment"]["envelope_rule"] = SC.metrics(counts_of(env_flag, keep))
    # ---- attack by attack
    descr: Dict[int, Dict[str, Any]] = {}
    if tags_for_description:
        descr = describe_segments(stream, tags_for_description, [int(s) for s in sizes])
    rows = SC.per_attack(counts_of(primary_flags))
    others = {n: {r["segment"]: r for r in SC.per_attack(counts_of(flags[n][pb]))} for n in ("refit_baseline", "pca", "iforest")}
    fold_of = {int(s): f + 1 for f, g in enumerate(F["groups"]) for s in g}
    for r in rows:
        s = r["segment"]
        r["fold"] = fold_of.get(s)
        r["detected_by"] = {n: others[n][s]["detected"] for n in others}
        r["describe"] = descr.get(s)
    res["per_attack"] = rows
    vis = [r for r in rows if r["describe"] and r["describe"].get("described")]
    if vis:
        v, nv = [r for r in vis if r["describe"]["visible_to_model"]], [r for r in vis if not r["describe"]["visible_to_model"]]
        res["visibility_bound"] = {"described_attacks": len(vis), "visible_on_live_tags": len(v), "visible_detected": sum(r["detected"] for r in v),
                                   "not_visible": len(nv), "not_visible_detected": sum(r["detected"] for r in nv),
                                   "max_recall_if_every_visible_attack_were_caught": round(len(v) / len(vis), 4),
                                   "note": "HEURISTIC (swat_protocol.describe_segments): SWaT ships no attack list. 'visible' = at least one of the 18 tags our model reads moved."}
    res["seconds"] = round(time.time() - t0, 1)
    res["environment"] = environment()
    return res


# --------------------------------------------------------------------------------------------- re-score a saved report (no data needed)
def rescore_report(path: str, n_boot: int = 4000, seed: int = 0) -> Dict[str, Any]:
    """Re-score the SAVED physical-v2 held-out test under every scheme from its per-segment aggregates. Same alarms, only the counting changes.
    The bootstrap resamples the 10 attacks (benign side held fixed, because the report keeps one benign total), so the intervals are narrower than
    the truth: the benign hours and the threshold are not resampled."""
    with open(path) as fh:
        rep = json.load(fh)
    t = rep["test"]
    hours = float(t["benign_hours"])
    out: Dict[str, Any] = {"source": os.path.relpath(path, ROOT), "windows": t["windows"], "attack_windows": t["attack_windows"], "benign_hours": hours,
                           "segments": len(next(v for v in t.values() if isinstance(v, dict) and "baseline" in v)["baseline"]["per_segment"]), "budgets": {}}
    for b, d in t.items():
        if not isinstance(d, dict) or "baseline" not in d:
            continue
        out["budgets"][b] = {}
        for name, blk in d.items():
            if "per_segment" not in blk:
                continue
            c = SC.from_report_block(blk, hours)
            m = SC.metrics(c)
            m["false_alarm_episodes_per_hour"] = blk["alarm_episodes_per_benign_hour"]      # the report's own figure (Counts holds a rounded-back episode count)
            if "accuracy" in blk:
                assert abs(m["accuracy"] - blk["accuracy"]) < 1e-3 and abs(m["f1"] - blk["f1"]) < 1e-3, f"re-scored strict numbers disagree with the report ({name}, {b})"
            out["budgets"][b][name] = {"rule": blk.get("rule"), "metrics": m, "ci_attack_side_only": SC.bootstrap(c, n_boot, seed), "schemes": SC.scheme_table(m)}
    return out


def render_rescore(res: Dict[str, Any]) -> str:
    L = ["# Physical model v2 - the same alarms under every scoring scheme", "",
         f"Generated by `python -m benchmark.swat_protocol --from-report {res['source']}`. **Nothing was retrained or re-run.** The held-out SWaT test block "
         f"({res['windows']:,} windows, {res['attack_windows']:,} attack windows, {res['segments']} attacks, {res['benign_hours']} benign hours) keeps its per-attack "
         "aggregates in the training report; only the way the alarms are COUNTED changes here.", "",
         "Why: published SWaT scores of 0.8-0.9 mostly use point-adjust (one flagged window credits the whole attack) and often pick the threshold on the test labels. "
         "Below, the live model's alarms are scored every way, so a reader can compare with the literature and still see the strict number. "
         "Our threshold was fixed on the training data before the test block was scored.", ""]
    for b, d in res["budgets"].items():
        L += [f"## False-alarm budget {b} per benign hour", ""]
        for name, label in (("selected_without_persistence", "v2 as shipped (selected features, single-window alarm)"), ("baseline", "refit baseline (67 shipped features, random forest)"),
                            ("selected", "v2 + 3-of-6 persistence (rejected: it hurt)")):
            if name not in d:
                continue
            m = d[name]["metrics"]
            L += [f"### {label}", "", "| scheme | precision | recall | F1 | accuracy |", "|---|---|---|---|---|"]
            for r in d[name]["schemes"]:
                L.append(f"| {r['scheme']} | {r['precision']} | {r['recall']} | **{r['f1']}** | {r['accuracy'] if r['accuracy'] is not None else '-'} |")
            ci = d[name]["ci_attack_side_only"]
            f = lambda k: "n/a" if not ci.get(k) else f"{ci[k][0]} to {ci[k][1]}"
            L += ["", f"Event level: {m['segments_detected']}/{m['segments_total']} attacks detected, median delay {m['median_latency_s']} s, "
                  f"{m['false_alarm_episodes_per_hour']} false-alarm episodes per benign hour. A never-alarm system scores accuracy {m['always_benign_accuracy']}.", "",
                  f"95 % interval over the {m['segments_total']} attacks (benign side fixed, so optimistic): strict F1 {f('f1')}; composite F1 {f('composite_f1')}; "
                  f"point-adjust F1 {f('pa_f1')}; attacks detected share {f('event_recall')}.", ""]
    L += ["Reading it: the model, the threshold and the alarms are identical in every row. Strict F1 -> point-adjust F1 is pure counting. The wide intervals are the "
          "honest size of a 10-attack test; `python -m benchmark.swat_protocol --data-dir <archive>` re-measures this on all 35 attacks with proper intervals and baselines.", ""]
    return "\n".join(L)


# --------------------------------------------------------------------------------------------- rendering
def _ci(res: Dict[str, Any], name: str, key: str) -> str:
    c = res["ci_primary_budget"].get(name, {}).get(key)
    return "" if not c else f" ({c[0]} to {c[1]})"


def render(res: Dict[str, Any], fixture: bool) -> str:
    p, pb = res["protocol"], str(res["protocol"]["primary_budget"])
    v2 = res["pooled"]["v2"][pb]
    L = ["# SWaT evaluation protocol - physical model v2 on all attacks", ""]
    if fixture:
        L += ["**SYNTHETIC FIXTURE: a code-path check only. Every number below is meaningless; never cite any of it.**", ""]
    env = res["environment"]
    L += [f"Generated by `python -m benchmark.swat_protocol` on {env['generated_utc']} UTC, commit `{env['git_commit']}`{' (dirty tree)' if env['git_dirty'] else ''}, "
          f"Python {env['python']}, scikit-learn {env['scikit_learn']}, seed {p['seed']}, run time {res['seconds']} s. Aggregate counts only: no raw SWaT rows.", "",
          "## What was measured", "",
          f"- **All {p['attack_segments']} attacks are tested**, each by a model that never trained on it or its neighbours: {p['folds']}-fold rolling blocked cross-validation "
          f"(attacks in time order, contiguous groups), {p['embargo_s']:.0f} s embargo around each test fold. {p['windows_tested']:,} windows tested "
          f"({p['attack_windows']:,} attack, {p['benign_hours_tested']} benign hours); {p['normal_period_windows_train_only']:,} pre-attack normal windows only ever train.",
          f"- **Thresholds never see the test fold.** Per fold the threshold is set for {pb} false-alarm episodes per benign hour on out-of-fold scores of the training part "
          f"({p['inner_folds']} inner blocked folds, {p['inner_benign_block_s'] // 3600} h benign blocks). Realised rates on the test fold are reported below.",
          f"- **Intervals** are 95 % cluster-bootstrap ({p['bootstrap']} resamples of attacks and benign hours).",
          "- Model family and feature set were chosen on the v2 experiment (its dev set overlaps these folds), so the v2 rows are slightly optimistic; the baselines are untuned.", ""]
    L += [f"## Headline: v2 at {pb} false alarms per benign hour, all attacks pooled", "", "| scheme | precision | recall | F1 | accuracy |", "|---|---|---|---|---|"]
    for r in SC.scheme_table(v2):
        L.append(f"| {r['scheme']} | {r['precision']} | {r['recall']} | **{r['f1']}** | {r['accuracy'] if r['accuracy'] is not None else '-'} |")
    ci = res["ci_primary_budget"]["v2"]
    f = lambda k: "n/a" if not ci.get(k) else f"{ci[k][0]} to {ci[k][1]}"
    L += ["", f"95 % intervals: strict F1 {f('f1')}; precision {f('precision')}; recall {f('recall')}; composite F1 {f('composite_f1')}; point-adjust F1 {f('pa_f1')}.", "",
          f"Event level: **{v2['segments_detected']}/{v2['segments_total']} attacks detected** (95 % {f('event_recall')} of attacks), median detection delay {v2['median_latency_s']} s "
          f"(95 % {f('median_latency_s')}), **{v2['false_alarm_episodes_per_hour']} false-alarm episodes per benign hour** against a budget of {pb} "
          f"(95 % {f('false_alarm_episodes_per_hour')}), {int(100 * v2['episode_precision']) if v2.get('episode_precision') is not None else 'n/a'} % of alarm episodes overlapped a real attack. "
          f"ROC-AUC per fold: {res['v2_roc_auc_over_folds']['mean']} +- {res['v2_roc_auc_over_folds']['sd']} (n = {res['v2_roc_auc_over_folds']['n']} folds)." if res.get("v2_roc_auc_over_folds") else "", ""]
    L += [f"A never-alarm system scores accuracy {v2['always_benign_accuracy']} here (v2: {v2['accuracy']}); accuracy is not the headline, see the event-level line.", ""]
    L += ["## Is the model better than doing nothing clever? Same folds, same budget", "",
          "| method | strict F1 | composite F1 | PA%K 50 F1 | point-adjust F1 | attacks detected | false-alarm episodes / h |", "|---|---|---|---|---|---|---|"]
    rows = [(n, res["methods"][n], res["pooled"][n][pb]) for n in res["methods"]]
    rows += [("envelope_rule", "envelope rule alone (alert-only rule, fixed, no training)", res["pooled"]["envelope_rule"]["fixed"]),
             ("never_alarm", "never alarm", res["pooled"]["never_alarm"]["fixed"])]
    for n, lab, m in rows:
        L.append(f"| {lab} | {m['f1']}{_ci(res, n, 'f1')} | {m['composite_f1']} | {m['pak50_f1']} | {m['pa_f1']} | {m['segments_detected']}/{m['segments_total']} | {m['false_alarm_episodes_per_hour']} |")
    cb = res["chance_baseline"]
    g = lambda k: f"{cb[k]['mean']} ({cb[k]['lo']} to {cb[k]['hi']})"
    L.append(f"| chance alarms matched to v2's alarm rate and length ({cb['trials']} draws, mean and 95 % range) | {g('f1')} | {g('composite_f1')} | {g('pak50_f1')} | {g('pa_f1')} | "
             f"{cb['segments_detected']['mean']}/{v2['segments_total']} | {g('false_alarm_episodes_per_hour')} |")
    L += ["", "The chance row is the point-adjust check: look at how much of v2's point-adjust F1 a coin-toss alarm process already earns, and how little of its strict F1.", ""]
    L += ["## Operating curve: what each false-alarm budget buys (pooled, realised rates)", "", "| budget (episodes / benign h) | realised episodes / h | attacks detected | strict F1 | point-adjust F1 |", "|---|---|---|---|---|"]
    for r in res["operating_curve"]["v2"]:
        L.append(f"| {r['budget']} | {r['false_alarm_episodes_per_hour']} | {r['segments_detected']}/{v2['segments_total']} | {r['f1']} | {r['pa_f1']} |")
    L += ["", "Realised rates above the budget are the cost of setting a threshold on the days the model trained on and deploying it on the next ones.", ""]
    L += ["## Fold by fold (v2)", "", "| fold | attacks | attack windows | attacks detected | strict F1 | composite F1 | ROC-AUC | false-alarm episodes / h |", "|---|---|---|---|---|---|---|---|"]
    for r in res["per_fold"]:
        m = r["v2"]
        L.append(f"| {r['fold']} | {len(r['attack_segments'])} | {r['attack_windows']:,} | {m['segments_detected']}/{m['segments_total']} | {m['f1']} | {m['composite_f1']} | {m['roc_auc']} | {m['false_alarm_episodes_per_hour']} |")
    ls = res["largest_segment"]
    L += ["", f"## Does one huge attack carry the result? Segment {ls['segment']} holds {100 * ls['share_of_attack_windows']:.0f} % of all attack windows", "",
          "| method | strict F1 with it | strict F1 without it | point-adjust F1 with it | without it |", "|---|---|---|---|---|"]
    for n in ("v2", "refit_baseline", "pca", "iforest", "envelope_rule"):
        a = res["pooled"][n][pb] if n != "envelope_rule" else res["pooled"][n]["fixed"]
        b = res["without_largest_segment"][n]
        L.append(f"| {n} | {a['f1']} | {b['f1']} | {a['pa_f1']} | {b['pa_f1']} |")
    L += ["", "## Attack by attack (v2)", "",
          "Description is a heuristic from the data (SWaT ships no attack list): tags that moved against the preceding benign minutes. 'visible' = at least one of the 18 tags the model reads moved.", "",
          "| attack | fold | duration | windows flagged | detected | delay (s) | also detected by: refit / PCA / iForest | tags moved (all 51) | live tags moved | visible |", "|---|---|---|---|---|---|---|---|---|---|"]
    for r in res["per_attack"]:
        d = r.get("describe") or {}
        db = r["detected_by"]
        L.append(f"| {r['segment']} | {r['fold']} | {r['duration_s']} s | {r['flagged_windows']}/{r['attack_windows']} ({int(100 * (r['flagged_share'] or 0))} %) | {'yes' if r['detected'] else '**no**'} | "
                 f"{r['latency_s'] if r['latency_s'] is not None else '-'} | {' / '.join('yes' if db[n] else 'no' for n in ('refit_baseline', 'pca', 'iforest'))} | "
                 f"{d.get('tags_moved', '?')} | {', '.join(d.get('live_tags_moved', [])) or ('none' if d.get('described') else '?')} | {('yes' if d.get('visible_to_model') else 'no') if d.get('described') else '?'} |")
    vb = res.get("visibility_bound")
    if vb:
        L += ["", f"Visibility bound: {vb['visible_on_live_tags']} of {vb['described_attacks']} attacks move at least one of the 18 live tags; v2 detects {vb['visible_detected']} of those and "
              f"{vb['not_visible_detected']} of the {vb['not_visible']} that move none. An attack that moves no live tag cannot be detected from them: the model is not at fault for those. ({vb['note']})"]
    L += ["", "## Limits that stay", "",
          "- 35 attacks is everything SWaT offers; intervals are wide because the unit of evidence is the attack, not the window.",
          "- The twin is a simulation of SWaT: these numbers are SWaT performance, not the twin's (see `docs/reports/twin_domain_gap_report.md` for the twin).",
          "- The cyber layer cannot be evaluated on SWaT (no HMAC, replay or source fields); it is evaluated against its specification in `docs/reports/benchmark_report.md`.",
          "- The model stays advisory (ALERT); blocking is by rules. These numbers do not change what is blocked.", ""]
    return "\n".join(L)


def figures(res: Dict[str, Any], out_dir: str) -> List[str]:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    os.makedirs(out_dir, exist_ok=True)
    pb = str(res["protocol"]["primary_budget"])
    v2, cb = res["pooled"]["v2"][pb], res["chance_baseline"]
    names = []
    # 1. the same alarms under every scheme: v2 vs chance
    fig, ax = plt.subplots(figsize=(8, 4))
    keys = [("f1", "strict"), ("composite_f1", "composite"), ("pak50_f1", "PA%K 50"), ("pa_f1", "point-adjust")]
    x = np.arange(len(keys))
    ci = res["ci_primary_budget"]["v2"]
    err = np.array([[0, 0] if not ci.get(k) else [v2[k] - ci[k][0], ci[k][1] - v2[k]] for k, _ in keys]).T
    ax.bar(x - 0.2, [v2[k] for k, _ in keys], 0.4, yerr=np.clip(err, 0, None), capsize=3, label="v2 (95 % CI)", color="#2a6fbb")
    ax.bar(x + 0.2, [cb[k]["mean"] for k, _ in keys], 0.4, yerr=[[cb[k]["mean"] - cb[k]["lo"] for k, _ in keys], [cb[k]["hi"] - cb[k]["mean"] for k, _ in keys]],
           capsize=3, label="chance alarms, same rate and length", color="#999999")
    ax.set_xticks(x, [n for _, n in keys])
    ax.set_ylabel("F1")
    ax.set_ylim(0, 1)
    ax.legend(fontsize=8)
    ax.set_title("Same alarms, four ways of counting" + ("  [SYNTHETIC FIXTURE]" if res.get("fixture") else ""), fontsize=10)
    names.append(_save(fig, out_dir, "protocol_scoring_schemes.png"))
    # 2. operating curve
    fig, ax = plt.subplots(figsize=(6.5, 4.2))
    for n, col in (("v2", "#2a6fbb"), ("refit_baseline", "#d98a1b"), ("pca", "#6a9955"), ("iforest", "#a04a9b")):
        pts = res["operating_curve"][n]
        ax.plot([p["false_alarm_episodes_per_hour"] for p in pts], [p["event_recall"] for p in pts], "o-", label=n, color=col)
    ax.set_xscale("log")
    ax.set_xlabel("realised false-alarm episodes per benign hour")
    ax.set_ylabel("share of attacks detected")
    ax.set_ylim(0, 1.02)
    ax.legend(fontsize=8)
    ax.set_title("Operating curve over all attacks" + ("  [SYNTHETIC FIXTURE]" if res.get("fixture") else ""), fontsize=10)
    names.append(_save(fig, out_dir, "protocol_operating_curve.png"))
    # 3. attack by attack
    rows = res["per_attack"]
    fig, ax = plt.subplots(figsize=(9, 3.8))
    ax.bar(range(len(rows)), [r["flagged_share"] or 0 for r in rows], color=["#2a6fbb" if r["detected"] else "#c0392b" for r in rows])
    ax.set_xticks(range(len(rows)), [str(r["segment"]) for r in rows], fontsize=7)
    ax.set_xlabel("attack segment (time order)")
    ax.set_ylabel("share of the attack's windows flagged")
    ax.set_title("Per attack: flagged share (red = never flagged)" + ("  [SYNTHETIC FIXTURE]" if res.get("fixture") else ""), fontsize=10)
    names.append(_save(fig, out_dir, "protocol_per_attack.png"))
    return names


def _save(fig, out_dir: str, name: str) -> str:
    import matplotlib.pyplot as plt
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, name), dpi=130)
    plt.close(fig)
    return name


def all_tags(data_dir: str) -> List[str]:
    import pandas as pd
    f = next(os.path.join(data_dir, n) for n in os.listdir(data_dir) if n.lower() in ("normal.csv", "merged.csv"))
    cols = [str(c).strip() for c in pd.read_csv(f, nrows=0, skipinitialspace=True).columns]
    return [c for c in cols if c.lower() != "timestamp" and c != "Normal/Attack"]


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s - %(message)s")
    ap = argparse.ArgumentParser(description="Cross-validated, multi-scheme evaluation of the physical model on all SWaT attacks.")
    ap.add_argument("--data-dir")
    ap.add_argument("--fixture", action="store_true", help="synthetic SWaT-shaped archive: code path only")
    ap.add_argument("--from-report", help="re-score a saved physical training report (no data needed)")
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--embargo-s", type=float, default=300.0)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--budgets", type=float, nargs="+", default=list(BUDGETS))
    ap.add_argument("--bootstrap", type=int, default=2000)
    ap.add_argument("--random-trials", type=int, default=200)
    ap.add_argument("--quick", action="store_true", help="fewer trees / resamples (smoke run)")
    ap.add_argument("--fast-hgb", action="store_true", help="row replication instead of sample_weight for gradient boosting (much faster on some machines; implied by --fixture)")
    ap.add_argument("--no-describe", action="store_true", help="skip the per-attack tag description (loads only the 18 live tags)")
    ap.add_argument("--out-dir", help="where to write (default: the repo's report paths; fixture/quick runs default to a temp dir)")
    a = ap.parse_args()

    if a.from_report:
        res = rescore_report(a.from_report)
        md = render_rescore(res)
        os.makedirs(os.path.dirname(RESCORE_JSON), exist_ok=True)
        with open(RESCORE_JSON, "w") as fh:
            json.dump(res, fh, indent=2)
        with open(RESCORE_MD, "w") as fh:
            fh.write(md)
        print(md)
        print(f"\nWrote {os.path.relpath(RESCORE_JSON, ROOT)} and {os.path.relpath(RESCORE_MD, ROOT)}")
        return

    if a.fixture:
        from tests.swat_fixture import make_swat_archive
        d = tempfile.mkdtemp(prefix="swat-fixture-")
        make_swat_archive(d, seed=0)
    elif a.data_dir:
        d = a.data_dir
    else:
        ap.error("give --data-dir, --fixture or --from-report")
    quick = a.quick or a.fixture
    tags = [] if a.no_describe else all_tags(d)
    stream, _info = load_stream(d, sorted(set(SENSORS + ACTUATORS + tags)))
    res = run(stream, a.folds, a.embargo_s, a.seed, tuple(a.budgets), quick, 300 if quick else a.bootstrap, 40 if quick else a.random_trials, tags or None,
              fast_hgb=a.fast_hgb or a.fixture)
    res["fixture"] = bool(a.fixture)
    if a.fixture or a.quick or a.out_dir:
        out = a.out_dir or tempfile.mkdtemp(prefix="swat-protocol-")
        jpath, mpath, fdir = os.path.join(out, "swat_protocol.json"), os.path.join(out, "swat_evaluation_protocol.md"), os.path.join(out, "figures")
    else:
        jpath, mpath, fdir = OUT_JSON, OUT_MD, FIG_DIR
    os.makedirs(os.path.dirname(jpath), exist_ok=True)
    os.makedirs(os.path.dirname(mpath), exist_ok=True)
    with open(jpath, "w") as fh:
        json.dump(res, fh, indent=2, default=float)
    md = render(res, bool(a.fixture))
    with open(mpath, "w") as fh:
        fh.write(md)
    figures(res, fdir)
    print(md)
    print(f"\nWrote {jpath}, {mpath} and figures in {fdir} (models/weights untouched).")


if __name__ == "__main__":
    main()
