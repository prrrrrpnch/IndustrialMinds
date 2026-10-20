"""
models/train_physical_swat.py - train the PhysicalModel on SWaT ONLY, derive the MEASURED bounds, write CANDIDATES.

    python -m models.train_physical_swat --data-dir "C:\\IndustrialMind\\SWaT_dataset\\archive" --candidate
    python -m models.train_physical_swat --fixture --candidate      # synthetic SWaT-SHAPED fixture, code check only

Outputs (default models/candidates/, NEVER models/weights/):
    physical_model.joblib            candidate weights (+ the measured bounds)
    swat_bounds.json                 measured normal-operation statistics + envelope per sensor (aggregate only)
    physical_training_report.json/.md

Protocol (same as the cyber model, agreed at the Phase 4 gate):
  * inputs = the twin's SWaT-backed points only (so the model can run live): 10 sensors + 8 actuators;
  * 30 s windows at 1 Hz, stride 5 s; label = the attack flag at the window's last second;
  * split by CALENDAR BLOCK (train 22-29 Dec, validation 30-31 Dec, test 1-2 Jan), never random rows;
  * bounds and normalisation come from TRAIN-block NORMAL rows only;
  * Isolation Forest fits on train-normal windows; the supervised head's FEATURE VARIANT and regularisation are
    chosen on the VALIDATION block by average precision EXCLUDING any segment that holds > 50 % of the block's
    attack windows (SWaT segment 22 is such a one-regime outlier); its threshold is set by a FALSE-ALARM BUDGET on
    validation normal data; the TEST block is used once, for reported numbers;
  * REVISION NOTE: run 1 used max-validation-F1 thresholds and one feature set. After seeing run 1 (validation was 88 %
    one segment; train AUC 1.0 vs test 0.66) the selection protocol above was introduced. The test block is therefore no
    longer a pristine hold-out for the revised pipeline; the report states this and shows the full operating curve;
  * the measured-envelope rule is validated separately on the held-out blocks.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import platform
import sys
import tempfile
import time
from typing import Any, Dict, List, Tuple

import numpy as np
import pandas as pd

from models.physical_model import PhysicalModel
from research.train_cyber_swat import WEIGHTS_DIR, best_f1_threshold, confusion, ranking
from swat.loader import load_stream
from swat.physical_features import (ACTUATORS, DROPPED_INPUTS, FEATURE_NAMES, PROVENANCE, SENSORS, VARIANTS, WINDOW, Norm,
                                    build_windows, compute_bounds)

log = logging.getLogger("industrialmind.train_physical_swat")
HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT = os.path.join(HERE, "candidates")
STRIDE = 5
GRID = [(6, 10), (6, 40), (10, 10), (10, 40)]     # (max_depth, min_samples_leaf), picked on validation AP
BUDGETS = [0.25, 0.5, 1.0, 2.0, 4.0]               # false-alarm budgets (alarm episodes per normal hour) for the operating curve
DEFAULT_BUDGET = 1.0


def episodes(epochs: np.ndarray, flagged: np.ndarray, gap_s: float = 30.0) -> int:
    """Number of alarm episodes: runs of flagged items separated by more than gap_s."""
    t = epochs[flagged]
    return 0 if t.size == 0 else int(1 + (np.diff(np.sort(t)) > gap_s).sum())


def threshold_for_budget(scores: np.ndarray, epochs: np.ndarray, hours: float, budget: float) -> float:
    """Smallest threshold whose alarm episodes per hour on NORMAL data stay within the budget."""
    cands = np.unique(np.quantile(scores, np.linspace(0.90, 0.99995, 500)))
    for t in cands:
        if episodes(epochs, scores > t) / max(hours, 1e-9) <= budget:
            return float(t)
    return float(scores.max())


def envelope_rows(stream: pd.DataFrame, bounds: Dict[str, Any]) -> np.ndarray:
    out = np.zeros(len(stream), bool)
    for s in SENSORS:
        x = stream[s].to_numpy(dtype=np.float64)
        out |= (x < bounds[s]["envelope_lo"]) | (x > bounds[s]["envelope_hi"])
    return out


def bounds_rule_validation(stream: pd.DataFrame, bounds: Dict[str, Any]) -> Dict[str, Any]:
    outside = envelope_rows(stream, bounds)
    res: Dict[str, Any] = {}
    for b in ("train", "val", "test"):
        m = (stream["block"] == b).to_numpy()
        att, nor = m & stream["label"].to_numpy(), m & ~stream["label"].to_numpy()
        hrs = nor.sum() / 3600.0
        segs = stream[att]["seg"].unique()
        seg_hit = int(sum(outside[(stream["seg"] == s).to_numpy()].any() for s in segs))
        res[b] = {"normal_rows": int(nor.sum()), "normal_rows_outside": int((outside & nor).sum()),
                  "normal_false_alarm_rate": float((outside & nor).sum() / max(1, nor.sum())),
                  "false_alarm_episodes_per_normal_hour": round(episodes(stream["epoch"].to_numpy(), outside & nor) / hrs, 3) if hrs else None,
                  "attack_rows": int(att.sum()), "attack_rows_outside": int((outside & att).sum()),
                  "attack_row_recall": float((outside & att).sum() / max(1, att.sum())),
                  "segments": int(len(segs)), "segments_with_any_row_outside": seg_hit}
    return res


def run(data_dir: str, out_dir: str, seed: int, fixture: bool) -> Dict[str, Any]:
    t0 = time.time()
    out_real = os.path.realpath(out_dir)
    if out_real == WEIGHTS_DIR or out_real.startswith(WEIGHTS_DIR + os.sep):
        raise SystemExit("refusing to write into models/weights - write candidates, then promote after approval")
    stream, info = load_stream(data_dir, SENSORS + ACTUATORS)
    train_norm = stream[(stream["block"] == "train") & ~stream["label"]]
    if len(train_norm) < 5000:
        raise SystemExit("too few train-block normal rows to measure bounds")
    bounds = compute_bounds(train_norm[SENSORS])
    norm = Norm(bounds)
    X, meta = build_windows(stream, norm, stride=STRIDE)
    y, blk = meta["label"].to_numpy().astype(int), meta["block"].to_numpy()
    tr, va, te = blk == "train", blk == "val", blk == "test"
    log.info("windows: %d (train %d / val %d / test %d); attack windows %d", len(y), tr.sum(), va.sum(), te.sum(), y.sum())
    if (y[tr] == 0).sum() < 200 or y[tr].sum() < 5:
        raise SystemExit("too few train windows (normal or attack)")

    rng = np.random.default_rng(seed)
    nrm_idx = np.flatnonzero(tr & (y == 0))
    nrm_idx = rng.choice(nrm_idx, size=min(60000, nrm_idx.size), replace=False)
    n1, n0 = max(1, int(y[tr].sum())), max(1, int((y[tr] == 0).sum()))
    w = np.where(y[tr] == 1, len(y[tr]) / (2.0 * n1), len(y[tr]) / (2.0 * n0))
    ep = meta["epoch"].to_numpy()

    # validation selection excludes any segment holding > 50 % of the block's attack windows
    seg_w = meta["seg"].to_numpy()
    dominant = [int(sg) for sg in np.unique(seg_w[va & (y == 1)]) if (seg_w[va & (y == 1)] == sg).sum() > 0.5 * max(1, (va & (y == 1)).sum())]
    sel_mask = va & ~np.isin(seg_w, dominant)
    if y[sel_mask].sum() == 0:
        sel_mask = va
    from sklearn.metrics import average_precision_score
    best, best_ap, grid_log = ("full", GRID[0]), -1.0, []
    for vname in VARIANTS:
        for depth, leaf in GRID:
            m = PhysicalModel(random_state=seed).set_variant(vname)
            m.fit(X[nrm_idx[:2000]], bounds).fit_classifier(X[tr], y[tr], w, n_estimators=60, max_depth=depth, min_samples_leaf=leaf)
            ap = float(average_precision_score(y[sel_mask], m.attack_probability(X[sel_mask]))) if y[sel_mask].sum() else 0.0
            grid_log.append({"variant": vname, "max_depth": depth, "min_samples_leaf": leaf, "val_average_precision": round(ap, 4)})
            if ap > best_ap:
                best, best_ap = (vname, (depth, leaf)), ap
    variant, (depth, leaf) = best
    model = PhysicalModel(random_state=seed).set_variant(variant).fit(X[nrm_idx], bounds)
    model.fit_classifier(X[tr], y[tr], w, n_estimators=150, max_depth=depth, min_samples_leaf=leaf)

    # classifier threshold by FALSE-ALARM BUDGET on validation normal windows (episodes per normal hour)
    vn = va & (y == 0)
    val_hours = float(((stream["block"] == "val") & ~stream["label"]).sum()) / 3600.0
    p_val = model.attack_probability(X[vn])
    thr_by_budget = {bud: threshold_for_budget(p_val, ep[vn], val_hours, bud) for bud in BUDGETS}
    model.clf_threshold = thr_by_budget[DEFAULT_BUDGET]
    thr_note = f"false-alarm budget {DEFAULT_BUDGET} alarm episodes per normal hour on validation"
    f1_thr, f1_note = best_f1_threshold(y[va], model.attack_probability(X[va]))
    # per-variant test ROC-AUC shown for transparency only (never used for selection)
    variant_test_auc = {}
    for vname in VARIANTS:
        m = PhysicalModel(random_state=seed).set_variant(vname)
        m.fit(X[nrm_idx[:2000]], bounds).fit_classifier(X[tr], y[tr], w, n_estimators=60, max_depth=depth, min_samples_leaf=leaf)
        variant_test_auc[vname] = ranking(y[te], m.attack_probability(X[te])).get("roc_auc")

    def evaluate(mask: np.ndarray) -> Dict[str, Any]:
        s_if, s_clf = model.anomaly_scores(X[mask]), model.attack_probability(X[mask])
        f_if, f_clf = s_if > model.threshold, s_clf > model.clf_threshold
        return {"isolation_forest": {**confusion(y[mask], f_if), **ranking(y[mask], s_if)},
                "classifier": {**confusion(y[mask], f_clf), **ranking(y[mask], s_clf)},
                "combined_either": confusion(y[mask], f_if | f_clf),
                "baseline_flag_everything": confusion(y[mask], np.ones(mask.sum(), bool))}

    results = {"train": evaluate(tr), "val": evaluate(va), "test": evaluate(te)}
    flag = model.predict(X).astype(bool)

    # per-segment detection (+ latency, + "was the segment visible in the twin's 18 points at all")
    mu, sd = norm.mu, norm.sd
    seg_tables: Dict[str, List[Dict[str, Any]]] = {}
    outside = envelope_rows(stream, bounds)
    for b in ("val", "test"):
        rows = []
        for s in info["segments"]:
            if s["block"] != b:
                continue
            wmask = (meta["seg"].to_numpy() == s["id"])
            srows = (stream["seg"] == s["id"]).to_numpy()
            zmax = float(np.abs((stream.loc[srows, SENSORS].mean().to_numpy() - mu) / sd).max())
            start = float(stream.loc[srows, "epoch"].iloc[0])
            fl = wmask & flag
            rows.append({"segment": s["id"], "start": s["start"], "rows": s["rows"], "windows": int(wmask.sum()),
                         "flagged_windows": int(fl.sum()), "detected": bool(fl.any()),
                         "first_detection_s": float(ep[fl].min() - start) if fl.any() else None,
                         "max_sensor_shift_sd": round(zmax, 2), "visible_in_twin_sensors": bool(zmax > 3.0 or outside[srows].any()),
                         "rule_envelope_hit": bool(outside[srows].any())})
        seg_tables[b] = rows

    nh = float(((stream["block"] == "test") & ~stream["label"]).sum()) / 3600.0
    fa_mask = flag & te & (y == 0)
    curve = []
    seg_vis = {r["segment"]: r["visible_in_twin_sensors"] for r in seg_tables["test"]}
    p_te, s_te = model.attack_probability(X[te]), model.anomaly_scores(X[te])
    for label, thr in [(f"budget {b_} /h", thr_by_budget[b_]) for b_ in BUDGETS] + [("val-F1-optimal (run-1 rule)", f1_thr)]:
        fl = (p_te > thr) | (s_te > model.threshold)
        fl_n = fl & (y[te] == 0)
        seg_ids = meta["seg"].to_numpy()[te]
        det = [int(sg) for sg in np.unique(seg_ids[(y[te] == 1) & fl])]
        c_ = confusion(y[te], fl)
        curve.append({"setting": label, "classifier_threshold": float(thr), "precision": c_["precision"], "recall": c_["recall"], "f1": c_["f1"],
                      "false_alarm_episodes_per_normal_hour": round(episodes(ep[te], fl_n) / nh, 3) if nh else None,
                      "segments_detected": len(det), "visible_segments_detected": sum(1 for sg in det if seg_vis.get(sg))})
    bounds_val = bounds_rule_validation(stream, bounds)
    imp = sorted(zip(FEATURE_NAMES, model._clf.feature_importances_), key=lambda kv: -kv[1])[:15]

    model.metadata.update({"trained_on": "SWaT only (local archive)", "fixture": fixture, "if_threshold": model.threshold,
                           "clf_threshold": model.clf_threshold, "clf_threshold_note": thr_note, "seed": seed,
                           "flag_rule": "isolation_forest > if_threshold OR attack_probability > clf_threshold",
                           "inputs": {"sensors": SENSORS, "actuators": ACTUATORS}, "selected_variant": variant,
                           "false_alarm_budget_per_hour": DEFAULT_BUDGET})
    os.makedirs(out_dir, exist_ok=True)
    model.save(os.path.join(out_dir, "physical_model.joblib"))
    with open(os.path.join(out_dir, "swat_bounds.json"), "w", encoding="utf-8") as fh:
        json.dump({"source": "SWaT train-block (22-29 Dec 2015) NORMAL rows only; aggregate statistics, no raw data",
                   "fixture_not_real_results": fixture, "envelope": "[p0.1, p99.9] widened by 10% of that span",
                   "rows_used": int(len(train_norm)), "sensors": bounds}, fh, indent=2)

    report = {
        "fixture_not_real_results": fixture, "generated": time.strftime("%Y-%m-%d %H:%M:%S"), "seconds": round(time.time() - t0, 1),
        "environment": {"python": sys.version.split()[0], "platform": platform.platform(), "numpy": np.__version__,
                        "pandas": pd.__version__, "sklearn": __import__("sklearn").__version__},
        "data": {k: info[k] for k in ("rows_read", "rows", "duplicate_timestamps_dropped", "duplicates_exact", "duplicates_conflicting",
                                      "chunks", "n_segments", "blocks")},
        "windows": {"window_seconds": WINDOW, "stride_seconds": STRIDE, "total": int(len(y)), "attack": int(y.sum()),
                    "by_block": {b: {"windows": int((blk == b).sum()), "attack_windows": int(y[blk == b].sum())} for b in ("train", "val", "test")}},
        "classifier_selection": {"grid": grid_log, "chosen": {"variant": variant, "max_depth": depth, "min_samples_leaf": leaf},
                                 "validation_selection_excludes_segments": dominant, "variant_test_roc_auc_transparency_only": variant_test_auc},
        "operating_curve_test": curve,
        "thresholds": {"isolation_forest": model.threshold, "classifier": model.clf_threshold, "classifier_note": thr_note},
        "results": results, "segments": seg_tables,
        "test_false_alarms": {"normal_windows_flagged": int(fa_mask.sum()), "episodes": episodes(ep, fa_mask),
                              "normal_hours": round(nh, 2), "episodes_per_normal_hour": round(episodes(ep, fa_mask) / nh, 3) if nh else None},
        "bounds_rule_validation": bounds_val, "bounds": bounds,
        "top_features": [{"feature": f, "importance": round(float(v), 4)} for f, v in imp],
        "provenance": [{"feature": f, "source": s, "status": st} for f, s, st in PROVENANCE],
        "dropped_inputs": [{"input": f, "reason": r} for f, r in DROPPED_INPUTS],
    }
    with open(os.path.join(out_dir, "physical_training_report.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)
    with open(os.path.join(out_dir, "physical_training_report.md"), "w", encoding="utf-8") as fh:
        fh.write(render_markdown(report))
    log.info("candidate + bounds + report -> %s (%.1fs)", out_dir, time.time() - t0)
    return report


def _f(v: Any) -> str:
    return "n/a" if v is None else (f"{v:.3f}" if isinstance(v, float) else str(v))


def render_markdown(r: Dict[str, Any]) -> str:
    L: List[str] = ["# PhysicalModel - SWaT-only training report (CANDIDATE)", ""]
    if r["fixture_not_real_results"]:
        L += ["> **SYNTHETIC FIXTURE RUN - these numbers describe generated test data, NOT SWaT. Never cite them.**", ""]
    d, w = r["data"], r["windows"]
    L += ["## Scope and honesty notes", "",
          "* Trained and evaluated on **SWaT only**; inputs are limited to the twin's SWaT-backed points (10 sensors, 8 actuators) so the model can run live.",
          "* Window label = attack flag of the window's last second (one binary flag per row). Segments whose attacked points are not among the twin's 18 inputs are "
          "invisible by construction; the per-segment table says which segments were visible at all.",
          "* The old health/RUL output is removed: SWaT has no degradation labels, so it cannot be derived and is never invented.",
          "* Calendar drift between days exists in SWaT; held-out blocks are later days than training, so drift counts against the model (honestly).", "",
          "## Data", "", f"* rows {d['rows']:,} after de-duplication; segments {d['n_segments']}; chunks {d['chunks']}", "",
          f"* windows: {w['window_seconds']} s, stride {w['stride_seconds']} s; total {w['total']:,}, attack {w['attack']:,}", "",
          "| block | windows | attack windows | segments |", "|---|---|---|---|"]
    for b in ("train", "val", "test"):
        L.append(f"| {b} | {w['by_block'][b]['windows']:,} | {w['by_block'][b]['attack_windows']:,} | {d['blocks'][b]['segments']} |")
    sel = r["classifier_selection"]
    L += ["", "## Regularisation and thresholds (chosen WITHOUT the test block)", "",
          "> REVISION NOTE: this selection protocol (feature variants, false-alarm-budget thresholds, exclusion of dominating segments) was introduced AFTER "
          "run 1 showed validation dominated by one segment and a large train/test gap. The test block is therefore not pristine for this revised pipeline.", "",
          f"Validation selection excludes segment(s) {sel['validation_selection_excludes_segments']} (each holds > 50 % of the validation attack windows).", "",
          "| variant | max_depth | min_samples_leaf | validation AP |", "|---|---|---|---|"]
    L += [f"| {g['variant']} | {g['max_depth']} | {g['min_samples_leaf']} | {g['val_average_precision']} |" for g in sel["grid"]]
    L += ["", f"Chosen: {sel['chosen']}. Isolation Forest threshold {r['thresholds']['isolation_forest']:.4f} (99.5th pct of train-normal scores); "
          f"classifier threshold {r['thresholds']['classifier']:.4f} ({r['thresholds']['classifier_note']}).",
          f"Variant test ROC-AUC, shown for transparency only (never used for selection): {sel['variant_test_roc_auc_transparency_only']}", "",
          "## Held-out TEST block (1-2 Jan) - window-level confusion matrices", ""]
    for name, key in (("Isolation Forest", "isolation_forest"), ("Supervised classifier", "classifier"),
                      ("Combined (either)", "combined_either"), ("Baseline: flag everything", "baseline_flag_everything")):
        c = r["results"]["test"][key]
        L += [f"**{name}**", "", "| | predicted normal | predicted attack |", "|---|---|---|",
              f"| actual normal | {c['tn']} | {c['fp']} |", f"| actual attack | {c['fn']} | {c['tp']} |", "",
              f"precision {_f(c['precision'])}, recall {_f(c['recall'])}, F1 {_f(c['f1'])}"
              + (f", ROC-AUC {_f(c.get('roc_auc'))}, AP {_f(c.get('average_precision'))}" if "roc_auc" in c else ""), ""]
    fa = r["test_false_alarms"]
    L += [f"Test false alarms: {fa['normal_windows_flagged']} normal windows flagged = {fa['episodes']} alarm episodes over {fa['normal_hours']} normal hours "
          f"({_f(fa['episodes_per_normal_hour'])} per hour).", "", "## Validation block (for transparency)", "",
          "| model | precision | recall | F1 | ROC-AUC |", "|---|---|---|---|---|"]
    for key in ("isolation_forest", "classifier", "combined_either"):
        c = r["results"]["val"][key]
        L.append(f"| {key} | {_f(c['precision'])} | {_f(c['recall'])} | {_f(c['f1'])} | {_f(c.get('roc_auc'))} |")
    L += ["", "ROC-AUC train / val / test (classifier): " + " / ".join(_f(r["results"][b]["classifier"].get("roc_auc")) for b in ("train", "val", "test")),
          "", "## Per-segment detection (combined flag)", ""]
    for b in ("val", "test"):
        segs = r["segments"][b]
        vis = [s for s in segs if s["visible_in_twin_sensors"]]
        L += [f"**{b}**: {len(segs)} segments; {len(vis)} visible in the twin's sensors (shift > 3 sd or outside the measured envelope); "
              f"{sum(s['detected'] for s in segs)} detected, of which {sum(s['detected'] for s in vis)} among the visible ones", "",
              "| segment | start | rows | windows | flagged | first detection (s) | max shift (sd) | visible | envelope hit |", "|---|---|---|---|---|---|---|---|---|"]
        L += [f"| {s['segment']} | {s['start']} | {s['rows']} | {s['windows']} | {s['flagged_windows']} | {_f(s['first_detection_s'])} | "
              f"{s['max_sensor_shift_sd']} | {s['visible_in_twin_sensors']} | {s['rule_envelope_hit']} |" for s in segs]
        L.append("")
    L += ["## Operating curve on the TEST block (threshold set on validation; Isolation Forest threshold fixed)", "",
          "| setting | classifier thr | precision | recall | F1 | false-alarm episodes / normal hour | segments detected (of 10) | visible segments detected |", "|---|---|---|---|---|---|---|---|"]
    L += [f"| {c['setting']} | {c['classifier_threshold']:.3f} | {_f(c['precision'])} | {_f(c['recall'])} | {_f(c['f1'])} | "
          f"{_f(c['false_alarm_episodes_per_normal_hour'])} | {c['segments_detected']} | {c['visible_segments_detected']} |" for c in r["operating_curve_test"]]
    L += ["", "## Measured-envelope RULE validated on held-out data", "",
          "Rule: a sensor outside its measured train-normal envelope [p0.1, p99.9] widened by 10 % is a violation. This is a RULE validated on real SWaT, not a model.", "",
          "| block | normal rows outside | false-alarm episodes / normal hour | attack-row recall | segments with any row outside |", "|---|---|---|---|---|"]
    for b in ("train", "val", "test"):
        v = r["bounds_rule_validation"][b]
        L.append(f"| {b} | {v['normal_rows_outside']:,} of {v['normal_rows']:,} ({v['normal_false_alarm_rate']:.2%}) | {_f(v['false_alarm_episodes_per_normal_hour'])} | "
                 f"{v['attack_row_recall']:.2%} | {v['segments_with_any_row_outside']} of {v['segments']} |")
    L += ["", "## Measured bounds (train-block normal rows)", "", "| sensor | min | p0.1 | median | p99.9 | max | envelope lo | envelope hi |", "|---|---|---|---|---|---|---|---|"]
    for s, b in r["bounds"].items():
        L.append(f"| {s} | {b['min']:.2f} | {b['p0.1']:.2f} | {b['median']:.2f} | {b['p99.9']:.2f} | {b['max']:.2f} | {b['envelope_lo']:.2f} | {b['envelope_hi']:.2f} |")
    L += ["", "## Top features (classifier importance)", "", "| feature | importance |", "|---|---|"]
    L += [f"| {t['feature']} | {t['importance']} |" for t in r["top_features"]]
    L += ["", "## Feature provenance", "", "| feature | SWaT source / derivation | status |", "|---|---|---|"]
    L += [f"| {p['feature']} | {p['source']} | {p['status']} |" for p in r["provenance"]]
    L += ["", "Inputs NOT used:", "", "| input | reason |", "|---|---|"] + [f"| {p['input']} | {p['reason']} |" for p in r["dropped_inputs"]]
    L += ["", "## Reproducibility", "", f"`{json.dumps(r['environment'])}`", ""]
    return "\n".join(L)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s - %(message)s")
    ap = argparse.ArgumentParser(description="Train the PhysicalModel on SWaT only (writes CANDIDATES).")
    ap.add_argument("--data-dir")
    ap.add_argument("--fixture", action="store_true", help="synthetic SWaT-SHAPED fixture (code check only)")
    ap.add_argument("--candidate", action="store_true", help="required acknowledgement: output is a candidate")
    ap.add_argument("--out-dir", default=DEFAULT_OUT)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    if not args.candidate:
        ap.error("pass --candidate (weights are only ever written as candidates; promote after approval)")
    if args.fixture:
        from tests.swat_fixture import make_swat_archive
        tmp = tempfile.mkdtemp(prefix="swat-fixture-")
        make_swat_archive(tmp, seed=0)
        run(tmp, args.out_dir, args.seed, fixture=True)
    elif args.data_dir:
        run(args.data_dir, args.out_dir, args.seed, fixture=False)
    else:
        ap.error("give --data-dir or --fixture")


if __name__ == "__main__":
    main()
