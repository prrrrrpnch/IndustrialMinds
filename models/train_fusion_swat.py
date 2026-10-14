"""
models/train_fusion_swat.py - Phase 7: orchestrator fusion model (scenario set from SWaT + constructed cyber failures).

    python -m models.train_fusion_swat --data-dir "C:\\IndustrialMind\\SWaT_dataset\\archive" --sample 20
    python -m models.train_fusion_swat --fixture --sample 20          # synthetic SWaT-SHAPED data, format check only

TRAIN MODE (approved protocol; candidate only):
    python -m models.train_fusion_swat --data-dir "C:\\IndustrialMind\\SWaT_dataset\\archive" --candidate
  Train-block physical outputs are OUT-OF-FOLD (cross-fitted: attack windows folded by segment, benign by hour), the
  dominant attack segment's weight is capped to the median segment's, a gradient-boosted classifier + ALERT threshold are
  chosen on the VALIDATION block (false-alarm budget), the TEST block is touched once. Writes orchestrator_model.joblib
  and a report to models/candidates/. It never touches models/weights/.

SAMPLE MODE (previous gate): builds the scenario set with the PROMOTED physical model, prints ~20 stratified labelled
rows, the composition of the full set and the HEADROOM (how often the naive four-branch lookup on the observed
flags, and the current AND-gate, disagree with the ground-truth decision). Writes fusion_sample_rows.csv and
fusion_scenario_summary.json to --out-dir. It does NOT train anything: training waits for approval of the sample.

Rows contain derived model scores and flags for specific windows (no raw SWaT sensor rows).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import tempfile
from typing import Any, Dict

import numpy as np
import pandas as pd

from models.physical_model import PhysicalModel
from swat.fusion_scenarios import (CLASSES, FEATURES, and_gate, build_scenarios, naive_lookup, sample_rows)
from swat.loader import load_stream
from swat.physical_features import ACTUATORS, SENSORS

log = logging.getLogger("industrialmind.train_fusion_swat")
HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT = os.path.join(HERE, "candidates")


def summarise(df: pd.DataFrame) -> Dict[str, Any]:
    out: Dict[str, Any] = {"rows": int(len(df))}
    out["by_source_and_decision"] = {f"{s}/{d}": int(n) for (s, d), n in df.groupby(["source", "decision"]).size().items()}
    out["by_block"] = {b: int(n) for b, n in df.groupby("block").size().items()}
    real = df[df["source"] == "swat_real"]
    for name, pred in (("naive_lookup_on_observed_flags", naive_lookup(real)), ("current_and_gate", and_gate(real))):
        wrong = pred != real["decision"].to_numpy()
        out[f"headroom_{name}"] = {
            "disagreement_with_truth_on_real_rows": float(wrong.mean()),
            "missed_attack_windows": int(((real["decision"] == "ALERT") & (pred == "PASS")).sum()),
            "false_alarm_windows": int(((real["decision"] == "PASS") & (pred != "PASS")).sum()),
        }
    return out


GRID = [dict(max_depth=d, max_iter=it, l2_regularization=l2, min_samples_leaf=ml, learning_rate=0.05)
        for d in (2, 3) for it in (100, 300) for l2 in (1.0, 10.0) for ml in (50, 200)]
PHYS_BUDGET_PER_H = 0.5
EPISODE_GAP_S = 30


def segment_weights(df: pd.DataFrame) -> np.ndarray:
    """Class-balanced weights; each attack segment's total weight is capped at the median segment's (segment 22 dominance)."""
    w = np.ones(len(df))
    att = (df["truth_physical_fail"].to_numpy()) & (df["source"].to_numpy() == "swat_real")
    seg = df["segment"].to_numpy()
    counts = pd.Series(seg[att]).value_counts()
    if len(counts):
        med = float(counts.median())
        for sg, n in counts.items():
            if n > med:
                w[att & (seg == sg)] = med / n
    y = (df["decision"] == "ALERT").to_numpy()
    if y.any():
        w[y] *= w[~y].sum() / w[y].sum()               # balance ALERT vs the rest
    return w


def episodes_per_hour(df: pd.DataFrame, flag: np.ndarray) -> float:
    """Alarm episodes per hour over the benign real windows of df (flags closer than EPISODE_GAP_S merge)."""
    b = df[(df["source"] == "swat_real") & (~df["truth_physical_fail"])]
    f = flag[b.index.to_numpy()] if len(flag) == len(df) else flag
    ep = np.sort(b["epoch"].to_numpy()[np.asarray(f, bool)])
    hours = max(len(b) * 5 / 3600.0, 1e-9)               # stride-5 windows
    n = 0 if ep.size == 0 else 1 + int((np.diff(ep) > EPISODE_GAP_S).sum())
    return n / hours


def threshold_for_budget(df: pd.DataFrame, score: np.ndarray, budget: float) -> float:
    cand = np.unique(np.quantile(score[(df["source"] == "swat_real").to_numpy()], np.linspace(0.5, 0.9999, 400)))
    best = float(cand[-1])
    for t in cand:
        if episodes_per_hour(df, score >= t) <= budget:
            best = float(t)
            break
    return best


def detection(df: pd.DataFrame, flag: np.ndarray) -> Dict[str, Any]:
    r = df[(df["source"] == "swat_real") & df["truth_physical_fail"]]
    f = np.asarray(flag)[r.index.to_numpy()]
    per = pd.Series(f).groupby(r["segment"].to_numpy()).any()
    return {"segments": int(len(per)), "segments_detected": int(per.sum()), "attack_window_recall": float(f.mean()) if len(f) else float("nan")}


def evaluate(df: pd.DataFrame, pred: np.ndarray, p_alert: np.ndarray) -> Dict[str, Any]:
    from sklearn.metrics import confusion_matrix, roc_auc_score
    out: Dict[str, Any] = {}
    for name, m in (("overall", np.ones(len(df), bool)), ("swat_real", (df["source"] == "swat_real").to_numpy()),
                    ("constructed", (df["source"] == "constructed").to_numpy())):
        cm = confusion_matrix(df["decision"][m], pred[m], labels=CLASSES)
        out[f"confusion_{name}"] = {"labels": CLASSES, "rows_truth_cols_pred": cm.tolist()}
    real = (df["source"] == "swat_real").to_numpy()
    y = df["truth_physical_fail"].to_numpy()[real].astype(int)
    out["roc_auc_fusion_p_alert_real"] = float(roc_auc_score(y, p_alert[real])) if 0 < y.sum() < len(y) else None
    out["roc_auc_physical_p_attack_real"] = float(roc_auc_score(y, df["phys_p_attack"].to_numpy()[real])) if 0 < y.sum() < len(y) else None
    out["fusion"] = {"alarm_episodes_per_h": episodes_per_hour(df, pred == "ALERT"), **detection(df, pred == "ALERT")}
    phys = (df["physical_pass"] == 0).to_numpy()
    out["physical_alone_at_promoted_operating_point"] = {"alarm_episodes_per_h": episodes_per_hour(df, phys), **detection(df, phys)}
    out["naive_lookup_accuracy"] = float((naive_lookup(df) == df["decision"].to_numpy()).mean())
    out["and_gate_accuracy_real"] = float((and_gate(df[real]) == df["decision"].to_numpy()[real]).mean())
    out["fusion_accuracy"] = float((pred == df["decision"].to_numpy()).mean())
    return out


def decide(clf: Any, df: pd.DataFrame, thr: float) -> Any:
    P = clf.predict_proba(df[FEATURES_USED].to_numpy(float))
    ci = {c: i for i, c in enumerate(clf.classes_)}
    p_alert, p_drop = P[:, ci["ALERT"]], P[:, ci["DROP"]]
    pred = np.where(p_drop >= 0.5, "DROP", np.where(p_alert >= thr, "ALERT", "PASS"))
    return pred, p_alert


FEATURES_USED = FEATURES


def train(df: pd.DataFrame, seed: int) -> Dict[str, Any]:
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.metrics import roc_auc_score
    tr, va, te = (df[df["block"] == b].reset_index(drop=True) for b in ("train", "val", "test"))
    if not len(tr) or not len(va) or not len(te):
        raise SystemExit("need train/val/test blocks in the scenario set")
    w = segment_weights(tr)
    seg_counts = va[(va["source"] == "swat_real") & va["truth_physical_fail"]]["segment"].value_counts()
    dominant = int(seg_counts.index[0]) if len(seg_counts) else -1
    sel = va[~((va["source"] == "swat_real") & (va["segment"] == dominant) & va["truth_physical_fail"])]
    sel_real = sel[sel["source"] == "swat_real"]
    best, trials = None, []
    for g in GRID:
        clf = HistGradientBoostingClassifier(random_state=seed, **g).fit(tr[FEATURES_USED].to_numpy(float), tr["decision"], sample_weight=w)
        P = clf.predict_proba(sel_real[FEATURES_USED].to_numpy(float))
        pa = P[:, list(clf.classes_).index("ALERT")]
        yy = sel_real["truth_physical_fail"].to_numpy().astype(int)
        auc = float(roc_auc_score(yy, pa)) if 0 < yy.sum() < len(yy) else 0.0
        trials.append({**g, "val_auc_excluding_dominant_segment": auc})
        if best is None or auc > best[0]:
            best = (auc, g, clf)
    _, g, clf = best
    p_alert_val = decide(clf, va, 2.0)[1]
    thr = threshold_for_budget(va, p_alert_val, PHYS_BUDGET_PER_H)
    val_pred, _ = decide(clf, va, thr)
    test_pred, test_pa = decide(clf, te, thr)
    return {"clf": clf, "thr": thr, "params": g, "trials": trials, "dominant_val_segment": dominant,
            "val": evaluate(va, val_pred, p_alert_val), "test": evaluate(te, test_pred, test_pa),
            "rows": {"train": len(tr), "val": len(va), "test": len(te)}}


def render_report(res: Dict[str, Any], fixture: bool) -> str:
    L = ["# Orchestrator fusion model - candidate report", ""]
    if fixture:
        L += ["**SYNTHETIC FIXTURE: format check only, never cite.**", ""]
    L += ["Protocol: out-of-fold physical outputs on train; dominant segment capped; classifier + ALERT threshold chosen on val; test touched once.",
          "Real-data evidence concerns the PHYSICAL side (PASS vs ALERT). DROP rows are constructed from deterministic cyber rules (scenario, not data).", "",
          f"Chosen params: `{res['params']}`; ALERT threshold {res['thr']:.4f} (val budget {PHYS_BUDGET_PER_H}/h); dominant val segment {res['dominant_val_segment']}", "",
          f"Rows: {res['rows']}", ""]
    for part in ("val", "test"):
        L += [f"## {part.upper()} block", "", "```", json.dumps(res[part], indent=2), "```", ""]
    L += ["## Grid trials", "", "```", json.dumps(res["trials"], indent=1), "```"]
    return "\n".join(L)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s - %(message)s")
    ap = argparse.ArgumentParser(description="Phase 7 orchestrator fusion model (sample mode until approved).")
    ap.add_argument("--data-dir")
    ap.add_argument("--fixture", action="store_true", help="synthetic SWaT-SHAPED fixture (format check only)")
    ap.add_argument("--weights", default=None, help="PhysicalModel weights (default: the promoted models/weights file)")
    ap.add_argument("--sample", type=int, default=20)
    ap.add_argument("--out-dir", default=DEFAULT_OUT)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--candidate", action="store_true", help="TRAIN mode: cross-fitted fusion model, written to models/candidates/")
    args = ap.parse_args()

    model = PhysicalModel.load(args.weights) if args.weights else PhysicalModel.load()
    if model.status != "OK":
        raise SystemExit(f"PhysicalModel not usable (status {model.status})")
    if args.fixture:
        from tests.swat_fixture import make_swat_archive
        data_dir = tempfile.mkdtemp(prefix="swat-fixture-")
        make_swat_archive(data_dir, seed=0)
    elif args.data_dir:
        data_dir = args.data_dir
    else:
        ap.error("give --data-dir or --fixture")

    stream, info = load_stream(data_dir, SENSORS + ACTUATORS)
    if args.candidate:
        import joblib
        df = build_scenarios(stream, model, seed=args.seed, cross_fit=True)
        res = train(df, args.seed)
        os.makedirs(args.out_dir, exist_ok=True)
        joblib.dump({"clf": res["clf"], "features": FEATURES_USED, "classes": CLASSES, "alert_threshold": res["thr"],
                     "drop_threshold": 0.5, "params": res["params"], "fixture": bool(args.fixture),
                     "provenance": "SWaT-only; cross-fitted physical outputs; candidate"}, os.path.join(args.out_dir, "orchestrator_model.joblib"))
        rep = render_report(res, bool(args.fixture))
        with open(os.path.join(args.out_dir, "fusion_training_report.md"), "w") as fh:
            fh.write(rep)
        print(rep)
        print(f"\nWrote candidate to {args.out_dir} (models/weights untouched). Paste fusion_training_report.md back for the Phase 7 gate.")
        return
    df = build_scenarios(stream, model, seed=args.seed)
    summ = summarise(df)
    summ["fixture_not_real_results"] = bool(args.fixture)
    sample = sample_rows(df, args.sample)
    os.makedirs(args.out_dir, exist_ok=True)
    sample.to_csv(os.path.join(args.out_dir, "fusion_sample_rows.csv"), index=False)
    with open(os.path.join(args.out_dir, "fusion_scenario_summary.json"), "w") as fh:
        json.dump(summ, fh, indent=2)

    if args.fixture:
        print("\n*** SYNTHETIC FIXTURE: rows illustrate the FORMAT only, never cite them ***")
    cols = ["scenario_id", "source", "block", "segment", "cyber_pass", "cyber_reason", "phys_if_score", "phys_p_attack",
            "physical_pass", "env_violations", "act_toggles", "decision"]
    pd.set_option("display.width", 250, "display.max_columns", 30)
    print("\n=== SAMPLE ROWS (stratified) ===")
    for kind, g in sample.groupby("kind", sort=False):
        print(f"\n-- {kind}")
        print(g[cols].round(3).to_string(index=False))
    print("\n=== COMPOSITION OF THE FULL SCENARIO SET ===")
    print(json.dumps({k: v for k, v in summ.items() if k != "rows"}, indent=2))
    print(f"rows: {summ['rows']:,}")
    print(f"\nWrote {os.path.join(args.out_dir, 'fusion_sample_rows.csv')} and fusion_scenario_summary.json")
    print("NO TRAINING was done. Paste this output back for the Phase 7 sample-row gate.")


if __name__ == "__main__":
    main()
