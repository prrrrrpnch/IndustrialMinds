"""
models/train_cyber_swat.py - train the CyberModel on SWaT ONLY and write a CANDIDATE + report.

    python -m models.train_cyber_swat --data-dir "C:\\IndustrialMind\\SWaT_dataset\\archive" --candidate
    python -m models.train_cyber_swat --fixture --candidate        # synthetic SWaT-SHAPED fixture, code check only

Outputs (default models/candidates/, NEVER models/weights/):
    cyber_model.joblib            candidate weights (Isolation Forest + supervised head + thresholds)
    cyber_training_report.json    all numbers
    cyber_training_report.md      human-readable report incl. the feature provenance table

Protocol (agreed at the Phase 4 gate):
  * events = actuator state changes (swat/cyber_events.py); label = event lies inside an attack segment;
  * split by CALENDAR BLOCK, never by random rows: train 22-29 Dec, validation 30-31 Dec, test 1-2 Jan;
    a segment belongs wholly to one block;
  * Isolation Forest fits on TRAIN-block NORMAL events; the supervised head fits on TRAIN events with
    class-balanced weights; its threshold is chosen on the VALIDATION block (max F1); the TEST block is
    touched exactly once, for the reported numbers;
  * the rule-based checks (HMAC, replay, whitelist, rate limit) are not part of this evaluation because
    SWaT contains no signatures, replay tags or source addresses.
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

from models.cyber_model import CyberModel
from swat.cyber_events import (ACTUATOR_COLUMNS, DROPPED, FEATURE_NAMES, PROVENANCE, event_features, extract_events)
from swat.loader import load_stream

log = logging.getLogger("industrialmind.train_cyber_swat")
HERE = os.path.dirname(os.path.abspath(__file__))
WEIGHTS_DIR = os.path.realpath(os.path.join(HERE, "weights"))
DEFAULT_OUT = os.path.join(HERE, "candidates")


def confusion(y: np.ndarray, flag: np.ndarray) -> Dict[str, Any]:
    y, flag = y.astype(bool), flag.astype(bool)
    tp, fp = int((y & flag).sum()), int((~y & flag).sum())
    fn, tn = int((y & ~flag).sum()), int((~y & ~flag).sum())
    p = tp / (tp + fp) if tp + fp else None
    r = tp / (tp + fn) if tp + fn else None
    f1 = 2 * p * r / (p + r) if p and r else (0.0 if (p is not None and r is not None) else None)
    return {"tn": tn, "fp": fp, "fn": fn, "tp": tp, "precision": p, "recall": r, "f1": f1,
            "n": int(y.size), "attack_events": int(y.sum())}


def ranking(y: np.ndarray, score: np.ndarray) -> Dict[str, Any]:
    from sklearn.metrics import average_precision_score, roc_auc_score
    if y.sum() == 0 or y.sum() == len(y):
        return {"roc_auc": None, "average_precision": None}
    return {"roc_auc": float(roc_auc_score(y, score)), "average_precision": float(average_precision_score(y, score))}


def best_f1_threshold(y: np.ndarray, score: np.ndarray) -> Tuple[float, str]:
    """Threshold maximising F1 on the validation block (0.5 if it holds no attack events)."""
    if y.sum() == 0:
        return 0.5, "no attack events in validation block -> default 0.5"
    cands = np.unique(np.quantile(score, np.linspace(0.02, 0.99, 98)))
    best, best_f = 0.5, -1.0
    for t in cands:
        f = confusion(y, score > t)["f1"] or 0.0
        if f > best_f:
            best, best_f = float(t), f
    return best, f"max validation F1 = {best_f:.3f}"


def per_segment(events: pd.DataFrame, flag: np.ndarray, segments: List[Dict[str, Any]], block: str) -> List[Dict[str, Any]]:
    rows = []
    for s in segments:
        if s["block"] != block:
            continue
        m = (events["seg"].to_numpy() == s["id"])
        n, k = int(m.sum()), int(flag[m].sum())
        rows.append({"segment": s["id"], "start": s["start"], "rows": s["rows"], "events": n, "flagged": k,
                     "detected": bool(k > 0), "has_events": bool(n > 0)})
    return rows


def run(data_dir: str, out_dir: str, seed: int, fixture: bool) -> Dict[str, Any]:
    t0 = time.time()
    stream, info = load_stream(data_dir, list(ACTUATOR_COLUMNS))
    ev = extract_events(stream)
    if ev.empty:
        raise SystemExit("no actuator events extracted - check the data folder")
    X = event_features(ev)
    y = ev["label"].to_numpy().astype(int)
    blk = ev["block"].to_numpy()
    tr, va, te = blk == "train", blk == "val", blk == "test"
    log.info("events: %d (train %d / val %d / test %d); attack events %d", len(ev), tr.sum(), va.sum(), te.sum(), y.sum())
    if tr.sum() == 0 or (y[tr] == 0).sum() < 20:
        raise SystemExit("too few normal training events to fit the Isolation Forest")

    model = CyberModel(random_state=seed).fit(X[tr & (y == 0)])
    n1, n0 = max(1, int(y[tr].sum())), max(1, int((y[tr] == 0).sum()))
    w = np.where(y[tr] == 1, len(y[tr]) / (2.0 * n1), len(y[tr]) / (2.0 * n0))
    model.fit_classifier(X[tr], y[tr], sample_weight=w)
    model.clf_threshold, thr_note = best_f1_threshold(y[va], model.attack_probability(X[va]))

    def evaluate(mask: np.ndarray) -> Dict[str, Any]:
        s_if, s_clf = model.anomaly_scores(X[mask]), model.attack_probability(X[mask])
        f_if, f_clf = s_if > model.threshold, s_clf > model.clf_threshold
        return {"isolation_forest": {**confusion(y[mask], f_if), **ranking(y[mask], s_if)},
                "classifier": {**confusion(y[mask], f_clf), **ranking(y[mask], s_clf)},
                "combined_either": confusion(y[mask], f_if | f_clf),
                "baseline_flag_everything": confusion(y[mask], np.ones(mask.sum(), bool)),
                "baseline_flag_nothing": confusion(y[mask], np.zeros(mask.sum(), bool))}

    results = {"train": evaluate(tr), "val": evaluate(va), "test": evaluate(te)}
    flag_all = model.predict(X)
    seg_tables = {b: per_segment(ev, flag_all, info["segments"], b) for b in ("val", "test")}
    normal_hours_test = float(((stream["block"] == "test") & ~stream["label"]).sum()) / 3600.0
    fa_test = int(((flag_all == 1) & (y == 0) & te).sum())

    model.metadata.update({
        "trained_on": "SWaT only (local archive, actuator state-change events)", "fixture": fixture,
        "if_threshold": model.threshold, "clf_threshold": model.clf_threshold, "clf_threshold_note": thr_note,
        "flag_rule": "isolation_forest > if_threshold OR attack_probability > clf_threshold",
        "feature_names": list(FEATURE_NAMES), "seed": seed})
    os.makedirs(out_dir, exist_ok=True)
    out_real = os.path.realpath(out_dir)
    if out_real == WEIGHTS_DIR or out_real.startswith(WEIGHTS_DIR + os.sep):
        raise SystemExit("refusing to write into models/weights - write candidates, then promote after approval")
    model.save(os.path.join(out_dir, "cyber_model.joblib"))

    report = {
        "fixture_not_real_results": fixture,
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"), "seconds": round(time.time() - t0, 1),
        "environment": {"python": sys.version.split()[0], "platform": platform.platform(),
                        "numpy": np.__version__, "pandas": pd.__version__, "sklearn": __import__("sklearn").__version__},
        "data": {k: info[k] for k in ("files", "rows_read", "rows", "duplicate_timestamps_dropped", "duplicates_exact",
                                      "duplicates_conflicting", "chunks", "n_segments", "segments_crossing_midnight",
                                      "blocks", "nan_share")},
        "events": {"total": int(len(ev)), "attack": int(y.sum()), "by_actuator": ev.groupby("tag").size().to_dict(),
                   "by_block": {b: {"events": int((blk == b).sum()), "attack_events": int(y[blk == b].sum())}
                                for b in ("train", "val", "test")}},
        "thresholds": {"isolation_forest": model.threshold, "classifier": model.clf_threshold, "classifier_note": thr_note},
        "results": results, "segments": seg_tables,
        "test_false_alarms": {"normal_events_flagged": fa_test, "normal_hours": round(normal_hours_test, 2),
                              "per_normal_hour": round(fa_test / normal_hours_test, 3) if normal_hours_test else None},
        "provenance": [{"feature": f, "source": s, "status": st} for f, s, st in PROVENANCE],
        "dropped": [{"feature": f, "reason": s, "status": st} for f, s, st in DROPPED],
        "seeds": {"model": seed},
    }
    with open(os.path.join(out_dir, "cyber_training_report.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)
    with open(os.path.join(out_dir, "cyber_training_report.md"), "w", encoding="utf-8") as fh:
        fh.write(render_markdown(report))
    log.info("candidate + report -> %s (%.1fs)", out_dir, time.time() - t0)
    return report


def _fmt(v: Any) -> str:
    return "n/a" if v is None else (f"{v:.3f}" if isinstance(v, float) else str(v))


def render_markdown(r: Dict[str, Any]) -> str:
    L: List[str] = ["# CyberModel - SWaT-only training report (CANDIDATE)", ""]
    if r["fixture_not_real_results"]:
        L += ["> **SYNTHETIC FIXTURE RUN - these numbers describe generated test data, NOT SWaT. Never cite them.**", ""]
    d = r["data"]
    L += ["## Scope and honesty notes", "",
          "* Trained and evaluated on **SWaT only** (actuator state-change events, labelled by attack segment).",
          "* **Rule-based checks (HMAC, replay, whitelist, rate limit) are NOT evaluated here.** SWaT has no signatures, replay tags or source "
          "addresses; those rules are validated only by unit tests and the rule-tested/constructed scenarios in later phases.",
          "* SWaT has no network data: a 'command' is an actuator state change. Event labels are inherited from the attack window "
          "(1 binary flag per row), so some flagged-attack events may be ordinary control reactions.",
          "* The model abstains on commands with no SWaT counterpart (writes that do not flip on/off, sensors, MV503 which is twin-only).", "",
          "## Data", "",
          f"* rows after de-duplication: {d['rows']:,} (read {d['rows_read']:,}); duplicate timestamps dropped {d['duplicate_timestamps_dropped']:,} "
          f"(exact {d['duplicates_exact']:,}, conflicting {d['duplicates_conflicting']:,})",
          f"* chunks (gaps > 5 s): {d['chunks']}; attack segments: {d['n_segments']}; segments crossing midnight: {d['segments_crossing_midnight']}", "",
          "| block | rows | attack rows | segments | events | attack events |", "|---|---|---|---|---|---|"]
    for b in ("train", "val", "test"):
        bi, ei = d["blocks"][b], r["events"]["by_block"][b]
        L.append(f"| {b} | {bi['rows']:,} | {bi['attack_rows']:,} | {bi['segments']} | {ei['events']:,} | {ei['attack_events']:,} |")
    L += ["", f"Events per actuator: {r['events']['by_actuator']}", "",
          "## Thresholds (chosen WITHOUT the test block)", "",
          f"* Isolation Forest: {r['thresholds']['isolation_forest']:.4f} (99.5th percentile of train-normal scores)",
          f"* Classifier: {r['thresholds']['classifier']:.4f} ({r['thresholds']['classifier_note']})", "",
          "## Held-out TEST block (1-2 Jan) - confusion matrices", ""]
    for name, key in (("Isolation Forest", "isolation_forest"), ("Supervised classifier", "classifier"),
                      ("Combined (either)", "combined_either"), ("Baseline: flag everything", "baseline_flag_everything")):
        c = r["results"]["test"][key]
        L += [f"**{name}**", "", "| | predicted normal | predicted attack |", "|---|---|---|",
              f"| actual normal | {c['tn']} | {c['fp']} |", f"| actual attack | {c['fn']} | {c['tp']} |", "",
              f"precision {_fmt(c['precision'])}, recall {_fmt(c['recall'])}, F1 {_fmt(c['f1'])}"
              + (f", ROC-AUC {_fmt(c.get('roc_auc'))}, AP {_fmt(c.get('average_precision'))}" if "roc_auc" in c else ""), ""]
    fa = r["test_false_alarms"]
    L += [f"Test false alarms: {fa['normal_events_flagged']} normal events flagged over {fa['normal_hours']} normal hours "
          f"({_fmt(fa['per_normal_hour'])} per hour).", "", "## Validation block (for transparency)", "",
          "| model | precision | recall | F1 |", "|---|---|---|---|"]
    for key in ("isolation_forest", "classifier", "combined_either"):
        c = r["results"]["val"][key]
        L.append(f"| {key} | {_fmt(c['precision'])} | {_fmt(c['recall'])} | {_fmt(c['f1'])} |")
    L += ["", "## Per-segment detection (combined flag)", ""]
    for b in ("val", "test"):
        segs = r["segments"][b]
        with_ev = [s for s in segs if s["has_events"]]
        L += [f"**{b}**: {len(segs)} segments, {len(with_ev)} contain actuator events, {sum(s['detected'] for s in segs)} detected "
              f"(a segment with no actuator events cannot be detected by an event-based model)", "",
              "| segment | start | rows | events | flagged |", "|---|---|---|---|---|"]
        L += [f"| {s['segment']} | {s['start']} | {s['rows']} | {s['events']} | {s['flagged']} |" for s in segs]
        L.append("")
    L += ["## Feature provenance", "", "| feature | SWaT source / derivation | status |", "|---|---|---|"]
    L += [f"| {p['feature']} | {p['source']} | {p['status']} |" for p in r["provenance"]]
    L += ["", "Legacy 13-feature schema items that SWaT cannot supply:", "", "| legacy feature | why | handling |", "|---|---|---|"]
    L += [f"| {p['feature']} | {p['reason']} | {p['status']} |" for p in r["dropped"]]
    L += ["", "## Reproducibility", "", f"`{json.dumps(r['environment'])}`  seeds: {r['seeds']}", ""]
    return "\n".join(L)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s - %(message)s")
    ap = argparse.ArgumentParser(description="Train the CyberModel on SWaT only (writes a CANDIDATE).")
    ap.add_argument("--data-dir", help="folder holding normal.csv + attack.csv")
    ap.add_argument("--fixture", action="store_true", help="use a generated SWaT-SHAPED synthetic fixture (code check only)")
    ap.add_argument("--candidate", action="store_true", help="required acknowledgement: output goes to a candidates folder")
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
