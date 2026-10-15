"""
models/package_physical_v2.py - turn the APPROVED v2 candidate into the live weights file (models/weights/physical_model_v2.joblib).

    python -m models.package_physical_v2 [--budget 0.5]

Refuses without the same approval promote_candidate uses (python3 .claude/hooks/confirm.py retrain physical, after the user says yes).
Does not touch physical_model.joblib (v1 stays as the fallback). Uses the 'selected without persistence' threshold for the budget.
"""

from __future__ import annotations

import argparse
import os
import sys

import joblib

from models.promote_candidate import approved
from swat.features_v2 import LONG, feature_names

ROOT = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
CAND = os.path.join(ROOT, "models", "candidates", "physical_v2", "physical_v2_candidate.joblib")
OUT = os.path.join(ROOT, "models", "weights", "physical_model_v2.joblib")
REPORT = "docs/reports/physical_training_report_v2_swat.md"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--budget", default="0.5")
    ap.add_argument("--src", default=CAND)
    ap.add_argument("--out", default=OUT)
    a = ap.parse_args()
    if not approved("physical"):
        print("REFUSED: promotion of the physical model was not approved this session")
        return 1
    b = joblib.load(a.src)
    if b.get("fixture"):
        print("REFUSED: that candidate was trained on the synthetic fixture, not SWaT")
        return 1
    rule = b["alarm_rules"][a.budget]["selected_without_persistence"]
    meta = {"feature_names": feature_names(b["feature_set"]), "window": LONG, "variant": "v2", "model_kind": b["model_kind"],
            "false_alarm_budget_per_hour": float(a.budget), "threshold_rule": "out-of-fold dev threshold at the budget, no persistence",
            "report": REPORT, "trained_on": "SWaT train+validation blocks (segment-grouped CV for selection)",
            "note": "advisory: flags become ALERT, never DROP; see the report for the held-out test numbers at this budget"}
    if str(a.budget) == "0.5":
        meta["test_block_result_at_0.5_budget"] = ("precision 0.461, recall 0.513, F1 0.485, 8/10 segments, "
                                                   "1.17 false-alarm episodes/h, ROC-AUC 0.836")
    import sklearn
    meta["sklearn"] = sklearn.__version__
    blob = {"schema": "physical_v2/1", "feature_set": b["feature_set"], "scorer": b["scorer"], "residual": b["residual"],
            "norm_stats": b["norm_stats"], "clf_threshold": float(rule["threshold"]), "metadata": meta}
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    if os.path.exists(a.out):
        print("REFUSED: output exists (never overwrite weights)")
        return 1
    joblib.dump(blob, a.out)
    print(f"wrote {a.out} (threshold {rule['threshold']:.4f}, budget {a.budget}/h)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
