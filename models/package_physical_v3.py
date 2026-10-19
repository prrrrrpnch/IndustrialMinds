"""
models/package_physical_v3.py - turn a REVIEWED v3 candidate into the live weights file models/weights/physical_model_v3.joblib.

    python -m models.package_physical_v3 --budget 0.5 --report-json models/candidates/physical_v3/physical_v3_report.json

Refuses unless the user approved replacing the physical model this session (python3 .claude/hooks/confirm.py retrain physical, only after the
user says yes in chat), refuses a candidate trained on the synthetic fixture, and never overwrites an existing weights file. It does not
touch physical_model.joblib (v1) or physical_model_v2.joblib (v2): both stay as fallbacks. Packaging does NOT make v3 the default: the
middleware uses v3 only with IM_PHYSICAL_MODEL=v3 until the default is changed deliberately.

--report-json embeds the report's HELD-OUT test numbers for the chosen budget into the weights' metadata, so the numbers travel with the model.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, Optional

import joblib

from models.promote_candidate import approved
from swat import features_v3 as F3

ROOT = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
CAND = os.path.join(ROOT, "models", "candidates", "physical_v3", "physical_v3_candidate.joblib")
OUT = os.path.join(ROOT, "models", "weights", "physical_model_v3.joblib")
REPORT = "models/candidates/physical_v3/physical_v3_report.md (copy the reviewed report to docs/reports/ when promoting)"


def package(src: str, out: str, budget: str, report_json: Optional[str] = None, check_approval: bool = True,
            allow_fixture: bool = False) -> int:
    if check_approval and not approved("physical"):
        print("REFUSED: promotion of the physical model was not approved this session")
        return 1
    blob = joblib.load(src)
    if blob.get("fixture") and not allow_fixture:
        print("REFUSED: that candidate was trained on the synthetic fixture, not SWaT")
        return 1
    if blob.get("schema") != F3.FEATURE_VERSION or list(blob.get("feature_names", [])) != F3.FEATURE_NAMES:
        print("REFUSED: candidate feature schema does not match swat/features_v3.py (retrain with the current code)")
        return 1
    rules = blob["alarm_rules"].get(str(budget))
    rule = rules and rules.get("selected_without_persistence")
    if not rule or rule.get("threshold") is None:
        print(f"REFUSED: no threshold met the {budget}/h false-alarm budget on the development scores")
        return 1
    if os.path.exists(out):
        print("REFUSED: output exists (never overwrite weights)")
        return 1
    meta: Dict[str, Any] = {"window": F3.LONG, "variant": "v3", "recipe": blob["recipe"], "false_alarm_budget_per_hour": float(budget),
                            "threshold_rule": "out-of-fold development threshold at the budget, no persistence", "report": REPORT,
                            "trained_on": "SWaT train+validation blocks (segment-grouped CV for selection, cross-fitted normal models)",
                            "note": "advisory: flags become ALERT, never DROP"}
    if report_json:
        with open(report_json) as fh:
            rep = json.load(fh)
        t = rep["test"].get(str(budget), {}).get("selected_without_persistence", {})
        keep = ("precision", "recall", "f1", "accuracy", "balanced_accuracy", "false_positive_rate", "alarm_episodes_per_benign_hour",
                "segments_detected", "segments_total", "median_latency_s", "roc_auc", "tn", "fp", "fn", "tp")
        meta["held_out_test_block"] = {k: t.get(k) for k in keep}
        meta["held_out_test_block"]["bootstrap_95ci"] = t.get("bootstrap_95ci")
    import sklearn
    meta["sklearn"] = sklearn.__version__
    packed = {"schema": F3.FEATURE_VERSION, "feature_names": F3.FEATURE_NAMES, "recipe": blob["recipe"], "heads": blob["heads"],
              "head_meta": blob["head_meta"], "normal_models": blob["normal_models"], "stacker": blob["stacker"], "norm_stats": blob["norm_stats"],
              "clf_threshold": float(rule["threshold"]), "metadata": meta}
    os.makedirs(os.path.dirname(out), exist_ok=True)
    joblib.dump(packed, out)
    print(f"wrote {out} (recipe {blob['recipe']}, threshold {rule['threshold']:.4f}, budget {budget}/h)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--budget", default="0.5")
    ap.add_argument("--src", default=CAND)
    ap.add_argument("--out", default=OUT)
    ap.add_argument("--report-json", default=None)
    a = ap.parse_args()
    return package(a.src, a.out, a.budget, a.report_json)


if __name__ == "__main__":
    sys.exit(main())
