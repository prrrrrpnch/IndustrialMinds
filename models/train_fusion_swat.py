"""
models/train_fusion_swat.py - Phase 7: orchestrator fusion model (scenario set from SWaT + constructed cyber failures).

    python -m models.train_fusion_swat --data-dir "C:\\IndustrialMind\\SWaT_dataset\\archive" --sample 20
    python -m models.train_fusion_swat --fixture --sample 20          # synthetic SWaT-SHAPED data, format check only

SAMPLE MODE (this gate): builds the scenario set with the PROMOTED physical model, prints ~20 stratified labelled
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
from swat.fusion_scenarios import (CLASSES, and_gate, build_scenarios, naive_lookup, sample_rows)
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


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s - %(message)s")
    ap = argparse.ArgumentParser(description="Phase 7 orchestrator fusion model (sample mode until approved).")
    ap.add_argument("--data-dir")
    ap.add_argument("--fixture", action="store_true", help="synthetic SWaT-SHAPED fixture (format check only)")
    ap.add_argument("--weights", default=None, help="PhysicalModel weights (default: the promoted models/weights file)")
    ap.add_argument("--sample", type=int, default=20)
    ap.add_argument("--out-dir", default=DEFAULT_OUT)
    ap.add_argument("--seed", type=int, default=7)
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
