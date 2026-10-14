"""
models/train_models.py - deterministic SYNTHETIC training for the PhysicalModel (replaced by SWaT in Phase 6).

The CyberModel is no longer trained here: it is SWaT-only (see models/train_cyber_swat.py).

    python -m models.train_models            # writes models/weights/*.joblib + training_report.json

Same seeds -> same synthetic data -> same trees -> same scores. Validation
uses trajectories/commands generated with DIFFERENT seeds than training.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import time
from typing import Dict, List, Tuple

import numpy as np

from docs.interfaces import MACHINES, NUM_REGISTERS
from models.physical_model import (
    DEFAULT_WEIGHTS as PHYS_W, DEFAULT_WINDOW, PhysicalModel, WINDOW_FEATURE_NAMES,
    series_to_steps, window_features,
)
from models.telemetry_generator import (
    RUL_HORIZON_HOURS, generate_channel,
)

log = logging.getLogger("industrialmind.train")
HERE = os.path.dirname(os.path.abspath(__file__))
REPORT = os.path.join(HERE, "weights", "training_report.json")

_SPANS = np.array([float(m["max"] - m["min"]) or 1.0 for m in MACHINES])
_MINS = np.array([float(m["min"]) for m in MACHINES])


# ---------------------------------------------------------------------------
# Physical dataset
# ---------------------------------------------------------------------------

def physical_dataset(seed: int, trajectories_per_machine: int, length: int = 1500,
                     window: int = DEFAULT_WINDOW, stride: int = 25) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Returns (X window features, y RUL hours, is_healthy_trajectory flag)."""
    rng = np.random.default_rng(seed)
    X: List[np.ndarray] = []
    y: List[float] = []
    healthy: List[bool] = []
    for reg in range(NUM_REGISTERS):
        span, lo = _SPANS[reg:reg + 1], _MINS[reg:reg + 1]
        for _ in range(trajectories_per_machine):
            start = None if rng.random() < 0.35 else float(rng.uniform(0.0, 0.6))
            tr = generate_channel(reg, length, rng, degradation_start=start)
            steps = series_to_steps(tr.values[:, None], span, lo)[:, 0, :]
            for end in range(window + 2, length + 1, stride):
                X.append(window_features(steps[end - window:end]))
                y.append(float(tr.rul_hours[end - 1]))
                healthy.append(start is None)
    return np.vstack(X), np.array(y), np.array(healthy)


def train_physical(seed: int = 101, val_seed: int = 202, per_machine: int = 40) -> Tuple[PhysicalModel, Dict]:
    X, y, _ = physical_dataset(seed, per_machine)
    model = PhysicalModel().fit(X, y)

    Xv, yv, hv = physical_dataset(val_seed, 12)
    pred = model.predict(Xv)
    hi_true, hi_pred = yv / RUL_HORIZON_HOURS, pred / RUL_HORIZON_HOURS
    metrics = {
        "train_windows": int(X.shape[0]),
        "validation_windows": int(Xv.shape[0]),
        "rul_mae_hours": round(float(np.abs(pred - yv).mean()), 2),
        "health_index_mae": round(float(np.abs(hi_pred - hi_true).mean()), 4),
        "health_index_r2": round(float(1 - ((hi_pred - hi_true) ** 2).sum() / ((hi_true - hi_true.mean()) ** 2).sum()), 4),
        "healthy_trajectories_mean_health": round(float(hi_pred[hv].mean()), 4),
        "healthy_trajectories_p05_health": round(float(np.quantile(hi_pred[hv], 0.05)), 4),
        "near_failure_mean_health (true HI<0.1)": round(float(hi_pred[hi_true < 0.1].mean()), 4),
        "feature_importances": {n: round(float(v), 4) for n, v in
                                zip(WINDOW_FEATURE_NAMES, model._model.feature_importances_)},
    }
    return model, metrics


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s - %(message)s")
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="smaller datasets (for CI)")
    args = ap.parse_args()

    t0 = time.time()
    log.info("CyberModel is trained on SWaT only: python -m models.train_cyber_swat --data-dir <archive> --candidate")

    log.info("Training PhysicalModel (Random Forest RUL) on synthetic run-to-failure trajectories ...")
    phys, pm = train_physical(per_machine=12 if args.quick else 40)
    phys.save(PHYS_W)
    log.info("PhysicalModel saved -> %s", PHYS_W)
    log.info("PhysicalModel validation: %s", {k: v for k, v in pm.items() if k != "feature_importances"})

    report = {"cyber_model": "see models/candidates/cyber_training_report.json (SWaT only)", "physical_model": pm, "training_seconds": round(time.time() - t0, 1),
              "deterministic_seeds": {"physical": [101, 202]}}
    os.makedirs(os.path.dirname(REPORT), exist_ok=True)
    with open(REPORT, "w") as fh:
        json.dump(report, fh, indent=2)
    log.info("Report -> %s (%.1fs)", REPORT, time.time() - t0)


if __name__ == "__main__":
    main()
