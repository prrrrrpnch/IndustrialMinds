#!/usr/bin/env python3
"""
tools/twin_domain_gap.py - does a SWaT-trained PhysicalModel behave on the calibrated TWIN?

    python tools/twin_domain_gap.py --weights models/candidates/physical_model.joblib --hours 2

The model was trained on real SWaT; the twin is a synthetic plant calibrated to SWaT's measured operating
point. This script measures the DOMAIN GAP: how often the model (and the measured-envelope rule) alarms on a
HEALTHY twin, and how fast it reacts to a few synthetic actuator attacks. It is a measurement of this
demonstration plant ONLY - it says nothing about SWaT detection performance and must never be quoted as such.

Alarm sources are kept apart: the learned flag (threat_flag) vs the measured-envelope rule (bounds_violations).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

ROOT = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import numpy as np  # noqa: E402

from docs.interfaces import MACHINE_BY_NAME  # noqa: E402
from models.physical_model import PhysicalModel  # noqa: E402
from plc.twin import PlantTwin  # noqa: E402

SCENARIOS: Dict[str, Dict[str, float]] = {
    "p101_stop (raw pump stops)": {"P101": 5.0},
    "acid_overdose (HCl max, raw pump low)": {"P203": 100.0, "P101": 15.0},
    "chlorine_breakthrough (NaOCl max, UV off)": {"P205": 100.0, "UV401": 0.0},
    "ro_deadhead (RO pump max, reject valve shut)": {"P501": 100.0, "MV503": 0.0},
    "uf_valve_shut (UF feed valve closes)": {"MV302": 2.0},
}


def episodes(times: List[float], gap_s: float = 30.0) -> int:
    return 0 if not times else int(1 + (np.diff(sorted(times)) > gap_s).sum())


def run_nominal(model: PhysicalModel, hours: float, seed: int) -> Dict[str, Any]:
    tw = PlantTwin(noise=True, seed=seed)
    model.reset_window()
    flags: List[float] = []
    viol: List[float] = []
    scores: List[float] = []
    states: Dict[str, int] = {}
    secs = int(hours * 3600)
    for t in range(secs):
        for _ in range(10):
            tw.step(0.1)
        model.update(tw.values(), timestamp=float(t))
        r = model.assess()
        states[r["plant_state"]] = states.get(r["plant_state"], 0) + 1
        if r["status"] == "OK":
            scores.append(r["anomaly_score"])
            if r["threat_flag"]:
                flags.append(float(t))
            if r["bounds_violations"]:
                viol.append(float(t))
    ok = max(1, states.get("NORMAL", 0) + states.get("ALERT", 0))
    q = np.quantile(scores, [0.5, 0.95, 0.99, 1.0]) if scores else [None] * 4
    return {"simulated_hours": hours, "plant_state_seconds": states,
            "model_flag_seconds": len(flags), "model_flag_fraction": round(len(flags) / ok, 4),
            "model_alarm_episodes": episodes(flags), "model_alarm_episodes_per_hour": round(episodes(flags) / hours, 3),
            "envelope_violation_seconds": len(viol), "envelope_alarm_episodes_per_hour": round(episodes(viol) / hours, 3),
            "anomaly_score_quantiles_p50_p95_p99_max": [None if v is None else round(float(v), 4) for v in q],
            "isolation_forest_threshold": model.threshold, "backwashes": tw.backwashes}


def run_scenario(model: PhysicalModel, changes: Dict[str, float], seed: int, settle_s: int = 600, after_s: int = 900) -> Dict[str, Any]:
    tw = PlantTwin(noise=True, seed=seed)
    model.reset_window()
    first_flag: Optional[int] = None
    first_viol: Optional[int] = None
    pre_flags = 0
    for t in range(settle_s + after_s):
        if t == settle_s:
            for tag, v in changes.items():
                tw.set_target(MACHINE_BY_NAME[tag]["register"], v)
        for _ in range(10):
            tw.step(0.1)
        model.update(tw.values(), timestamp=float(t))
        r = model.assess()
        if r["status"] != "OK":
            continue
        if t < settle_s:
            pre_flags += int(r["threat_flag"] or bool(r["bounds_violations"]))
        else:
            if first_flag is None and r["threat_flag"]:
                first_flag = t - settle_s
            if first_viol is None and r["bounds_violations"]:
                first_viol = t - settle_s
    return {"changes": changes, "alarm_seconds_before_attack": pre_flags,
            "first_model_flag_after_s": first_flag, "first_envelope_violation_after_s": first_viol}


def run(weights: str, hours: float, seed: int) -> Dict[str, Any]:
    model = PhysicalModel.load(weights)
    if model.status != "OK":
        raise SystemExit(f"weights not usable (status {model.status}): {weights}")
    return {"label": "TWIN MEASUREMENT (synthetic plant calibrated to SWaT) - NOT SWaT detection performance",
            "weights": os.path.basename(weights), "selected_variant": model.variant,
            "nominal": run_nominal(model, hours, seed),
            "scenarios": {name: run_scenario(model, ch, seed + 1) for name, ch in SCENARIOS.items()}}


def render(rep: Dict[str, Any]) -> str:
    n = rep["nominal"]
    L = ["# Twin domain-gap report", "", f"> **{rep['label']}**", "",
         f"Weights `{rep['weights']}` (variant `{rep['selected_variant']}`).", "",
         f"## Nominal operation, {n['simulated_hours']} simulated hours, sensor noise on", "",
         f"* plant_state seconds: {n['plant_state_seconds']}",
         f"* learned-model flag: {n['model_flag_seconds']} s ({n['model_flag_fraction']:.2%}), {n['model_alarm_episodes']} alarm episodes = **{n['model_alarm_episodes_per_hour']} per hour**",
         f"* measured-envelope rule: {n['envelope_violation_seconds']} violating seconds, **{n['envelope_alarm_episodes_per_hour']} episodes per hour**",
         f"* Isolation Forest anomaly score p50/p95/p99/max: {n['anomaly_score_quantiles_p50_p95_p99_max']} against threshold {n['isolation_forest_threshold']:.4f}",
         f"* UF backwashes: {n['backwashes']}", "",
         "## Synthetic actuator attacks (10 min settle, then the change, 15 min observed)", "",
         "| scenario | alarm s before attack | first model flag (s after) | first envelope violation (s after) |", "|---|---|---|---|"]
    for name, s in rep["scenarios"].items():
        L.append(f"| {name} | {s['alarm_seconds_before_attack']} | {s['first_model_flag_after_s']} | {s['first_envelope_violation_after_s']} |")
    L += ["", "A value of `None` means no alarm within the observation window.", ""]
    return "\n".join(L)


def main() -> None:
    ap = argparse.ArgumentParser(description="Measure the SWaT-to-twin domain gap of a PhysicalModel.")
    ap.add_argument("--weights", required=True)
    ap.add_argument("--hours", type=float, default=2.0)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", default=None, help="folder for domain_gap_report.md/.json (default: print only)")
    a = ap.parse_args()
    rep = run(a.weights, a.hours, a.seed)
    text = render(rep)
    print(text)
    if a.out:
        os.makedirs(a.out, exist_ok=True)
        open(os.path.join(a.out, "domain_gap_report.md"), "w", encoding="utf-8").write(text)
        json.dump(rep, open(os.path.join(a.out, "domain_gap_report.json"), "w"), indent=2, default=str)


if __name__ == "__main__":
    main()
