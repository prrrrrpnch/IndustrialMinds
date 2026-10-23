#!/usr/bin/env python3
"""
tools/fit_invariants.py - learn the physical-invariant rules (swat/invariants.py) from NORMAL operation and measure them.

    python -m tools.fit_invariants --data-dir "<SWaT archive>"      # SWaT: fit on the 22-28 Dec normal period, test on ALL 35 attacks (needs the archive)
    python -m tools.fit_invariants --twin [--hours 6] [--seed 1]    # the demo plant: fit on a healthy twin run, test on a fresh run + synthetic attacks

SWaT mode. The invariants are fitted on the pre-attack normal period ONLY (nothing from the attack period, no labels), so every attack and every
attack-period benign second is genuinely out of sample, and out of time. Writes docs/swat_invariants.json (the fitted rules: aggregate
statistics, no raw rows), benchmarks/swat_invariants.json and docs/reports/swat_invariants_report.md. Windowed, cross-validated numbers for the
protocol come from `python -m benchmark.swat_protocol`, which scores the same rules next to the model and the baselines.

Twin mode. The twin's tank dynamics are compressed in time (plc/twin.py keeps propagation timing, not tank geometry), so SWaT-fitted invariants
do not describe it: the demo gets its own file, config/invariants_twin.json, labelled as fitted on the twin. Its report is a TWIN measurement,
never SWaT performance.

Neither mode touches models/weights.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
from typing import Any, Dict, List, Optional, Tuple

ROOT = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import numpy as np  # noqa: E402

from benchmark.env import environment  # noqa: E402
from core.interfaces import MACHINE_BY_NAME, MACHINES  # noqa: E402
from swat import scoring as SC  # noqa: E402
from swat.invariants import InvariantSet, stream_signals  # noqa: E402
from swat.physical_features import ACTUATORS, ON_THRESHOLD, SENSORS  # noqa: E402

SWAT_SET = os.path.join(ROOT, "docs", "swat_invariants.json")
SWAT_EVAL = os.path.join(ROOT, "benchmarks", "swat_invariants.json")
SWAT_MD = os.path.join(ROOT, "docs", "reports", "swat_invariants_report.md")
TWIN_SET = os.path.join(ROOT, "config", "invariants_twin.json")
TWIN_EVAL = os.path.join(ROOT, "benchmarks", "twin_invariants.json")
TWIN_MD = os.path.join(ROOT, "docs", "reports", "twin_invariants_report.md")
THETAS = (1.0, 1.5, 2.0, 3.0)


# ---------------------------------------------------------------------------------------------------------- SWaT
def evaluate_stream(inv: InvariantSet, stream, S: np.ndarray, A: np.ndarray, chunk: np.ndarray, region: np.ndarray) -> Dict[str, Any]:
    """Score the rules on `region` rows (per second): false-alarm episodes per benign hour and detection of every attack segment, per theta."""
    V, arg = inv.score(S, A, chunk)
    y, seg, ep = stream["label"].to_numpy(), stream["seg"].to_numpy(), stream["epoch"].to_numpy().astype(float)
    out: Dict[str, Any] = {"seconds_scored": int(region.sum()), "attack_seconds": int((y & region).sum()), "per_theta": {}}
    for th in THETAS:
        fl = (V > th)[region]
        c = SC.counts_from_flags(fl, y[region], seg[region], ep[region], stride=1)
        m = SC.metrics(c)
        keys = ("segments_detected", "segments_total", "event_recall", "median_latency_s", "false_alarm_episodes_per_hour", "precision", "recall", "f1", "episode_precision", "alarm_episodes")
        out["per_theta"][str(th)] = {k: m.get(k) for k in keys}
    rows = []
    fl1 = (V > 1.0)
    for s in np.unique(seg[region & y]):
        m = (seg == s) & y & region
        hit = np.flatnonzero(m & fl1)
        t0 = float(ep[m].min())
        rows.append({"segment": int(s), "duration_s": int(m.sum()), "flagged_share": round(float((m & fl1).sum() / m.sum()), 4), "detected": bool(hit.size),
                     "delay_s": float(ep[hit[0]] - t0) if hit.size else None,
                     "first_invariant": inv.invariants[int(arg[hit[0]])]["id"] if hit.size else None,
                     "first_family": inv.invariants[int(arg[hit[0]])]["family"] if hit.size else None})
    out["per_attack"] = rows
    fam: Dict[str, int] = {}
    for r in rows:
        if r["detected"]:
            fam[r["first_family"]] = fam.get(r["first_family"], 0) + 1
    out["first_detection_by_family"] = fam
    return out


def fit_swat(data_dir: str, out_set: str, out_eval: str, out_md: str) -> Dict[str, Any]:
    from swat.loader import load_stream
    stream, info = load_stream(data_dir, SENSORS + ACTUATORS)
    S, A, chunk = stream_signals(stream)
    normal = ((stream["period"] == "normal_period") & ~stream["label"]).to_numpy()
    if int(normal.sum()) < 20000:
        raise SystemExit("the pre-attack normal period is too short to fit invariants")
    inv = InvariantSet.fit(S[normal], A[normal], chunk[normal], label="SWaT 22-28 Dec normal period (pre-attack)")
    attack_period = (stream["period"] == "attack_period").to_numpy()
    ev = evaluate_stream(inv, stream, S, A, chunk, attack_period)
    res = {"label": "REAL SWaT, fitted on the pre-attack normal period only; every attack and attack-period benign second is out of sample",
           "fit_rows": int(normal.sum()), "report": inv.meta["report"], "evaluation": ev, "environment": environment()}
    inv.save(out_set)
    os.makedirs(os.path.dirname(out_eval), exist_ok=True)
    with open(out_eval, "w") as fh:
        json.dump(res, fh, indent=1, default=float)
    os.makedirs(os.path.dirname(out_md), exist_ok=True)
    with open(out_md, "w") as fh:
        fh.write(render(res, inv, "SWaT"))
    return res


# ---------------------------------------------------------------------------------------------------------- twin
def simulate_twin(hours: float, seed: int, changes: Optional[Dict[str, float]] = None, change_at_s: Optional[int] = None,
                  wander: float = 0.08) -> Tuple[np.ndarray, np.ndarray]:
    """1 Hz (S, A) from the healthy twin under an operator-like profile: the SCADA operator's step-to-target moves, then small setpoint
    excursions every 20 min. `changes` (tag -> target) are applied at `change_at_s` to model a synthetic attack."""
    from plc.twin import PlantTwin
    tw = PlantTwin(noise=True, seed=seed)
    rng = random.Random(seed + 99)
    n = int(hours * 3600)
    S, A = np.zeros((n, len(SENSORS))), np.zeros((n, len(ACTUATORS)))
    base = {m["name"]: float(m["initial"]) for m in MACHINES}
    actuators = [m for m in MACHINES if m["kind"] == "actuator"]
    op_cur = {m["name"]: float(m["initial"]) for m in actuators}
    ri = 0
    for t in range(n):
        if t < 1800 and t % 20 == 0:                                     # the operator walks each actuator toward its target, one command per 20 s
            m = actuators[ri % len(actuators)]
            ri += 1
            cur, tgt, step = op_cur[m["name"]], float(m["operator"]["target"]), float(m["operator"]["step"])
            op_cur[m["name"]] = min(cur + step, tgt) if cur < tgt else max(cur - step, tgt)
            tw.set_target(m["register"], op_cur[m["name"]])
        elif t >= 1800 and t % 1200 == 0:
            for m in actuators:
                if rng.random() < 0.5:
                    tw.set_target(m["register"], min(100.0, max(0.0, op_cur[m["name"]] * (1.0 + rng.uniform(-wander, wander)))))
        if changes and change_at_s is not None and t == change_at_s:
            for tag, v in changes.items():
                tw.set_target(MACHINE_BY_NAME[tag]["register"], v)
        for _ in range(10):
            tw.step(0.1)
        v = {r: round(x * 10.0) / 10.0 for r, x in tw.values().items()}      # the Modbus wire carries value x 10 as an integer: 0.1 resolution
        S[t] = [v[MACHINE_BY_NAME[s]["register"]] for s in SENSORS]
        A[t] = [1.0 if v[MACHINE_BY_NAME[a]["register"]] >= ON_THRESHOLD else 0.0 for a in ACTUATORS]
    return S, A


def fit_twin(hours: float, seed: int, out_set: str, out_eval: str, out_md: str) -> Dict[str, Any]:
    from tools.twin_domain_gap import SCENARIOS
    S, A = simulate_twin(hours, seed)
    inv = InvariantSet.fit(S, A, np.zeros(len(S), dtype=int), label=f"healthy digital twin, {hours} h, seed {seed}")
    S2, A2 = simulate_twin(max(2.0, hours / 2), seed + 1000)                 # a fresh healthy run: false alarms out of sample
    V2, _ = inv.score(S2, A2, np.zeros(len(S2), dtype=int))
    hours2 = len(S2) / 3600.0
    # theta: the smallest value on the ladder with NO violating second on the fresh healthy run (the twin's setpoint variety is wider than any
    # one fit run shows). Calibrated on a different run from the one reported as false alarms below only in the sense that both are healthy twin runs.
    inv.meta["theta"] = next((th for th in (1.0, 1.25, 1.5, 2.0, 3.0) if int((V2 > th).sum()) == 0), 3.0)
    nominal = {"simulated_hours": round(hours2, 2), "calibrated_theta": inv.theta,
               "per_theta": {str(th): {"violating_seconds": int((V2 > th).sum()), "episodes_per_hour": round(SC.count_episodes(np.arange(len(V2), dtype=float), V2 > th) / hours2, 3)} for th in THETAS}}
    scen: Dict[str, Any] = {}
    for name, changes in SCENARIOS.items():
        settle = 1900 if hours >= 1 else 600
        S3, A3 = simulate_twin(1.0, seed + 2000, changes, settle)
        V3, a3 = inv.score(S3, A3, np.zeros(len(S3), dtype=int))
        before = int((V3[:settle] > inv.theta).sum())
        hit = np.flatnonzero(V3[settle:] > inv.theta)
        scen[name] = {"changes": changes, "violating_seconds_before_attack": before, "first_violation_after_s": int(hit[0]) if hit.size else None,
                      "first_invariant": inv.invariants[int(a3[settle + hit[0]])]["id"] if hit.size else None}
    res = {"label": "TWIN MEASUREMENT (synthetic plant) - NOT SWaT detection performance", "fit_hours": hours, "seed": seed, "report": inv.meta["report"],
           "nominal": nominal, "scenarios": scen, "environment": environment()}
    inv.save(out_set)
    os.makedirs(os.path.dirname(out_eval), exist_ok=True)
    with open(out_eval, "w") as fh:
        json.dump(res, fh, indent=1, default=float)
    os.makedirs(os.path.dirname(out_md), exist_ok=True)
    with open(out_md, "w") as fh:
        fh.write(render(res, inv, "twin"))
    return res


# ---------------------------------------------------------------------------------------------------------- report
def render(res: Dict[str, Any], inv: InvariantSet, kind: str) -> str:
    rep = res["report"]
    env = res["environment"]
    L = [f"# Physical invariants - {kind} fit and measurement", "", f"> **{res['label']}**", "",
         f"Generated by `python -m tools.fit_invariants` on {env['generated_utc']} UTC, commit `{env['git_commit']}`. The rules are deterministic consistency checks "
         "learned from normal operation only (no attack labels, no classifier); see `docs/INVARIANTS.md`. They are ADVISORY: a violation raises an ALERT, it never blocks.", "",
         "## What was learned", "",
         f"Fitted on {rep['rows']:,} normal rows ({rep['rows_fit']:,} to propose, the last {rep['rows_holdout']:,} held out in time to validate). "
         f"Proposed {rep['proposed']}; kept {rep['kept']}.", "", "| invariant | meaning | held-out violation rate |", "|---|---|---|"]
    for k in inv.invariants:
        h = rep["holdout"].get(k["id"], {})
        L.append(f"| `{k['id']}` | {k['text']} | {h.get('violation_rate', 'n/a')} |")
    if rep["dropped"]:
        L += ["", "### Proposed but dropped", "", "| invariant | reason |", "|---|---|"]
        for d in rep["dropped"]:
            L.append(f"| `{d['id']}` | {d['reason']} |")
    if kind == "SWaT":
        ev = res["evaluation"]
        L += ["", "## Out-of-sample result (attack period, per second)", "",
              f"{ev['seconds_scored']:,} seconds scored, {ev['attack_seconds']:,} of them inside attacks. theta is the violation threshold in units of the normal range seen in training "
              "(1 = beyond everything normal training showed).", "",
              "| theta | attacks detected | median delay (s) | false-alarm episodes / benign hour | share of alarm episodes inside an attack |", "|---|---|---|---|---|"]
        for th, m in ev["per_theta"].items():
            L.append(f"| {th} | {m['segments_detected']}/{m['segments_total']} | {m['median_latency_s']} | {m['false_alarm_episodes_per_hour']} | {m['episode_precision']} |")
        L += ["", f"First detection by family at theta 1: {ev['first_detection_by_family']}.", "", "## Attack by attack (theta 1)", "",
              "| attack | duration | seconds flagged | detected | delay (s) | first invariant |", "|---|---|---|---|---|---|"]
        for r in ev["per_attack"]:
            L.append(f"| {r['segment']} | {r['duration_s']} s | {int(100 * r['flagged_share'])} % | {'yes' if r['detected'] else '**no**'} | {r['delay_s'] if r['delay_s'] is not None else '-'} | {r['first_invariant'] or '-'} |")
        L += ["", "Reading it: an attack that alters an actuator and nothing else leaves a consistent plant, and consistency rules cannot see it; sensor spoofing, freezes and "
              "tampered readings are what they target. Compare with the model and the baselines in `docs/reports/swat_evaluation_protocol.md`."]
    else:
        n = res["nominal"]
        L += ["", f"## Healthy twin, fresh run ({n['simulated_hours']} simulated hours, not used for fitting); the file's calibrated theta is {n['calibrated_theta']}", "",
              "| theta | violating seconds | episodes / hour |", "|---|---|---|"]
        for th, m in n["per_theta"].items():
            L.append(f"| {th} | {m['violating_seconds']} | {m['episodes_per_hour']} |")
        L += ["", "## Synthetic actuator attacks on the twin", "", "| scenario | violating s before (at the calibrated theta) | first violation (s after) | first invariant |", "|---|---|---|---|"]
        for name, s in res["scenarios"].items():
            L.append(f"| {name} | {s['violating_seconds_before_attack']} | {s['first_violation_after_s']} | {s['first_invariant'] or '-'} |")
        L += ["", "A value of `None` means the invariants did not fire: an actuator change whose consequences are internally consistent is not an inconsistency. "
              "These are twin numbers; they say nothing about SWaT."]
    L.append("")
    return "\n".join(L)


def main() -> None:
    ap = argparse.ArgumentParser(description="Fit and measure the physical-invariant rules.")
    ap.add_argument("--data-dir", help="SWaT archive folder (fits on the 22-28 Dec normal period, tests on the attack period)")
    ap.add_argument("--twin", action="store_true", help="fit on a healthy twin run (writes config/invariants_twin.json)")
    ap.add_argument("--hours", type=float, default=6.0)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out-dir", help="write the three outputs here instead of the repo paths")
    a = ap.parse_args()
    if bool(a.data_dir) == bool(a.twin):
        ap.error("give exactly one of --data-dir or --twin")
    if a.twin:
        paths = (TWIN_SET, TWIN_EVAL, TWIN_MD)
        if a.out_dir:
            paths = tuple(os.path.join(a.out_dir, os.path.basename(p)) for p in paths)
        res = fit_twin(a.hours, a.seed, *paths)
        print(f"kept {res['report']['kept']} invariants -> {paths[0]}")
        n = res["nominal"]
        print(f"calibrated theta {n['calibrated_theta']}; healthy fresh run at theta 1: {n['per_theta']['1.0']}")
        for n, s in res["scenarios"].items():
            print(f"  {n}: first violation after {s['first_violation_after_s']} s ({s['first_invariant']})")
    else:
        paths = (SWAT_SET, SWAT_EVAL, SWAT_MD)
        if a.out_dir:
            paths = tuple(os.path.join(a.out_dir, os.path.basename(p)) for p in paths)
        res = fit_swat(a.data_dir, *paths)
        t1 = res["evaluation"]["per_theta"]["1.0"]
        print(f"kept {res['report']['kept']} invariants -> {paths[0]}")
        print(f"theta 1: {t1['segments_detected']}/{t1['segments_total']} attacks, {t1['false_alarm_episodes_per_hour']} false-alarm episodes per benign hour")
    print(f"wrote {paths[1]} and {paths[2]} (models/weights untouched)")


if __name__ == "__main__":
    main()
