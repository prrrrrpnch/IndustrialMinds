"""
tools/swat_attack_profile.py - Phase 8: profile SWaT's LABELLED attack segments (aggregate only).

    python tools/swat_attack_profile.py --data-dir "C:\\IndustrialMind\\SWaT_dataset\\archive" --out docs/swat_attack_profile.json
    python tools/swat_attack_profile.py --fixture --out <tmp>/profile.json        # synthetic SWaT-SHAPED data, format check only

SWaT ships NO attack list: only a Normal/Attack label per second. So an attack's "type" can only be inferred from how
the 10 plant sensors behave inside each labelled segment, relative to normal operation:

  freeze   a sensor that normally moves is (near) constant for the whole segment (>= 30 s)
  ramp     a sensor moves monotonically (linear-fit R^2 >= 0.9) by >= 2 normal standard deviations
  shift    its mean differs from normal by >= 3 normal standard deviations without being a freeze/ramp
  (a segment can show several; segments showing none are 'unclassified')

Output (aggregate statistics only, no raw rows): per-type segment counts, segment-duration quantiles, and
`attacker_ranges`: ONLY the fraction-of-normal-span moved by ramp-like segments is calibrated from SWaT
(`ramp_total_fraction`). Everything else the attacker randomises stays a design default, and says so.
attacker/scenarios.py loads this file if it exists.
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from typing import Any, Dict, List

import numpy as np

from swat.loader import load_stream
from swat.physical_features import ACTUATORS, SENSORS

MIN_FREEZE_S = 30
RAMP_R2, RAMP_MIN_SD, SHIFT_MIN_SD = 0.9, 2.0, 3.0


def classify_segment(x: np.ndarray, mean: float, sd: float, span: float) -> Dict[str, Any]:
    n = len(x)
    out: Dict[str, Any] = {"freeze": False, "ramp": False, "shift": False, "frac_span": 0.0}
    if n < 10 or sd <= 0 or span <= 0 or not np.isfinite(x).all():
        return out
    if n >= MIN_FREEZE_S and float(np.ptp(x)) <= 1e-9 * max(1.0, abs(mean)):
        out["freeze"] = True
        return out
    t = np.arange(n, dtype=float)
    slope, icpt = np.polyfit(t, x, 1)
    resid = x - (slope * t + icpt)
    r2 = 1.0 - float(resid.var() / max(x.var(), 1e-12))
    total = abs(float(slope) * (n - 1))
    if r2 >= RAMP_R2 and total >= RAMP_MIN_SD * sd:
        out["ramp"], out["frac_span"] = True, float(min(total / span, 1.0))
    elif abs(float(x.mean()) - mean) >= SHIFT_MIN_SD * sd:
        out["shift"] = True
    return out


def profile(stream, sensors: List[str]) -> Dict[str, Any]:
    normal = stream[~stream["label"].to_numpy()]
    ref = {s: (float(normal[s].mean()), float(normal[s].std()),
               float(np.nanpercentile(normal[s], 99.9) - np.nanpercentile(normal[s], 0.1))) for s in sensors}
    segs = stream[stream["seg"].to_numpy() > 0].groupby("seg")
    per_seg, fracs, durations = [], [], []
    counts = {"freeze": 0, "ramp": 0, "shift": 0, "unclassified": 0}
    for sid, g in segs:
        beh = {"freeze": False, "ramp": False, "shift": False}
        for s in sensors:
            mean, sd, span = ref[s]
            r = classify_segment(g[s].to_numpy(float), mean, sd, span)
            for k in beh:
                beh[k] = beh[k] or r[k]
            if r["ramp"]:
                fracs.append(r["frac_span"])
        kinds = [k for k, v in beh.items() if v]
        for k in kinds or ["unclassified"]:
            counts[k] += 1
        durations.append(len(g))
        per_seg.append({"segment": int(sid), "duration_s": int(len(g)), "behaviours": kinds or ["unclassified"],
                        "block": str(g["block"].iloc[0])})
    q = lambda a, p: float(np.quantile(a, p)) if len(a) else None
    out: Dict[str, Any] = {
        "segments": len(per_seg), "behaviour_counts": counts,
        "segment_duration_s": {"p10": q(durations, .1), "median": q(durations, .5), "p90": q(durations, .9)},
        "ramp_fraction_of_normal_span": {"n_sensor_ramps": len(fracs), "p10": q(fracs, .1), "median": q(fracs, .5), "p90": q(fracs, .9)},
        "per_segment": per_seg,
        "attacker_ranges": {},
        "notes": ["Behaviours are INFERRED from sensor data; SWaT has no attack list.",
                  "Only ramp_total_fraction is calibrated from SWaT; all other attacker ranges are design defaults."],
    }
    if len(fracs) >= 3:
        lo, hi = float(np.clip(q(fracs, .1), 0.05, 0.9)), float(np.clip(q(fracs, .9), 0.1, 0.9))
        out["attacker_ranges"] = {"ramp_total_fraction": [round(min(lo, hi - 0.05), 3), round(hi, 3)]}
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Aggregate profile of SWaT's labelled attack segments.")
    ap.add_argument("--data-dir")
    ap.add_argument("--fixture", action="store_true", help="synthetic SWaT-SHAPED fixture (format check only)")
    ap.add_argument("--out", default=os.path.join("docs", "swat_attack_profile.json"))
    args = ap.parse_args()
    if args.fixture:
        from tests.swat_fixture import make_swat_archive
        data_dir = tempfile.mkdtemp(prefix="swat-fixture-")
        make_swat_archive(data_dir, seed=0)
    elif args.data_dir:
        data_dir = args.data_dir
    else:
        ap.error("give --data-dir or --fixture")
    stream, _ = load_stream(data_dir, SENSORS + ACTUATORS)
    prof = profile(stream, SENSORS)
    prof["fixture_not_real_results"] = bool(args.fixture)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w") as fh:
        json.dump(prof, fh, indent=2)
    print(json.dumps({k: v for k, v in prof.items() if k != "per_segment"}, indent=2))
    print(f"\nWrote {args.out} (aggregate only).")
    if args.fixture:
        print("*** SYNTHETIC FIXTURE: never cite ***")


if __name__ == "__main__":
    main()
