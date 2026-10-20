"""
tests/test_bounds_alignment.py - PART 0 #2 evidence: the plant configuration is MEASURED, not guessed.

Checks core/interfaces.MACHINES and the calibrated twin against docs/swat_bounds.json (aggregate statistics
of SWaT train-block NORMAL rows, produced by models/train_physical_swat.py on the real archive).

    python -m tests.test_bounds_alignment
"""

from __future__ import annotations

import json
import os

from core.interfaces import MACHINES
from plc.twin import PlantTwin

fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global fails
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    fails += 0 if cond else 1


path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "docs", "swat_bounds.json")
doc = json.load(open(path))
B = doc["sensors"]
sensors = [m for m in MACHINES if m["kind"] == "sensor"]

print("SOURCE")
check("bounds file comes from the REAL archive, not the synthetic fixture", doc["fixture_not_real_results"] is False
      and doc["rows_used"] > 100_000, f"{doc['rows_used']:,} train-normal rows")
check("every twin sensor has a measured entry", {m["name"] for m in sensors} <= set(B))

print("\nCONFIG vs MEASURED")
for m in sensors:
    b = B[m["name"]]
    span = b["p99.9"] - b["p0.1"]
    check(f"{m['name']:8s} range [{m['min']}, {m['max']}] encloses the measured [{b['min']:.2f}, {b['max']:.2f}]",
          m["min"] <= b["min"] and m["max"] >= b["max"])
    check(f"{m['name']:8s} nominal {m['initial']} is within 10% of the measured normal span of the median {b['median']:.2f}",
          abs(m["initial"] - b["median"]) <= 0.10 * span, f"|diff| {abs(m['initial'] - b['median']):.3f} <= {0.10 * span:.3f}")
on = {m["name"]: m["initial"] for m in MACHINES if m["kind"] == "actuator" and m["swat_backed"]}
check("every SWaT-backed pump/UV/valve nominal setpoint is 'on/open' (>= 50 %), as SWaT's dominant state 2", all(v >= 50.0 for v in on.values()), str(on))

print("\nCALIBRATED TWIN AT NOMINAL SETPOINTS (1 simulated hour, sensor noise on, 1 Hz samples)")
tw = PlantTwin(noise=True, seed=5)
outside = {m["name"]: 0 for m in sensors}
n = 0
for i in range(36000):
    tw.step(0.1)
    if i % 10 == 0:
        v = tw.values()
        n += 1
        for m in sensors:
            x = v[m["register"]]
            outside[m["name"]] += not (B[m["name"]]["envelope_lo"] <= x <= B[m["name"]]["envelope_hi"])
for m in sensors:
    check(f"{m['name']:8s} stays inside the measured normal envelope", outside[m["name"]] / n <= 0.001, f"{outside[m['name']]} of {n} samples outside")
fast = PlantTwin(noise=True, seed=6, time_scale=20.0)      # 36,000 steps x 2 s = 20 simulated hours
dp_max = 0.0
for i in range(36000):
    fast.step(0.1)
    if i % 50 == 0:
        dp_max = max(dp_max, fast.values()[[m for m in sensors if m["name"] == "DPIT301"][0]["register"]])
check("the UF backwash cycle runs over 20 simulated hours (slow, SWaT-like) and DPIT301 never leaves the measured envelope",
      fast.backwashes >= 2 and dp_max <= B["DPIT301"]["envelope_hi"], f"{fast.backwashes} backwashes, max DPIT301 {dp_max:.2f} <= {B['DPIT301']['envelope_hi']:.2f}")

print("\nALL PASS" if fails == 0 else f"\n{fails} CHECK(S) FAILED")
raise SystemExit(1 if fails else 0)
