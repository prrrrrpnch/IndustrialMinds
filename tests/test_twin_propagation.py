"""
Phase 3 check: perturb Stage 1 of the twin and assert Stage 2+ telemetry moves
within an expected window, in causal order S2 -> S3 -> S4 -> S5.

  python -m tests.test_twin_propagation              # standalone, simulated time (instant)
  python -m tests.test_twin_propagation --live --time-scale 10
        # against a RUNNING PLC (started with IM_TWIN_TIME_SCALE=10), over Modbus, real time

A sensor "responds" when it departs its baseline by more than RESPONSE_FRAC of its range.
Windows are in SIMULATED seconds (wall seconds x time scale in --live mode).
"""

from __future__ import annotations

import argparse
import sys
import time
from typing import Dict, Optional

from docs.interfaces import (
    MACHINE_BY_REGISTER, SENSOR_REGISTERS, NUM_REGISTERS, MACHINES,
    P101, FIT201, AIT202, LIT301, LIT401, AIT402, PIT501, from_raw, to_raw,
)
from plc.twin import PlantTwin

RESPONSE_FRAC = 0.02          # 2 % of the sensor's range
NAMES = {m["register"]: m["name"] for m in MACHINES}

# Stage-1 perturbation: raw-water pump P101 50 % -> 5 % (starves everything downstream).
PERTURB_REG, PERTURB_VALUE = P101, 5.0

# (sensor, stage, max seconds until it responds)
EXPECTED = [
    (FIT201, 2, 3.0),
    (AIT202, 2, 6.0),
    (LIT301, 3, 10.0),
    (AIT402, 4, 15.0),
    (LIT401, 4, 40.0),
    (PIT501, 5, 200.0),
]
HORIZON = 220.0

fails = 0


def check(ok: bool, msg: str) -> None:
    global fails
    print(("  [PASS] " if ok else "  [FAIL] ") + msg)
    fails += 0 if ok else 1


def detect(baseline: Dict[int, float], sample: Dict[int, float], first: Dict[int, float], t: float) -> None:
    for r in SENSOR_REGISTERS:
        m = MACHINE_BY_REGISTER[r]
        if r not in first and abs(sample[r] - baseline[r]) > RESPONSE_FRAC * (m["max"] - m["min"]):
            first[r] = t


def run_sim(perturb: bool) -> Dict[int, float]:
    twin = PlantTwin()                       # noise off -> deterministic
    baseline = twin.values()
    if perturb:
        twin.set_target(PERTURB_REG, PERTURB_VALUE)
    first: Dict[int, float] = {}
    steps = int(HORIZON / 0.1)
    for i in range(steps):
        twin.step(0.1)
        detect(baseline, twin.values(), first, (i + 1) * 0.1)
    return first


def run_live(time_scale: float) -> Dict[int, float]:
    from pymodbus.client import ModbusTcpClient
    from docs import netconfig
    client = ModbusTcpClient(netconfig.PLC_HOST, port=netconfig.PLC_PORT)
    if not client.connect():
        print(f"cannot reach PLC at {netconfig.PLC_HOST}:{netconfig.PLC_PORT}")
        sys.exit(2)

    def read() -> Dict[int, float]:
        res = client.read_holding_registers(0, count=NUM_REGISTERS, slave=1)
        return {m["register"]: from_raw(raw) for m, raw in zip(MACHINES, res.registers)}

    baseline = read()
    client.write_register(PERTURB_REG, to_raw(PERTURB_VALUE), slave=1)
    t0 = time.time()
    first: Dict[int, float] = {}
    while (time.time() - t0) * time_scale < HORIZON:
        detect(baseline, read(), first, (time.time() - t0) * time_scale)
        time.sleep(0.1)
    client.write_register(PERTURB_REG, to_raw(float(MACHINE_BY_REGISTER[PERTURB_REG]["initial"])), slave=1)
    client.close()
    return first


def evaluate(first: Dict[int, float], control: Optional[Dict[int, float]]) -> None:
    print(f"\nFirst-response times (simulated s) after P101 {MACHINE_BY_REGISTER[P101]['initial']:.0f}% -> {PERTURB_VALUE:.0f}%:")
    for r, stage, window in EXPECTED:
        t = first.get(r)
        shown = f"{t:6.1f}s" if t is not None else "  never"
        check(t is not None and t <= window, f"S{stage} {NAMES[r]:7s} responds at {shown} (window <= {window:g}s)")
    # causal ordering: downstream stages cannot respond before upstream ones
    order = [first.get(r) for r in (FIT201, LIT301, LIT401, PIT501)]
    check(all(x is not None for x in order) and order == sorted(order),
          f"causal order S2 < S3 < S4 < S5 : {[None if x is None else round(x, 1) for x in order]}")
    if control is not None:
        moved = sorted(NAMES[r] for r in control)
        check(not any(r in control for r, _, _ in EXPECTED), f"negative control (no perturbation): none of the S2-S5 probes moved (moved: {moved or 'nothing'})")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true", help="perturb a running PLC over Modbus")
    ap.add_argument("--time-scale", type=float, default=1.0, help="PLC IM_TWIN_TIME_SCALE (live mode)")
    args = ap.parse_args()
    print("Twin cross-stage propagation check -", "LIVE over Modbus" if args.live else "standalone simulation")
    if args.live:
        evaluate(run_live(args.time_scale), None)
    else:
        evaluate(run_sim(True), run_sim(False))
    print("\nALL PASS" if fails == 0 else f"\n{fails} CHECK(S) FAILED")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
