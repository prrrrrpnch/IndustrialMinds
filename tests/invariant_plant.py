"""
tests/invariant_plant.py - a small SYNTHETIC plant whose physics is exactly known, for testing the invariant rules (never real data).

Stage 1 is a tank with a hysteresis-controlled outflow pump:
    P101 turns ON when LIT101 > 650 mm and OFF when it falls below 350 mm      (control-logic invariant)
    FIT201 = 2.5 m3/h while P101 is on (3 s lag), 0 when off                    (pump state -> flow)
    FIT101 = 1.2 m3/h inflow with a slow swell                                  (independent supply)
    dLIT101/dt = 2 mm/s per m3/h of (FIT101 - FIT201)                           (mass balance)
Every other signal is independent noise around a mean: nothing links them, so the invariants must NOT invent a relation for them.
"""

from __future__ import annotations

from typing import Dict, Tuple

import numpy as np

from swat.physical_features import ACTUATORS, SENSORS

SI = {n: i for i, n in enumerate(SENSORS)}
AI = {n: i for i, n in enumerate(ACTUATORS)}
OTHER_MEAN = {"AIT202": 8.4, "LIT301": 900.0, "DPIT301": 20.0, "LIT401": 880.0, "AIT402": 160.0, "PIT501": 250.0, "FIT501": 1.7}
OTHER_SD = {"AIT202": 0.02, "LIT301": 8.0, "DPIT301": 0.5, "LIT401": 8.0, "AIT402": 2.0, "PIT501": 2.0, "FIT501": 0.02}


def make_plant(n: int, seed: int) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """(S [n,10] raw sensors, A [n,8] 0/1 actuators, chunk [n] zeros) for n seconds."""
    rng = np.random.default_rng(seed)
    S = np.zeros((n, len(SENSORS)))
    A = np.ones((n, len(ACTUATORS)))
    level, pump = 480.0 + rng.uniform(-80, 80), 1
    flow2 = 2.5
    ar: Dict[str, float] = {k: 0.0 for k in OTHER_MEAN}
    p203 = 1.0
    for t in range(n):
        if level > 650:
            pump = 1
        elif level < 350:
            pump = 0
        flow2 += (2.5 * pump - flow2) / 3.0                          # 3 s lag
        fin = 1.2 + 0.2 * np.sin(t / 900.0)
        level = float(np.clip(level + 2.0 * (fin - flow2), 0.0, 1200.0))
        S[t, SI["LIT101"]] = level + rng.normal(0, 0.6)
        S[t, SI["FIT101"]] = fin + rng.normal(0, 0.01)
        S[t, SI["FIT201"]] = flow2 + rng.normal(0, 0.02)
        A[t, AI["P101"]] = pump
        if rng.random() < 1 / 1200:                                   # an unrelated pump that toggles now and then
            p203 = 1.0 - p203
        A[t, AI["P203"]] = p203
        for k, m in OTHER_MEAN.items():
            ar[k] = 0.9 * ar[k] + rng.normal(0, OTHER_SD[k])
            S[t, SI[k]] = m + ar[k]
    return S, A, np.zeros(n, dtype=int)
