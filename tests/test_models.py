"""
tests/test_models.py - PhysicalModel checks (synthetic until Phase 6; CyberModel -> tests/test_swat_cyber.py).

    python -m models.train_models      # once, creates models/weights/
    python -m tests.test_models
"""

from __future__ import annotations

import os
import tempfile
import time
from typing import Any

import numpy as np

from docs.netconfig import LOOPBACK  # documented loopback default
from docs.interfaces import MACHINES, NUM_REGISTERS, make_command
from docs import hmac_auth
from models.physical_model import N_STEP_FEATURES, PhysicalModel
from models.telemetry_generator import ChannelProfile, generate_channel

PASSED = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    assert cond, name
    PASSED.append(name)


# CyberModel checks live in tests/test_swat_cyber.py (SWaT-derived schema, Phase 5).

print()
print("=" * 70)
print("PHYSICAL MODEL")
print("=" * 70)

pm = PhysicalModel.load()
check("weights load", pm.status == "OK", pm.status)

rng = np.random.default_rng(2024)


def feed(model: PhysicalModel, series: np.ndarray) -> None:
    for row in series:
        model.update({i: float(v) for i, v in enumerate(row)})


def stream(n: int, overrides: dict) -> np.ndarray:
    """10-channel stream; overrides = {register: dict(kwargs for generate_channel)}"""
    out = np.zeros((n, NUM_REGISTERS))
    for reg in range(NUM_REGISTERS):
        out[:, reg] = generate_channel(reg, n, rng, **overrides.get(reg, {})).values
    return out


pm.reset_window()
check("WARMING_UP before window is full", pm.assess()["status"] == "WARMING_UP")
feed(pm, stream(pm.window_size + 5, {}))
w = pm.window_tensor()
check("sliding window shape [window_size, 10, features]",
      w.shape == (pm.window_size, NUM_REGISTERS, N_STEP_FEATURES), str(w.shape))

rep = pm.assess()
his = [m["health_index"] for m in rep["machines"].values()]
ruls = [m["rul_hours"] for m in rep["machines"].values()]
check("report covers every configured register", len(rep["machines"]) == NUM_REGISTERS)
check("health indices normalised to [0, 1]", all(0.0 <= h <= 1.0 for h in his), str(his))
check("RUL estimates present and >= 0", all(r >= 0 for r in ruls))
check("assess latency < 10 ms", rep["latency_ms"] < 10, f"{rep['latency_ms']} ms")


def health_of(reg: int, n: int = 400, **kw: Any) -> float:
    pm.reset_window()
    feed(pm, stream(n, {reg: kw}))
    return pm.assess()["machines"][MACHINES[reg]["name"]]["health_index"]


# Benign effects must NOT look like wear
drifty = ChannelProfile(noise_frac=0.004, drift_frac_per_step=2e-4, noise_modulation=0.0, step_prob=0.0)
h = health_of(3, profile=drifty)
check("strong calibration drift is not wear (health > 0.7)", h > 0.7, f"health={h}")

nonstat = ChannelProfile(noise_frac=0.006, drift_frac_per_step=0.0, noise_modulation=0.6, step_prob=0.0)
h = health_of(4, profile=nonstat)
check("non-stationary sensor noise is not wear (health > 0.7)", h > 0.7, f"health={h}")

ramping = ChannelProfile(noise_frac=0.004, drift_frac_per_step=0.0, noise_modulation=0.0, step_prob=0.02)
h = health_of(6, profile=ramping)
check("operator setpoint ramps are not wear (health > 0.7)", h > 0.7, f"health={h}")

# Real wear must be detected and ordered
h_mid = health_of(2, n=600, degradation_start=0.0, degradation_end=0.5)
h_end = health_of(2, n=600, degradation_start=0.0, degradation_end=1.0)
check("near-failure machine health < 0.4", h_end < 0.4, f"health={h_end}")
check("health decreases with wear (half-worn > near-failure)", h_mid > h_end, f"{h_mid} > {h_end}")

pm.reset_window()
feed(pm, stream(pm.window_size + 5, {5: {"degradation_start": 0.0, "degradation_end": 1.0}}))
names = sorted(pm.assess()["machines"].items(), key=lambda kv: kv[1]["health_index"])
check("failing channel identified among 10", names[0][0] == MACHINES[5]["name"],
      f"lowest = {names[0][0]}")

# Fallback
missing = PhysicalModel.load("/nonexistent/physical.joblib")
feed(missing, stream(missing.window_size + 1, {}))
r = missing.assess()
check("missing weights -> NO_MODEL, no crash", r["status"] == "NO_MODEL" and r["min_health_index"] is None)

# Packed == sklearn
from models.physical_model import window_features  # noqa: E402
F = np.vstack([window_features(pm.window_tensor()[:, c, :]) for c in range(NUM_REGISTERS)])
diff = np.abs(pm._packed.predict(F) - pm._model.predict(F)).max()
check("packed inference == sklearn predict", diff < 1e-9, f"max diff {diff:.1e}")

print(f"\nAll {len(PASSED)} model checks passed")
