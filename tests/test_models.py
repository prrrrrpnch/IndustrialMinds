"""
tests/test_models.py - CyberModel / PhysicalModel checks (checklist sections 2 and 3).

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
from models.cyber_model import CyberModel, FEATURE_NAMES
from models.physical_model import N_STEP_FEATURES, PhysicalModel
from models.telemetry_generator import ChannelProfile, generate_channel, generate_normal_commands

PASSED = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    assert cond, name
    PASSED.append(name)


print("=" * 70)
print("CYBER MODEL")
print("=" * 70)

cm = CyberModel.load()
check("weights load", cm.status == "OK", cm.status)
for meth in ("fit", "predict", "evaluate_payload"):
    check(f"CyberModel.{meth}() exists", callable(getattr(cm, meth, None)))

# Raw command -> feature vector
cmd, state = next(generate_normal_commands(1, seed=99))
vec = cm.extractor.transform(cmd, state, update=False)
check("payload -> feature vector", vec.shape == (len(FEATURE_NAMES),) and np.isfinite(vec).all(),
      f"{len(FEATURE_NAMES)} features")

# Normal traffic mostly not flagged; obvious anomalies flagged
normal = [cm.evaluate_payload(c, s) for c, s in generate_normal_commands(500, seed=321)]
fpr = np.mean([r["threat_flag"] for r in normal])
check("normal traffic false-positive rate < 3%", fpr < 0.03, f"{fpr:.1%}")

now = time.time()
burst = []
for i in range(12):   # 12 commands in 120 ms, unsigned, big jumps
    c = make_command(f"b{i}", now + i * 0.01, LOOPBACK, 6, 1, 110.0 - i,
                     raw_value=1100 - i * 10, auth=None)
    burst.append(cm.evaluate_payload(c, {"registers": {1: 5.0}}))
check("unsigned burst flagged as anomalous", burst[-1]["threat_flag"],
      f"score={burst[-1]['anomaly_score']} thr={cm.threshold:.3f}")

r = cm.evaluate_payload(cmd, state)
check("evaluate_payload latency < 10 ms", r["latency_ms"] < 10, f"{r['latency_ms']} ms")

# Packed inference == sklearn
X = np.vstack([cm.extractor.transform(c, s) for c, s in generate_normal_commands(300, seed=5)])
diff = np.abs(cm.anomaly_scores(X) - (-cm._model.score_samples(X))).max()
check("packed inference == sklearn score_samples", diff < 1e-12, f"max diff {diff:.1e}")

# Fallback: missing and corrupt weights
missing = CyberModel.load("/nonexistent/cyber.joblib")
rm = missing.evaluate_payload(cmd, state)
check("missing weights -> NO_MODEL, no crash, abstains",
      rm["status"] == "NO_MODEL" and rm["threat_flag"] is False and rm["anomaly_score"] is None)
with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as fh:
    fh.write(b"not a model")
corrupt = CyberModel.load(fh.name)
os.unlink(fh.name)
check("corrupt weights -> NO_MODEL, no crash", corrupt.evaluate_payload(cmd, state)["status"] == "NO_MODEL")
bad = cm.evaluate_payload({"timestamp": "garbage"}, None)
check("malformed command -> ERROR status, no crash", bad["status"] == "ERROR" and bad["threat_flag"] is False)

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
