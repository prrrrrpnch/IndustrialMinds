"""
models/telemetry_generator.py - deterministic synthetic data for training and stress tests.

There is no historical plant data in this project, so both ML models are
trained on synthetic data produced here from the central machine config
(docs/interfaces.MACHINES). Every generator takes an explicit seed, so the
same seed always produces the same data and therefore the same model.

Physical telemetry (one value per machine per sample):
    value(t) = operator setpoint (ramp-limited steps)
             + calibration drift      (slow linear offset - benign)
             + sensor noise           (non-stationary variance - benign)
             + degradation signature  (growing vibration noise + spikes - NOT benign)

Cyber traffic: legitimate SCADA operator commands (signed, trusted sources,
small setpoint moves, ~2 s spacing per source).
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple

import numpy as np

from docs.netconfig import LOOPBACK  # documented loopback default
from docs.interfaces import MACHINES, NUM_REGISTERS, ACTUATOR_REGISTERS, make_command, to_raw
from docs import hmac_auth

# Telemetry sample period used by the middleware poll loop (seconds).
SAMPLE_PERIOD_S = 0.2

# Maximum calibration drift, as a fraction of the machine's range.
MAX_DRIFT_FRAC = 0.06

# Run-to-failure horizon used to express RUL (hours of operation).
RUL_HORIZON_HOURS = 500.0


@dataclass
class ChannelProfile:
    """Per-trajectory randomised characteristics of one machine channel."""
    noise_frac: float          # base noise std as fraction of range
    drift_frac_per_step: float # calibration drift per sample as fraction of range
    noise_modulation: float    # amplitude of slow noise-variance modulation (0..1)
    step_prob: float           # probability of an operator setpoint change per sample


@dataclass
class Trajectory:
    """One channel's samples plus ground-truth degradation and RUL."""
    register: int
    values: np.ndarray            # [n]
    degradation: np.ndarray       # [n] 0 = healthy .. 1 = failed
    rul_hours: np.ndarray         # [n]
    profile: ChannelProfile = field(repr=False, default=None)  # type: ignore[assignment]


def _random_profile(rng: np.random.Generator) -> ChannelProfile:
    return ChannelProfile(
        noise_frac=float(rng.uniform(0.002, 0.008)),
        drift_frac_per_step=float(rng.uniform(-4e-5, 4e-5)),
        noise_modulation=float(rng.uniform(0.0, 0.6)),
        step_prob=float(rng.uniform(0.0, 0.02)),
    )


def generate_channel(register: int, n: int, rng: np.random.Generator,
                     degradation_start: Optional[float] = None,
                     degradation_end: float = 1.0,
                     profile: Optional[ChannelProfile] = None,
                     envelope: Optional[Tuple[float, float]] = None) -> Trajectory:
    """
    One machine channel for n samples.

    degradation_start: fraction of the series where wear begins (None = healthy
    for the whole series). Degradation rises to `degradation_end` at the end.
    envelope: (lo_frac, hi_frac) of the range the operator setpoint stays in
    (default 0.2 .. 0.8).
    """
    m = MACHINES[register]
    lo, hi = float(m["min"]), float(m["max"])
    span = hi - lo
    rate = float(m["rate_per_sec"]) * SAMPLE_PERIOD_S
    profile = profile or _random_profile(rng)

    # --- operator setpoint, ramp limited like the PLC -----------------------
    e_lo, e_hi = envelope or (0.2, 0.8)
    setpoint = float(rng.uniform(lo + e_lo * span, lo + e_hi * span))
    target = setpoint
    sp = np.empty(n)
    for i in range(n):
        if rng.random() < profile.step_prob:
            target = float(np.clip(target + rng.normal(0, 0.08 * span),
                                   lo + max(0.05, e_lo) * span, lo + min(0.95, e_hi) * span))
        setpoint += float(np.clip(target - setpoint, -rate, rate))
        sp[i] = setpoint

    # --- benign effects ------------------------------------------------------
    t = np.arange(n)
    # Calibration drift is real but bounded: sensors are recalibrated long before
    # they read several percent off. Cap at +/-6% of span (the most the training
    # trajectories ever reach), so long streams don't drift into absurd values.
    drift = np.clip(profile.drift_frac_per_step * t, -MAX_DRIFT_FRAC, MAX_DRIFT_FRAC) * span
    modulation = 1.0 + profile.noise_modulation * np.sin(2 * np.pi * t / max(50.0, n / 3.0) + rng.uniform(0, 6.28))
    base_std = profile.noise_frac * span
    noise = rng.normal(0.0, 1.0, n) * base_std * modulation

    # --- degradation signature ----------------------------------------------
    deg = np.zeros(n)
    if degradation_start is not None:
        s = int(np.clip(degradation_start, 0.0, 1.0) * n)
        if s < n:
            deg[s:] = np.linspace(0.0, degradation_end, n - s)
    wear_noise = rng.normal(0.0, 1.0, n) * base_std * (5.0 * deg ** 1.5)
    spikes = (rng.random(n) < (0.002 + 0.06 * deg ** 2)) * rng.normal(0.0, 10.0 * base_std, n)

    values = np.clip(sp + drift + noise + wear_noise + spikes, lo - 0.05 * span, hi + 0.05 * span)
    rul = RUL_HORIZON_HOURS * (1.0 - deg)

    return Trajectory(register=register, values=values, degradation=deg, rul_hours=rul, profile=profile)


def generate_stream(n_steps: int, seed: int = 7,
                    failing: Optional[Dict[int, float]] = None,
                    envelopes: Optional[Dict[int, Tuple[float, float]]] = None) -> Dict[str, np.ndarray]:
    """
    Multivariate stream for all machines: values [n_steps, NUM_REGISTERS].

    failing: {register: degradation_start_fraction} for channels that wear out.
    """
    rng = np.random.default_rng(seed)
    failing = failing or {}
    values = np.zeros((n_steps, NUM_REGISTERS))
    degradation = np.zeros((n_steps, NUM_REGISTERS))
    for reg in range(NUM_REGISTERS):
        tr = generate_channel(reg, n_steps, rng, degradation_start=failing.get(reg),
                              envelope=(envelopes or {}).get(reg))
        values[:, reg] = tr.values
        degradation[:, reg] = tr.degradation
    return {"values": values, "degradation": degradation,
            "rul_hours": RUL_HORIZON_HOURS * (1.0 - degradation)}


# ---------------------------------------------------------------------------
# Cyber: legitimate operator command traffic
# ---------------------------------------------------------------------------

_TRAINING_KEY = b"synthetic-training-only-key-not-a-secret-0000"


def generate_normal_commands(n: int, seed: int = 11,
                             sources: Optional[List[str]] = None,
                             start_time: float = 1_700_000_000.0) -> Iterator[dict]:
    """
    Yields (command, current_state) pairs shaped exactly like the middleware's.
    Commands are properly HMAC-signed so feature extraction sees real frames.
    """
    rng = np.random.default_rng(seed)
    sources = sources or [LOOPBACK, "192.168.1.10"]
    plant = {m["register"]: float(m["initial"]) for m in MACHINES}
    clock = {s: start_time + float(rng.uniform(0, 2)) for s in sources}

    for i in range(n):
        src = sources[int(rng.integers(len(sources)))]
        # Operators issue one command every ~1.5-4 s per source.
        clock[src] += float(rng.uniform(1.5, 4.0))
        ts = clock[src]

        reg = int(ACTUATOR_REGISTERS[int(rng.integers(len(ACTUATOR_REGISTERS)))])   # only actuators are commanded
        m = MACHINES[reg]
        span = m["max"] - m["min"]
        step = m["operator"]["step"]
        if rng.random() < 0.08:
            move = float(rng.normal(0, 0.1 * span))      # occasional larger planned move
        else:
            move = float(rng.choice([-1, 1]) * step * rng.uniform(0.5, 2.0))
        value = float(np.clip(plant[reg] + move, m["min"], m["max"]))
        value = round(value, 1)

        nonce = secrets.randbits(64) if seed is None else int(rng.integers(0, 2**63))
        ts_ms = int(ts * 1000) - int(rng.uniform(0, 40))   # small network delay
        # Training frames are signed with a throwaway key: the model's features use
        # only frame structure and timing, never the shared secret.
        parsed = hmac_auth.parse_frame(hmac_auth.build_frame(
            reg, value, key=_TRAINING_KEY, nonce=nonce, timestamp_ms=ts_ms))
        cmd = make_command(f"train-{i}", ts, src, 16, reg, parsed["raw_value"] / 10.0,
                           raw_value=parsed["raw_value"], auth=parsed["auth"])
        state = {"registers": dict(plant), "timestamp": ts - float(rng.uniform(2, 15))}
        yield cmd, state
        plant[reg] = value


def unsigned_raw(value: float) -> int:
    return to_raw(value)
