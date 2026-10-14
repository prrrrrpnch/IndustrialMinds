"""
attacker/scenarios.py - randomised attack PLANS for the Phase 8 attacker (pure functions, no network).

A plan is a list of timed steps; attacker.py executes it over Modbus. Every parameter that matters (target
register, timing, intensity, step size, count, direction) is drawn from a distribution by a seeded RNG, so
runs differ but any run is reproducible from its seed.

ORIGIN LABELS (honest provenance, also printed by the attacker and written to its log):
  swat-derived         the TYPE is a behaviour seen in SWaT's labelled attack windows (an actuator forced to a wrong
                       state, a sensor/process value frozen, a slow drift/ramp, a physically inconsistent combination).
                       Parameter ranges are taken from docs/swat_attack_profile.json when it exists (produced by
                       tools/swat_attack_profile.py, run locally on the SWaT archive, aggregate only). Without that
                       file the ranges are DESIGN DEFAULTS and the plan says so (`ranges_from`).
  synthetic-extension  SWaT has no network-layer attacks (no flood / replay / rule-boundary probing: the archive has no
                       network fields, no pcaps, no attack list). These types are rule-tested constructions, NOT SWaT data.

TYPES
  freeze               swat-derived        hold an actuator at one wrong value, re-asserting it (SWaT: frozen/forced actuator)
  ramp                 swat-derived        drift an actuator in small steps (SWaT: slow drift attacks)
  cross-register       swat-derived        drive two actuators into a physically inconsistent combination (SWaT: multi-point attacks)
  impossible-command   synthetic-extension signed out-of-range value, random actuator/magnitude
  flood                synthetic-extension signed burst above the per-source rate limit, random size/pace
  replay               synthetic-extension capture one signed frame, resend it k times with random delays
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

import numpy as np

from docs.interfaces import ACTUATOR_REGISTERS, CROSS_REGISTER_RULES, MACHINE_BY_REGISTER

TYPES: Dict[str, str] = {
    "freeze": "swat-derived",
    "ramp": "swat-derived",
    "cross-register": "swat-derived",
    "impossible-command": "synthetic-extension",
    "flood": "synthetic-extension",
    "replay": "synthetic-extension",
}

PROFILE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "swat_attack_profile.json")

# Design defaults, used when no SWaT attack profile has been generated. Units: seconds / percent of range.
DEFAULTS: Dict[str, Any] = {
    "ramp_total_fraction": [0.15, 0.60],     # how far an actuator is dragged, as a fraction of its range
    "ramp_step_pct": [1.0, 12.0],            # per-command step
    "ramp_interval_s": [0.5, 3.0],
    "freeze_writes": [3, 8],
    "freeze_interval_s": [0.4, 3.0],
}


def load_profile(path: str = PROFILE_PATH) -> Optional[Dict[str, Any]]:
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _ranges(profile: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Defaults, overridden by whatever the SWaT profile supplies under 'attacker_ranges'."""
    r = dict(DEFAULTS)
    if profile:
        r.update({k: v for k, v in profile.get("attacker_ranges", {}).items() if k in DEFAULTS})
    return r


def _u(rng: np.random.Generator, lo_hi, integer: bool = False):
    lo, hi = lo_hi
    return int(rng.integers(lo, hi + 1)) if integer else float(rng.uniform(lo, hi))


def _clip(reg: int, v: float) -> float:
    m = MACHINE_BY_REGISTER[reg]
    return round(float(min(max(v, m["min"]), m["max"])), 1)


def _base(state: Optional[Dict[int, float]], reg: int) -> float:
    if state and reg in state:
        return float(state[reg])
    return float(MACHINE_BY_REGISTER[reg]["initial"])


def _name(reg: int) -> str:
    return MACHINE_BY_REGISTER[reg]["name"]


def _step(t: float, reg: int, value: float, kind: str = "signed", **extra: Any) -> Dict[str, Any]:
    return {"t": round(float(t), 3), "kind": kind, "register": reg, "tag": _name(reg), "value": float(value), **extra}


def plan_freeze(rng: np.random.Generator, state, rg) -> Dict[str, Any]:
    reg = int(rng.choice(ACTUATOR_REGISTERS))
    m = MACHINE_BY_REGISTER[reg]
    nominal = float(m["initial"])
    # a wrong-but-valid state: far from nominal (SWaT: actuator forced off, or held on while it should cycle)
    hold = _clip(reg, nominal * rng.uniform(0.0, 0.5) if rng.random() < 0.5 else nominal + rng.uniform(0.2, 0.45) * (m["max"] - m["min"]))
    n, gap = _u(rng, rg["freeze_writes"], True), _u(rng, rg["freeze_interval_s"])
    steps, t = [], 0.0
    for _ in range(n):
        steps.append(_step(t, reg, hold))
        t += gap * rng.uniform(0.7, 1.3)
    return {"params": {"target": _name(reg), "hold_value": hold, "writes": n, "interval_s": round(gap, 3)}, "steps": steps}


def plan_ramp(rng: np.random.Generator, state, rg) -> Dict[str, Any]:
    reg = int(rng.choice(ACTUATOR_REGISTERS))
    m = MACHINE_BY_REGISTER[reg]
    span = m["max"] - m["min"]
    start = _base(state, reg)
    sign = 1.0 if (rng.random() < 0.5 and start < m["max"] - 0.3 * span) or start - 0.3 * span < m["min"] else -1.0
    goal = _clip(reg, start + sign * _u(rng, rg["ramp_total_fraction"]) * span)
    step_pct = _u(rng, rg["ramp_step_pct"])
    gap = _u(rng, rg["ramp_interval_s"])
    step = max(0.5, step_pct / 100.0 * span)
    steps, cur, t = [], start, 0.0
    while abs(goal - cur) > 0.3 and len(steps) < 60:
        cur = _clip(reg, cur + float(np.sign(goal - cur)) * min(step, abs(goal - cur)))
        steps.append(_step(t, reg, cur))
        t += gap * rng.uniform(0.8, 1.2)
    return {"params": {"target": _name(reg), "start": round(start, 1), "goal": goal, "step": round(step, 2),
                       "interval_s": round(gap, 3), "steps": len(steps)}, "steps": steps}


def plan_cross_register(rng: np.random.Generator, state, rg) -> Dict[str, Any]:
    rule = CROSS_REGISTER_RULES[int(rng.integers(len(CROSS_REGISTER_RULES)))]
    conds = list(rule["conditions"])
    if rng.random() < 0.5:
        conds.reverse()                                   # which half of the unsafe combination is set first
    step_pct, gap = float(rng.uniform(4, 15)), float(rng.uniform(0.5, 3.0))
    steps, t, goals = [], 0.0, {}
    for reg, op, thr in conds:
        m = MACHINE_BY_REGISTER[reg]
        span = m["max"] - m["min"]
        goal = _clip(reg, thr + rng.uniform(0, 0.15 * span) if op == ">=" else thr - rng.uniform(0, max(thr, 1.0)))
        goals[_name(reg)] = goal
        cur = _base(state, reg)
        step = max(0.5, step_pct / 100.0 * span)
        while abs(goal - cur) > 0.3 and len(steps) < 80:
            cur = _clip(reg, cur + float(np.sign(goal - cur)) * min(step, abs(goal - cur)))
            steps.append(_step(t, reg, cur))
            t += gap * rng.uniform(0.8, 1.2)
    return {"params": {"rule": rule["id"], "goals": goals, "step_pct": round(step_pct, 2), "interval_s": round(gap, 3),
                       "steps": len(steps)}, "steps": steps}


def plan_impossible(rng: np.random.Generator, state, rg) -> Dict[str, Any]:
    reg = int(rng.choice(ACTUATOR_REGISTERS))
    m = MACHINE_BY_REGISTER[reg]
    n = int(rng.integers(1, 4))
    steps, t = [], 0.0
    mags, gaps = [], []
    for _ in range(n):
        v = round(min(float(m["max"]) * float(rng.uniform(1.1, 10.0)), 6553.0), 1)
        mags.append(v)
        steps.append(_step(t, reg, v))
        g = float(rng.uniform(0.3, 2.0))
        gaps.append(g)
        t += g
    return {"params": {"target": _name(reg), "values": mags, "writes": n, "max_value": max(mags),
                       "overshoot_factor": round(max(mags) / float(m["max"]), 2), "mean_gap_s": round(float(np.mean(gaps)), 3)},
            "steps": steps}


def plan_flood(rng: np.random.Generator, state, rg) -> Dict[str, Any]:
    reg = int(rng.choice(ACTUATOR_REGISTERS))
    base = _base(state, reg)
    n = int(rng.integers(8, 41))
    gap = float(rng.uniform(0.01, 0.15))
    jitter = float(rng.uniform(0.05, 0.5))
    steps, t = [], 0.0
    for i in range(n):
        steps.append(_step(t, reg, _clip(reg, base + jitter * (i + 1))))
        t += gap * float(rng.uniform(0.7, 1.3))
    return {"params": {"target": _name(reg), "writes": n, "interval_s": round(gap, 4), "offered_rate_per_s": round(1.0 / gap, 1)},
            "steps": steps}


def plan_replay(rng: np.random.Generator, state, rg) -> Dict[str, Any]:
    reg = int(rng.choice(ACTUATOR_REGISTERS))
    value = _clip(reg, _base(state, reg) + float(rng.uniform(-3, 3)))
    k = int(rng.integers(1, 6))
    steps, t = [_step(0.0, reg, value)], 0.0
    delays = []
    for _ in range(k):
        d = float(rng.uniform(0.05, 1.5))
        delays.append(round(d, 3))
        t += d
        steps.append(_step(t, reg, value, kind="replay_of", ref=0))
    return {"params": {"target": _name(reg), "value": value, "replays": k, "delays_s": delays}, "steps": steps}


_PLANNERS = {"freeze": plan_freeze, "ramp": plan_ramp, "cross-register": plan_cross_register,
             "impossible-command": plan_impossible, "flood": plan_flood, "replay": plan_replay}


def make_plan(attack_type: str, seed: int, state: Optional[Dict[int, float]] = None,
              profile: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Deterministic for (attack_type, seed, state, profile)."""
    if attack_type not in _PLANNERS:
        raise ValueError(f"unknown randomised attack type {attack_type!r}; choose from {sorted(_PLANNERS)}")
    rng = np.random.default_rng(int(seed))
    rg = _ranges(profile)
    body = _PLANNERS[attack_type](rng, state, rg)
    return {"type": attack_type, "seed": int(seed), "origin": TYPES[attack_type],
            "ranges_from": "docs/swat_attack_profile.json (SWaT-derived)" if profile and profile.get("attacker_ranges") else "design defaults",
            **body}
