"""
models/explain.py - why did the physical model flag THIS window? Turns one probability into a sentence an operator can act on.

No retraining and no new data: the explanation is computed from the model that is already loaded.

Two independent signals, reported side by side because they answer different questions:

  1. STAGE ATTRIBUTION (model-faithful, needs a reference window). Each of the 18 live channels (10 sensors, 8 actuators) belongs to
     one plant stage. For each stage the current 120 s window is rebuilt with THAT stage's channels replaced by the ones from the most
     recent window the model itself considered normal, every feature is recomputed from the rebuilt window, and the drop in
     probability is that stage's contribution. Swapping raw channels rather than feature columns matters: several features
     (the envelope counters, the residual aggregates) summarise the whole plant, so editing columns directly would leave them
     stale and hide the stage that caused them to move.
     This is a contrastive explanation - "what changed since the plant last looked fine" - so it needs no training data at run
     time. It costs one extra batched scoring pass (a few milliseconds) and runs only when the model flags.

  2. SENSOR DEVIATIONS (always available). The z-score of each sensor's latest reading against the MEASURED normal statistics, plus
     whether it is outside the measured envelope. This works even before a normal reference exists, and it is descriptive: it says
     what looks unusual, not what the model used.

Both are advisory, like the model itself. Nothing here can change a verdict; it only explains one.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Sequence

import numpy as np

from docs.interfaces import MACHINE_BY_NAME, STAGES

MIN_CONTRIBUTION = 0.02              # below this a stage is not called a driver (probability units)
MARGINAL_BAND = 0.05                 # |probability - threshold| under this is reported as a marginal call


def stage_of_tag(tag: str) -> Optional[str]:
    m = MACHINE_BY_NAME.get(tag)
    return f"S{m['stage']}" if m else None


def channel_groups(sensors: Sequence[str], actuators: Sequence[str]) -> Dict[str, Dict[str, List[int]]]:
    """{'S1': {'sensors': [col, ...], 'actuators': [col, ...]}, ...} - which window channels belong to each stage."""
    groups: Dict[str, Dict[str, List[int]]] = {}
    for kind, tags in (("sensors", sensors), ("actuators", actuators)):
        for i, tag in enumerate(tags):
            stage = stage_of_tag(tag)
            if stage:
                groups.setdefault(stage, {"sensors": [], "actuators": []})[kind].append(i)
    return groups


def stage_label(stage_id: str) -> str:
    for num, info in STAGES.items():
        if info["id"] == stage_id:
            return f"stage {num} ({info['name']})"
    return stage_id


def contributions(score_windows: Callable[[np.ndarray, np.ndarray], np.ndarray],
                  S: np.ndarray, A: np.ndarray, ref_S: np.ndarray, ref_A: np.ndarray,
                  groups: Dict[str, Dict[str, List[int]]]) -> Dict[str, float]:
    """How much each stage pushed the probability up, versus the reference window. One batched scoring pass.

    S/A are [1, window, channels] for the window being explained; ref_S/ref_A the same shape for the reference."""
    names = sorted(groups)
    Sv, Av = np.repeat(S, len(names), axis=0), np.repeat(A, len(names), axis=0)
    for row, name in enumerate(names):
        g = groups[name]
        if g["sensors"]:
            Sv[row][:, g["sensors"]] = ref_S[0][:, g["sensors"]]
        if g["actuators"]:
            Av[row][:, g["actuators"]] = ref_A[0][:, g["actuators"]]
    p_full = float(score_windows(S, A)[0])
    p_without = score_windows(Sv, Av)
    return {n: round(p_full - float(p_without[i]), 4) for i, n in enumerate(names)}


def deviations(sensors_last: np.ndarray, tags: Sequence[str], norm: Any, top: int = 3) -> List[Dict[str, Any]]:
    """The sensors furthest from measured normal right now, largest first."""
    z = (np.asarray(sensors_last, dtype=np.float64) - norm.mu) / np.where(norm.sd > 0, norm.sd, 1.0)
    out = []
    for i in np.argsort(-np.abs(z))[:top]:
        out.append({"tag": tags[i], "stage": stage_of_tag(tags[i]), "value": round(float(sensors_last[i]), 3),
                    "z": round(float(z[i]), 2), "direction": "above" if z[i] >= 0 else "below",
                    "outside_envelope": bool(sensors_last[i] < norm.lo[i] or sensors_last[i] > norm.hi[i])})
    return out


def suspect_stage(contrib: Dict[str, float]) -> Optional[str]:
    """The stage that moved the probability most, or None when no single stage stands out."""
    if not contrib:
        return None
    best = max(contrib, key=lambda k: contrib[k])
    return best if contrib[best] >= MIN_CONTRIBUTION else None


def _reading(d: Dict[str, Any]) -> str:
    out = f"{d['tag']} {abs(d['z']):.1f} sigma {d['direction']} normal"
    return out + " (outside the measured envelope)" if d["outside_envelope"] else out


def sentence(stage: Optional[str], contrib: Optional[Dict[str, float]], devs: List[Dict[str, Any]]) -> str:
    """One line a human can read off the dashboard. Always ends somewhere an operator can walk to."""
    here = [d for d in devs if stage and d["stage"] == stage]
    worst = (here or devs or [None])[0]
    detail = _reading(worst) if worst else ""
    if stage:
        return f"{stage_label(stage)} is driving this" + (f": {detail}" if detail else "")
    if contrib is not None:
        # Every stage looks wrong (a cascade, or an attack that bypassed the middleware): removing any one of them changes
        # little, so name where the worst reading is instead of pretending one stage is responsible.
        tail = f"; worst reading is in {stage_label(worst['stage'])}: {detail}" if worst and worst.get("stage") else (f"; most unusual reading: {detail}" if detail else "")
        return "no single stage dominates - plant-wide deviation" + tail
    return f"most unusual reading: {detail}" if detail else "no reading stands out"


def confidence(p: float, threshold: float) -> str:
    """'marginal' when the probability sits near the threshold - the call could go either way."""
    return "marginal" if abs(p - threshold) < MARGINAL_BAND else "clear"
