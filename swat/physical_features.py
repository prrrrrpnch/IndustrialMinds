"""
swat/physical_features.py - window features for the SWaT-trained PhysicalModel, measured bounds,
and the SINGLE feature implementation shared by training and the live middleware.

Inputs are limited to what the live twin can provide (the twin's own SWaT-backed points):
  sensors   (10): LIT101 FIT101 AIT202 FIT201 LIT301 DPIT301 LIT401 AIT402 PIT501 FIT501
  actuators ( 8): P101 P203 P205 MV302 P302 P402 UV401 P501   (on/off classes, 1 -> 0, 2 -> 1)
Excluded on purpose: MV101 (NaN for the whole 7-day normal period in the archive) and MV503
(twin-only synthetic, no SWaT column).

Windows are WINDOW seconds at 1 Hz (the live model decimates the 5 Hz poll to 1 Hz). Features are
normalised with statistics measured on TRAIN-block NORMAL rows only.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from docs.interfaces import MACHINES

WINDOW = 30           # seconds
SENSORS: List[str] = [m["name"] for m in MACHINES if m["kind"] == "sensor"]
ACTUATORS: List[str] = ["P101", "P203", "P205", "MV302", "P302", "P402", "UV401", "P501"]
ON_THRESHOLD = 50.0   # percent: >= this is "on/open" for live (continuous) actuator values
ENVELOPE_MARGIN = 0.10   # envelope = [p0.1, p99.9] widened by 10 % of that span

_PER_SENSOR = ["last", "mean", "std", "slope", "range", "delta"]
_PER_ACT = ["state", "toggles", "frac_on"]
FEATURE_NAMES: List[str] = (
    [f"{s}.{f}" for s in SENSORS for f in _PER_SENSOR]
    + [f"{a}.{f}" for a in ACTUATORS for f in _PER_ACT]
    + ["flow_balance_101_201", "sensors_outside_envelope", "max_envelope_excess"]
)
_I101, _I201 = SENSORS.index("FIT101"), SENSORS.index("FIT201")

# Feature-set variants (validation picks one): "drift_robust" drops the absolute sensor levels (.last/.mean),
# which carry the day-to-day drift of SWaT, keeping dynamics (std/slope/range/delta), actuators and envelope features.
_ABS_LEVEL = {f"{s}.{f}" for s in SENSORS for f in ("last", "mean")}
VARIANTS: Dict[str, List[int]] = {
    "full": list(range(len(FEATURE_NAMES))),
    "drift_robust": [i for i, n in enumerate(FEATURE_NAMES) if n not in _ABS_LEVEL],
}

PROVENANCE: List[Tuple[str, str, str]] = [
    ("<sensor>.last/mean/std/slope/range/delta (10 sensors x 6)",
     "z-scored 1 Hz sensor columns " + ", ".join(SENSORS) + " over a 30 s trailing window (mean/std from train-block normal rows)", "real (SWaT columns), derived statistics"),
    ("<actuator>.state/toggles/frac_on (8 actuators x 3)",
     "actuator state columns " + ", ".join(ACTUATORS) + " mapped 1->off, 2->on; valve transit state 0 forward-filled", "derived"),
    ("flow_balance_101_201", "difference of window-mean z-scores of FIT101 and FIT201 (stage 1 -> stage 2 continuity)", "derived"),
    ("sensors_outside_envelope, max_envelope_excess", "distance outside the MEASURED train-normal envelope [p0.1, p99.9] +10 %", "derived from measured bounds"),
]
DROPPED_INPUTS: List[Tuple[str, str]] = [
    ("MV101", "NaN for the whole 7-day normal period in the archive (only present in the attack period)"),
    ("MV503", "twin-only synthetic actuator: no SWaT column, covered by rules only"),
    ("health index / RUL", "SWaT has no degradation or run-to-failure labels; not derivable, so removed (never invented)"),
    ("33 other SWaT columns (P102, AIT201, FIT301, MV301, PIT502, ...)", "the live twin has no such points, so a model using them could not run live"),
]


def actuator_class_series(values: np.ndarray, is_valve: bool, chunk: np.ndarray) -> np.ndarray:
    """SWaT state column -> 0/1 float (NaN where unknown). Valve transit (0) carries the last stable state."""
    mapped = np.where(values == 2, 1.0, np.where(values == 1, 0.0, np.nan))
    if is_valve:
        ff = pd.Series(mapped).groupby(chunk).ffill().to_numpy()
        mapped = np.where(values == 0, ff, mapped)
    return mapped


def compute_bounds(sensor_values: pd.DataFrame) -> Dict[str, Any]:
    """Measured statistics of normal operation (call with TRAIN-block NORMAL rows only)."""
    out: Dict[str, Any] = {}
    for s in sensor_values.columns:
        x = sensor_values[s].dropna().to_numpy(dtype=np.float64)
        q = np.quantile(x, [0.001, 0.005, 0.5, 0.995, 0.999])
        span = q[4] - q[0]
        m = ENVELOPE_MARGIN * span
        lo = float(q[0] - m)
        if x.min() >= 0.0:
            lo = max(lo, 0.0)          # a sensor that is never negative cannot have a negative envelope
        out[s] = {"n": int(x.size), "min": float(x.min()), "p0.1": float(q[0]), "p0.5": float(q[1]), "median": float(q[2]),
                  "p99.5": float(q[3]), "p99.9": float(q[4]), "max": float(x.max()), "mean": float(x.mean()),
                  "std": float(x.std()), "envelope_lo": lo, "envelope_hi": float(q[4] + m)}
    return out


class Norm:
    """Normalisation + envelope arrays aligned with SENSORS."""

    def __init__(self, bounds: Dict[str, Any]) -> None:
        self.mu = np.array([bounds[s]["mean"] for s in SENSORS], dtype=np.float64)
        self.sd = np.array([max(bounds[s]["std"], 1e-6) for s in SENSORS], dtype=np.float64)
        self.lo = np.array([bounds[s]["envelope_lo"] for s in SENSORS], dtype=np.float64)
        self.hi = np.array([bounds[s]["envelope_hi"] for s in SENSORS], dtype=np.float64)


def window_features(Sw: np.ndarray, Aw: np.ndarray, norm: Norm) -> np.ndarray:
    """
    Sw [n, W, 10] raw sensor windows, Aw [n, W, 8] actuator 0/1 windows -> [n, len(FEATURE_NAMES)].
    This is THE implementation: training builds windows from the SWaT stream and calls it, the live
    model builds one window from telemetry and calls it.
    """
    n, W, _ = Sw.shape
    z = (Sw - norm.mu) / norm.sd
    t = np.arange(W, dtype=np.float64) - (W - 1) / 2.0
    slope = (z * t[None, :, None]).sum(axis=1) / float((t ** 2).sum())
    last, first = z[:, -1, :], z[:, 0, :]
    per_sensor = np.stack([last, z.mean(axis=1), z.std(axis=1), slope, z.max(axis=1) - z.min(axis=1), last - first], axis=2)
    toggles = np.abs(np.diff(Aw, axis=1)).sum(axis=1)
    per_act = np.stack([Aw[:, -1, :], toggles, Aw.mean(axis=1)], axis=2)
    x = Sw[:, -1, :]
    excess = np.maximum(np.maximum(norm.lo - x, x - norm.hi), 0.0) / norm.sd
    zmean = z.mean(axis=1)
    cross = np.stack([zmean[:, _I101] - zmean[:, _I201], (excess > 0).sum(axis=1).astype(np.float64), excess.max(axis=1)], axis=1)
    return np.concatenate([per_sensor.reshape(n, -1), per_act.reshape(n, -1), cross], axis=1)


def build_windows(stream: pd.DataFrame, norm: Norm, stride: int = 5, batch: int = 20000
                  ) -> Tuple[np.ndarray, pd.DataFrame]:
    """Training windows from the loader's stream. Returns (X, meta) with meta rows aligned to X."""
    chunk = stream["chunk"].to_numpy()
    S = stream[SENSORS].to_numpy(dtype=np.float64)
    A = np.column_stack([actuator_class_series(stream[a].to_numpy(dtype=np.float64), a.startswith("MV"), chunk)
                         for a in ACTUATORS])
    ends: List[np.ndarray] = []
    bounds_idx = np.flatnonzero(np.concatenate(([True], chunk[1:] != chunk[:-1], [True])))
    for a, b in zip(bounds_idx[:-1], bounds_idx[1:]):           # one contiguous chunk = rows [a, b)
        if b - a >= WINDOW:
            ends.append(np.arange(a + WINDOW - 1, b, stride))
    if not ends:
        return np.empty((0, len(FEATURE_NAMES))), stream.iloc[:0][["epoch", "label", "seg", "block"]]
    e = np.concatenate(ends)
    offs = np.arange(-WINDOW + 1, 1)
    keep, feats = [], []
    for i in range(0, len(e), batch):
        eb = e[i:i + batch]
        idx = eb[:, None] + offs[None, :]
        Sw, Aw = S[idx], A[idx]
        ok = ~(np.isnan(Sw).any(axis=(1, 2)) | np.isnan(Aw).any(axis=(1, 2)))
        if ok.any():
            feats.append(window_features(Sw[ok], Aw[ok], norm))
            keep.append(eb[ok])
    X = np.vstack(feats)
    k = np.concatenate(keep)
    meta = stream.iloc[k][["epoch", "label", "seg", "block"]].reset_index(drop=True)
    return X, meta
