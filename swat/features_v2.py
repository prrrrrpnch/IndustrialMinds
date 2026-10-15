"""
swat/features_v2.py - EXPERIMENTAL richer window features for the physical model (research track; the live model is unchanged).

Why: the shipped model sees one 30 s window of 87 features and misses slow attacks (a 30 s window barely moves) and relationships
between sensors. Two additions, both computed only from the same 10 sensors and 8 actuators the live twin provides:

  1. LONG-CONTEXT features over a 120 s window ending at the same second: per-sensor slope, std and net change, and per-actuator
     toggles. A slow drift that is invisible in 30 s is visible in 120 s.
  2. CROSS-SENSOR CONSISTENCY ("invariant") RESIDUALS, learned from NORMAL windows only: for each sensor, a ridge regression predicts
     its 30 s trend (z-scored slope) from the OTHER sensors' window means and the actuators' on-fractions. During an attack that
     breaks a physical relationship (a tank level that does not follow the flows, a pressure that does not follow the pump) the
     prediction error grows. Trend-based, so it does not carry SWaT's day-to-day level drift.

The training windows are the same 5 s-stride windows as swat/physical_features.build_windows, restricted to those with a full 120 s
history (the first 90 s of each chunk are lost). Feature code is shared by training and (later) live use.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

import numpy as np
import pandas as pd

from swat.physical_features import (ACTUATORS, FEATURE_NAMES, SENSORS, VARIANTS, WINDOW, Norm, actuator_class_series, window_features)

LONG = 120
LONG_NAMES: List[str] = [f"{s}.{f}@{LONG}" for s in SENSORS for f in ("slope", "std", "delta")] + [f"{a}.toggles@{LONG}" for a in ACTUATORS]
RESID_NAMES: List[str] = [f"{s}.resid" for s in SENSORS] + ["resid_abs_max", "resid_abs_mean"]
_SLOPE = [FEATURE_NAMES.index(f"{s}.slope") for s in SENSORS]
_MEAN = [FEATURE_NAMES.index(f"{s}.mean") for s in SENSORS]
_FRAC = [FEATURE_NAMES.index(f"{a}.frac_on") for a in ACTUATORS]
BASE_COLS = VARIANTS["drift_robust"]          # the 67 shipped features (no absolute levels)


def long_features(Sl: np.ndarray, Al: np.ndarray, norm: Norm) -> np.ndarray:
    """Sl [n, LONG, 10] raw sensors, Al [n, LONG, 8] actuator 0/1 -> [n, len(LONG_NAMES)]."""
    n, W, _ = Sl.shape
    z = (Sl - norm.mu) / norm.sd
    t = np.arange(W, dtype=np.float64) - (W - 1) / 2.0
    slope = (z * t[None, :, None]).sum(axis=1) / float((t ** 2).sum())
    per = np.stack([slope, z.std(axis=1), z[:, -1, :] - z[:, 0, :]], axis=2).reshape(n, -1)
    toggles = np.abs(np.diff(Al, axis=1)).sum(axis=1)
    return np.concatenate([per, toggles], axis=1)


class ResidualModel:
    """Per-sensor ridge regression of the 30 s trend on the other sensors' means + actuator on-fractions. Fit on NORMAL windows only."""

    def __init__(self, alpha: float = 10.0) -> None:
        self.alpha = alpha
        self.w: List[np.ndarray] = []
        self.b: np.ndarray = np.zeros(len(SENSORS))
        self.sd: np.ndarray = np.ones(len(SENSORS))
        self.mu_x: List[np.ndarray] = []

    def _design(self, X: np.ndarray, i: int) -> np.ndarray:
        others = [c for j, c in enumerate(_MEAN) if j != i]
        return np.concatenate([X[:, others], X[:, _FRAC]], axis=1)

    def fit(self, X87_normal: np.ndarray) -> "ResidualModel":
        self.w, self.mu_x = [], []
        for i in range(len(SENSORS)):
            A, y = self._design(X87_normal, i), X87_normal[:, _SLOPE[i]]
            mu = A.mean(axis=0)
            Ac = A - mu
            w = np.linalg.solve(Ac.T @ Ac + self.alpha * np.eye(Ac.shape[1]), Ac.T @ (y - y.mean()))
            self.w.append(w)
            self.mu_x.append(mu)
            self.b[i] = float(y.mean())
            self.sd[i] = float(max((y - (Ac @ w + y.mean())).std(), 1e-6))
        return self

    def transform(self, X87: np.ndarray) -> np.ndarray:
        r = np.empty((X87.shape[0], len(SENSORS)))
        for i in range(len(SENSORS)):
            pred = (self._design(X87, i) - self.mu_x[i]) @ self.w[i] + self.b[i]
            r[:, i] = (X87[:, _SLOPE[i]] - pred) / self.sd[i]
        a = np.abs(r)
        return np.concatenate([r, a.max(axis=1, keepdims=True), a.mean(axis=1, keepdims=True)], axis=1)


FEATURE_SETS: Dict[str, str] = {
    "v1_67": "the 67 shipped features (30 s window, no absolute levels)",
    "v1_long": "v1_67 + 120 s long-context features",
    "v1_long_resid": "v1_67 + 120 s long-context features + cross-sensor consistency residuals",
}


def assemble(name: str, X87: np.ndarray, XL: np.ndarray, resid: "ResidualModel | None") -> np.ndarray:
    parts = [X87[:, BASE_COLS]]
    if name in ("v1_long", "v1_long_resid"):
        parts.append(XL)
    if name == "v1_long_resid":
        if resid is None:
            raise ValueError("v1_long_resid needs a fitted ResidualModel")
        parts.append(resid.transform(X87))
    return np.concatenate(parts, axis=1)


def feature_names(name: str) -> List[str]:
    names = [FEATURE_NAMES[c] for c in BASE_COLS]
    if name in ("v1_long", "v1_long_resid"):
        names += LONG_NAMES
    if name == "v1_long_resid":
        names += RESID_NAMES
    return names


def build_windows_v2(stream: pd.DataFrame, norm: Norm, stride: int = 5, batch: int = 4000) -> Tuple[np.ndarray, np.ndarray, pd.DataFrame]:
    """(X87 [n,87], XL [n,len(LONG_NAMES)], meta[epoch,label,seg,block,chunk]) for windows with a full LONG-second history."""
    chunk = stream["chunk"].to_numpy()
    S = stream[SENSORS].to_numpy(dtype=np.float64)
    A = np.column_stack([actuator_class_series(stream[a].to_numpy(dtype=np.float64), a.startswith("MV"), chunk) for a in ACTUATORS])
    bounds_idx = np.flatnonzero(np.concatenate(([True], chunk[1:] != chunk[:-1], [True])))
    ends = [np.arange(a + LONG - 1, b, stride) for a, b in zip(bounds_idx[:-1], bounds_idx[1:]) if b - a >= LONG]
    if not ends:
        return np.empty((0, len(FEATURE_NAMES))), np.empty((0, len(LONG_NAMES))), stream.iloc[:0][["epoch", "label", "seg", "block", "chunk"]]
    e = np.concatenate(ends)
    offs = np.arange(-LONG + 1, 1)
    keep, x87, xl = [], [], []
    for i in range(0, len(e), batch):
        eb = e[i:i + batch]
        idx = eb[:, None] + offs[None, :]
        Sl, Al = S[idx], A[idx]
        ok = ~(np.isnan(Sl).any(axis=(1, 2)) | np.isnan(Al).any(axis=(1, 2)))
        if ok.any():
            x87.append(window_features(Sl[ok][:, -WINDOW:], Al[ok][:, -WINDOW:], norm))
            xl.append(long_features(Sl[ok], Al[ok], norm))
            keep.append(eb[ok])
    k = np.concatenate(keep)
    meta = stream.iloc[k][["epoch", "label", "seg", "block", "chunk"]].reset_index(drop=True)
    return np.vstack(x87), np.vstack(xl), meta
