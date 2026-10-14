"""
models/physical_model.py - PhysicalModel: per-machine health index and RUL from live telemetry.

Runs ALONGSIDE the deterministic Physical Agent. The agent's bounds,
rate-of-change and cross-register rules still decide PASS/DROP; this model
is predictive maintenance: it estimates how worn each machine is.

Sliding window
    The model keeps a ring buffer shaped [window_size, NUM_REGISTERS, 3].
    Per sample and machine it stores:
        0  normalised value           (value - min) / span
        1  normalised first difference (value_t - value_t-1) / span
        2  normalised second difference (value_t - 2 value_t-1 + value_t-2) / span
    The second difference cancels constant offsets AND linear trends, so slow
    calibration drift and ramp-limited setpoint moves do not look like wear,
    while vibration noise and spikes (the wear signature) pass straight through.

Model
    RandomForestRegressor on robust per-machine window statistics -> RUL
    (hours). Health index = clip(RUL / horizon, 0, 1). Inference uses the
    packed-tree path (same output as sklearn, < 1 ms for all machines).

Safe fallback
    Missing/corrupt weights -> status NO_MODEL, health None. Window not yet
    full -> WARMING_UP. Inference errors are logged and reported as ERROR.
    Nothing here raises into the middleware.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Dict, List, Mapping, Optional, Union

import numpy as np

from docs.interfaces import MACHINES, NUM_REGISTERS
from models.telemetry_generator import RUL_HORIZON_HOURS
from models.tree_inference import PackedForestRegressor

log = logging.getLogger("industrialmind.models.physical")

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_WEIGHTS = os.path.join(HERE, "weights", "physical_model.joblib")

STEP_FEATURES: List[str] = ["value_norm", "delta_norm", "second_diff_norm"]
N_STEP_FEATURES = len(STEP_FEATURES)
DEFAULT_WINDOW = 60          # 60 samples x 0.2 s poll = 12 s of history

WINDOW_FEATURE_NAMES: List[str] = [
    "sd2_robust_scale",       # 1.4826 * MAD of second difference
    "sd2_std",
    "sd2_abs_q99",
    "sd2_frac_gt_2pct",
    "sd2_frac_gt_5pct",
    "sd2_noise_growth",       # std(second half) / std(first half)
    "delta_dev_abs_mean",     # mean |first diff - median first diff| (ramp-invariant)
    "sd2_kurtosis",
    "log_noise",
]

_SPANS = np.array([float(m["max"] - m["min"]) or 1.0 for m in MACHINES])
_MINS = np.array([float(m["min"]) for m in MACHINES])


def window_features_batch(window: np.ndarray) -> np.ndarray:
    """[window, channels, 3] -> [channels, n_features], vectorised across channels."""
    d1 = window[:, :, 1]
    d2 = window[:, :, 2]
    med = np.median(d2, axis=0)
    mad = np.median(np.abs(d2 - med), axis=0) * 1.4826
    std = d2.std(axis=0)
    a = np.abs(d2)
    half = d2.shape[0] // 2
    s1 = d2[:half].std(axis=0) + 1e-9
    s2 = d2[half:].std(axis=0) + 1e-9
    centred = d2 - d2.mean(axis=0)
    var = (centred ** 2).mean(axis=0) + 1e-12
    kurt = np.minimum((centred ** 4).mean(axis=0) / var ** 2, 50.0)
    return np.stack([
        mad,
        std,
        np.quantile(a, 0.99, axis=0),
        (a > 0.02).mean(axis=0),
        (a > 0.05).mean(axis=0),
        s2 / s1,
        np.abs(d1 - np.median(d1, axis=0)).mean(axis=0),
        kurt,
        np.log10(mad + 1e-6),
    ], axis=1)


def window_features(channel_window: np.ndarray) -> np.ndarray:
    """[window, 3] slice of one machine -> robust summary feature vector."""
    return window_features_batch(channel_window[:, None, :])[0]


def series_to_steps(values: np.ndarray, spans: np.ndarray, mins: np.ndarray) -> np.ndarray:
    """[n, channels] raw values -> [n, channels, 3] per-step features (first 2 rows have partial diffs)."""
    v = (values - mins) / spans
    d1 = np.zeros_like(v)
    d1[1:] = v[1:] - v[:-1]
    d2 = np.zeros_like(v)
    d2[2:] = v[2:] - 2 * v[1:-1] + v[:-2]
    return np.stack([v, d1, d2], axis=-1)


class PhysicalModel:
    """Sliding-window Random Forest health / RUL estimator for all machines."""

    def __init__(self, window_size: int = DEFAULT_WINDOW, n_estimators: int = 80,
                 max_depth: int = 14, random_state: int = 42,
                 assess_interval_s: float = float(os.environ.get("IM_HEALTH_REFRESH_SECONDS", "1.0"))) -> None:
        self.window_size = window_size
        # Health/RUL change over hours; recompute at most this often.
        self.assess_interval_s = assess_interval_s
        self._cache_time = 0.0
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.random_state = random_state

        self._buffer = np.zeros((window_size, NUM_REGISTERS, N_STEP_FEATURES))
        self._count = 0                      # samples written in total
        self._prev = np.full(NUM_REGISTERS, np.nan)
        self._prev2 = np.full(NUM_REGISTERS, np.nan)
        self._lock = threading.Lock()

        self._model = None
        self._packed: Optional[PackedForestRegressor] = None
        self.status = "NO_MODEL"
        self.metadata: Dict[str, Any] = {}

        self._cache: Optional[Dict[str, Any]] = None
        self._cache_count = -1

    # -------------------------------------------------------------- window
    def update(self, registers: Mapping[Union[int, str], float]) -> None:
        """Push one telemetry sample. Keys may be register numbers or names."""
        row = np.empty(NUM_REGISTERS)
        for i, m in enumerate(MACHINES):
            v = registers.get(m["register"], registers.get(m["name"]))
            if v is None:
                v = self._prev[i] if not np.isnan(self._prev[i]) else m["initial"]
            row[i] = float(v)

        v = (row - _MINS) / _SPANS
        prev = np.where(np.isnan(self._prev), v, self._prev)
        prev2 = np.where(np.isnan(self._prev2), prev, self._prev2)
        step = np.stack([v, v - prev, v - 2 * prev + prev2], axis=-1)

        with self._lock:
            self._buffer[self._count % self.window_size] = step
            self._count += 1
            self._prev2, self._prev = prev, v

    def window_tensor(self) -> np.ndarray:
        """Current window, oldest -> newest, shape [window_size, NUM_REGISTERS, 3]."""
        with self._lock:
            if self._count < self.window_size:
                return self._buffer[: self._count].copy()
            start = self._count % self.window_size
            return np.concatenate([self._buffer[start:], self._buffer[:start]]).copy()

    @property
    def is_warm(self) -> bool:
        return self._count >= self.window_size

    def reset_window(self) -> None:
        with self._lock:
            self._buffer[:] = 0
            self._count = 0
            self._prev[:] = np.nan
            self._prev2[:] = np.nan
            self._cache, self._cache_count, self._cache_time = None, -1, 0.0

    # ----------------------------------------------------------------- fit
    def fit(self, X: np.ndarray, y_rul_hours: np.ndarray) -> "PhysicalModel":
        """X: [n_windows, len(WINDOW_FEATURE_NAMES)], y: RUL hours."""
        from sklearn.ensemble import RandomForestRegressor

        if X.ndim != 2 or X.shape[1] != len(WINDOW_FEATURE_NAMES):
            raise ValueError(f"expected [n, {len(WINDOW_FEATURE_NAMES)}] features, got {X.shape}")
        self._model = RandomForestRegressor(
            n_estimators=self.n_estimators, max_depth=self.max_depth,
            min_samples_leaf=5, random_state=self.random_state, n_jobs=-1,
        ).fit(X, y_rul_hours)
        self._model.n_jobs = 1
        self._packed = PackedForestRegressor(self._model)
        self.status = "OK"
        self.metadata = {"trained_windows": int(X.shape[0]), "window_size": self.window_size,
                         "rul_horizon_hours": RUL_HORIZON_HOURS,
                         "feature_names": WINDOW_FEATURE_NAMES}
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """RUL hours for a matrix of window features."""
        if self._packed is None:
            raise RuntimeError("PhysicalModel has no trained weights")
        return np.clip(self._packed.predict(np.atleast_2d(X)), 0.0, RUL_HORIZON_HOURS)

    def predict_window(self, window: np.ndarray) -> Dict[str, np.ndarray]:
        """[window, NUM_REGISTERS, 3] -> {"rul_hours": [N], "health_index": [N]}."""
        rul = self.predict(window_features_batch(window))
        return {"rul_hours": rul, "health_index": np.clip(rul / RUL_HORIZON_HOURS, 0.0, 1.0)}

    # -------------------------------------------------------------- assess
    def assess(self) -> Dict[str, Any]:
        """Health report for every machine from the live window. Never raises."""
        t0 = time.perf_counter()
        count = self._count
        if self._cache is not None and (
            self._cache_count == count
            or (self._cache.get("status") == "OK"
                and time.monotonic() - self._cache_time < self.assess_interval_s)
        ):
            return self._cache

        report: Dict[str, Any] = {
            "model": "PhysicalModel",
            "status": self.status,
            "window_fill": f"{min(count, self.window_size)}/{self.window_size}",
            "min_health_index": None,
            "machines": {},
        }
        try:
            if self._packed is None:
                report["status"] = "NO_MODEL"
            elif count < self.window_size:
                report["status"] = "WARMING_UP"
            else:
                out = self.predict_window(self.window_tensor())
                for i, m in enumerate(MACHINES):
                    report["machines"][m["name"]] = {
                        "health_index": round(float(out["health_index"][i]), 3),
                        "rul_hours": round(float(out["rul_hours"][i]), 1),
                    }
                report["min_health_index"] = round(float(out["health_index"].min()), 3)
                report["status"] = "OK"
        except Exception:
            log.exception("PhysicalModel inference failed - abstaining")
            report.update(status="ERROR", machines={}, min_health_index=None)

        report["latency_ms"] = round((time.perf_counter() - t0) * 1000.0, 4)
        report["computed_at"] = time.time()
        self._cache, self._cache_count, self._cache_time = report, count, time.monotonic()
        return report

    # --------------------------------------------------------- persistence
    def save(self, path: str = DEFAULT_WEIGHTS) -> None:
        import joblib
        if self._model is None:
            raise RuntimeError("nothing to save - model not trained")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump({"model": self._model, "metadata": self.metadata,
                     "window_size": self.window_size}, path)

    @classmethod
    def load(cls, path: str = DEFAULT_WEIGHTS) -> "PhysicalModel":
        """Loads weights; on any failure returns an abstaining model (safe state)."""
        if not os.path.exists(path):
            log.warning("PhysicalModel weights not found at %s - health estimation disabled (NO_MODEL)", path)
            return cls()
        try:
            import joblib
            blob = joblib.load(path)
            inst = cls(window_size=int(blob.get("window_size", DEFAULT_WINDOW)))
            inst._model = blob["model"]
            inst._packed = PackedForestRegressor(inst._model)
            inst.metadata = dict(blob.get("metadata", {}))
            inst.status = "OK"
            return inst
        except Exception:
            log.exception("PhysicalModel weights at %s unreadable - health estimation disabled", path)
            return cls()
