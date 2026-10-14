"""
models/physical_model.py - PhysicalModel: learned (ML) plausibility check on the plant TELEMETRY.

Two layers exist in the physical branch and they are different things:
  * RULES (middleware/physical_agent.py): bounds on commands, rate of change, cross-register rules,
    feedback mismatch. Deterministic; the hard gate.
  * MODEL (this file): trained on SWaT ONLY. A 30 s window (1 Hz) over the twin's SWaT-backed sensors
    and actuators is turned into 87 features (swat/physical_features.py) and scored by
      - an Isolation Forest (normal windows only)  -> anomaly_score
      - a supervised forest (window inside a SWaT attack segment) -> attack_probability
    plus the MEASURED normal envelope (train-block normal p0.1..p99.9) -> bounds_violations.
    threat_flag = either score above its threshold (thresholds chosen on the validation block).

The old health-index / RUL model is gone: SWaT has no degradation labels, so RUL cannot be derived and
is never invented.

Safe fallback: no/stale/corrupt weights, a warming-up window, or any failure -> the model ABSTAINS
(status NO_MODEL / WARMING_UP / ERROR, threat_flag False) and never raises into the middleware.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections import deque
from typing import Any, Deque, Dict, List, Mapping, Optional, Tuple, Union

import numpy as np

from docs.interfaces import MACHINE_BY_NAME, MACHINE_BY_REGISTER
from models.tree_inference import PackedForestRegressor, PackedIsolationForest
from swat.physical_features import (ACTUATORS, FEATURE_NAMES, ON_THRESHOLD, SENSORS, WINDOW, Norm, window_features)

log = logging.getLogger("industrialmind.models.physical")

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_WEIGHTS = os.path.join(HERE, "weights", "physical_model.joblib")
DEFAULT_WINDOW = WINDOW
SAMPLE_PERIOD_S = 1.0          # the live poll (5 Hz) is decimated to the 1 Hz SWaT rate
MAX_GAP_S = 5.0                # a longer hole in telemetry restarts the window (as chunks do in training)

Registers = Mapping[Union[int, str], float]


class PhysicalModel:
    """Isolation Forest + supervised head over SWaT-derived telemetry windows."""

    def __init__(self, window_size: int = WINDOW, random_state: int = 42, threshold_quantile: float = 0.995) -> None:
        self.window_size = window_size
        self.random_state = random_state
        self.threshold_quantile = threshold_quantile
        self._buf: Deque[Tuple[np.ndarray, np.ndarray]] = deque(maxlen=window_size)
        self._last_t: Optional[float] = None
        self._lock = threading.Lock()
        self._cache: Optional[Dict[str, Any]] = None
        self._cache_t: Optional[float] = None

        self._model = None
        self._packed: Optional[PackedIsolationForest] = None
        self._clf = None
        self._clf_packed: Optional[PackedForestRegressor] = None
        self.threshold: Optional[float] = None
        self.clf_threshold: Optional[float] = None
        self.bounds: Dict[str, Any] = {}
        self.norm: Optional[Norm] = None
        self.status = "NO_MODEL"
        self.metadata: Dict[str, Any] = {}

    # --------------------------------------------------------------- window
    @staticmethod
    def _value(registers: Registers, tag: str) -> Optional[float]:
        m = MACHINE_BY_NAME[tag]
        v = registers.get(m["register"], registers.get(tag))
        return None if v is None else float(v)

    def update(self, registers: Registers, timestamp: Optional[float] = None) -> None:
        """Push one telemetry sample (keys: register numbers or names). Decimated to 1 Hz."""
        t = float(timestamp) if timestamp is not None else time.time()
        s = [self._value(registers, tag) for tag in SENSORS]
        a = [self._value(registers, tag) for tag in ACTUATORS]
        if any(v is None for v in s + a):
            return
        with self._lock:
            if self._last_t is not None:
                if t - self._last_t < SAMPLE_PERIOD_S - 1e-6:
                    return
                if t - self._last_t > MAX_GAP_S:
                    self._buf.clear()
            self._buf.append((np.array(s, dtype=np.float64), (np.array(a) >= ON_THRESHOLD).astype(np.float64)))
            self._last_t = t

    @property
    def is_warm(self) -> bool:
        return len(self._buf) >= self.window_size

    def reset_window(self) -> None:
        with self._lock:
            self._buf.clear()
            self._last_t = None
            self._cache, self._cache_t = None, None

    # ------------------------------------------------------------------ fit
    def fit(self, X_normal: np.ndarray, bounds: Dict[str, Any]) -> "PhysicalModel":
        from sklearn.ensemble import IsolationForest
        if X_normal.ndim != 2 or X_normal.shape[1] != len(FEATURE_NAMES):
            raise ValueError(f"expected [n, {len(FEATURE_NAMES)}] features, got {X_normal.shape}")
        self.bounds, self.norm = bounds, Norm(bounds)
        self._model = IsolationForest(n_estimators=100, max_samples=256, contamination="auto",
                                      random_state=self.random_state).fit(X_normal)
        self._packed = PackedIsolationForest(self._model)
        self.threshold = float(np.quantile(self.anomaly_scores(X_normal), self.threshold_quantile))
        self.status = "OK"
        self.metadata.update({"feature_names": list(FEATURE_NAMES), "window": self.window_size,
                              "trained_normal_windows": int(X_normal.shape[0]), "if_threshold_quantile": self.threshold_quantile})
        return self

    def fit_classifier(self, X: np.ndarray, y: np.ndarray, sample_weight: Optional[np.ndarray] = None,
                       n_estimators: int = 150, max_depth: int = 8, min_samples_leaf: int = 20) -> "PhysicalModel":
        """Regression forest on the 0/1 label: leaf mean = attack fraction = probability estimate."""
        from sklearn.ensemble import RandomForestRegressor
        self._clf = RandomForestRegressor(n_estimators=n_estimators, max_depth=max_depth, min_samples_leaf=min_samples_leaf,
                                          max_features="sqrt", random_state=self.random_state, n_jobs=-1
                                          ).fit(X, y.astype(float), sample_weight=sample_weight)
        self._clf.n_jobs = 1
        self._clf_packed = PackedForestRegressor(self._clf)
        self.metadata.update({"trained_labelled_windows": int(X.shape[0]), "attack_windows_in_training": int(np.sum(y)),
                              "classifier_params": {"n_estimators": n_estimators, "max_depth": max_depth,
                                                    "min_samples_leaf": min_samples_leaf}})
        return self

    # -------------------------------------------------------------- predict
    def anomaly_scores(self, X: np.ndarray) -> np.ndarray:
        if self._packed is None:
            raise RuntimeError("PhysicalModel has no trained weights")
        return -self._packed.score_samples(np.atleast_2d(X))

    def attack_probability(self, X: np.ndarray) -> np.ndarray:
        if self._clf_packed is None:
            raise RuntimeError("PhysicalModel has no supervised head")
        return self._clf_packed.predict(np.atleast_2d(X))

    def predict(self, X: np.ndarray) -> np.ndarray:
        flag = self.anomaly_scores(X) > self.threshold
        if self._clf_packed is not None and self.clf_threshold is not None:
            flag = flag | (self.attack_probability(X) > self.clf_threshold)
        return flag.astype(int)

    def _bounds_violations(self, sensors: np.ndarray) -> List[Dict[str, Any]]:
        assert self.norm is not None
        out = []
        for i, tag in enumerate(SENSORS):
            if sensors[i] < self.norm.lo[i] or sensors[i] > self.norm.hi[i]:
                out.append({"tag": tag, "value": round(float(sensors[i]), 3),
                            "lo": round(float(self.norm.lo[i]), 3), "hi": round(float(self.norm.hi[i]), 3)})
        return out

    def assess(self) -> Dict[str, Any]:
        """Score the current window. Always returns a dict and never raises."""
        t0 = time.perf_counter()
        report: Dict[str, Any] = {"model": "PhysicalModel", "status": self.status, "plant_state": self.status,
                                  "anomaly_score": None, "threshold": self.threshold, "attack_probability": None,
                                  "clf_threshold": self.clf_threshold, "threat_flag": False, "flagged_by": [],
                                  "bounds_violations": [], "window_fill": len(self._buf), "window_size": self.window_size}
        try:
            if self._packed is None or self.norm is None:
                return report
            if not self.is_warm:
                report.update(status="WARMING_UP", plant_state="WARMING_UP")
                return report
            with self._lock:
                if self._cache is not None and self._cache_t == self._last_t:
                    return dict(self._cache)
                S = np.stack([b[0] for b in self._buf])[None]
                A = np.stack([b[1] for b in self._buf])[None]
                last_t = self._last_t
            X = window_features(S, A, self.norm)
            score = float(self.anomaly_scores(X)[0])
            report["anomaly_score"] = round(score, 4)
            if score > self.threshold:
                report["flagged_by"].append("isolation_forest")
            if self._clf_packed is not None and self.clf_threshold is not None:
                p = float(self.attack_probability(X)[0])
                report["attack_probability"] = round(p, 4)
                if p > self.clf_threshold:
                    report["flagged_by"].append("classifier")
            report["bounds_violations"] = self._bounds_violations(S[0, -1])
            report["threat_flag"] = bool(report["flagged_by"])
            report["status"] = "OK"
            report["plant_state"] = "ALERT" if (report["threat_flag"] or report["bounds_violations"]) else "NORMAL"
            report["latency_ms"] = round((time.perf_counter() - t0) * 1000.0, 4)
            self._cache, self._cache_t = dict(report), last_t
        except Exception:
            log.exception("PhysicalModel inference failed - abstaining (rules still enforce)")
            report.update(status="ERROR", plant_state="ERROR", anomaly_score=None, threat_flag=False, flagged_by=[])
        report.setdefault("latency_ms", round((time.perf_counter() - t0) * 1000.0, 4))
        return report

    # ----------------------------------------------------------- persistence
    def save(self, path: str = DEFAULT_WEIGHTS) -> None:
        import joblib
        if self._model is None:
            raise RuntimeError("nothing to save - model not trained")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump({"model": self._model, "clf": self._clf, "threshold": self.threshold, "clf_threshold": self.clf_threshold,
                     "bounds": self.bounds, "metadata": self.metadata}, path)

    @classmethod
    def load(cls, path: str = DEFAULT_WEIGHTS) -> "PhysicalModel":
        """Loads weights; on any failure (or a stale feature schema, e.g. the old RUL model) returns an abstaining model."""
        inst = cls()
        if not os.path.exists(path):
            log.warning("PhysicalModel weights not found at %s - rules-only (NO_MODEL)", path)
            return inst
        try:
            import joblib
            blob = joblib.load(path)
            meta = dict(blob.get("metadata", {})) if isinstance(blob, dict) else {}
            if not isinstance(blob, dict) or "bounds" not in blob or meta.get("feature_names") != list(FEATURE_NAMES):
                log.warning("PhysicalModel weights at %s are not the SWaT window schema (old synthetic RUL model?) - "
                            "ignoring them; retrain with models.train_physical_swat (NO_MODEL)", path)
                return inst
            inst._model = blob["model"]
            inst._packed = PackedIsolationForest(inst._model)
            inst.threshold = float(blob["threshold"])
            if blob.get("clf") is not None:
                inst._clf = blob["clf"]
                inst._clf_packed = PackedForestRegressor(inst._clf)
                inst.clf_threshold = float(blob["clf_threshold"])
            inst.bounds, inst.norm = blob["bounds"], Norm(blob["bounds"])
            inst.window_size = int(meta.get("window", WINDOW))
            inst._buf = deque(maxlen=inst.window_size)
            inst.metadata = meta
            inst.status = "OK"
        except Exception:
            log.exception("PhysicalModel weights at %s unreadable - rules-only (NO_MODEL)", path)
            inst = cls()
        return inst
