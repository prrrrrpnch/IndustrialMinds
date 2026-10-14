"""
models/cyber_model.py - CyberModel: learned (ML) detection on SCADA -> PLC command behaviour.

TWO LAYERS EXIST IN THE CYBER BRANCH, AND THEY ARE DIFFERENT THINGS:
  * RULES  (middleware/cyber_agent.py): whitelist, function code, register allow-list, rate limit,
           HMAC-SHA256, nonce/replay. Deterministic, the hard gate. They are NOT validated against
           SWaT (SWaT has no signatures, replay tags or source addresses).
  * MODEL  (this file): trained on SWaT ONLY. It scores actuator STATE-CHANGE commands with
           features derived from SWaT actuator timing (swat/cyber_events.py):
             - an Isolation Forest (unsupervised, normal events only) -> anomaly_score
             - a supervised forest (event label = inside a SWaT attack window) -> attack_probability
           threat_flag = either score above its threshold (thresholds chosen on the validation block).

The model ABSTAINS (status NOT_APPLICABLE) on commands with no SWaT counterpart (writes that do
not flip the quantised on/off state, sensors, unknown registers) and on any failure (NO_MODEL /
ERROR). It never raises into the middleware; the rules keep gating every command.

Both forests are evaluated with the packed-tree path in models/tree_inference.py (identical outputs
to sklearn, ~0.1 ms).
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

import numpy as np

from docs.interfaces import MACHINE_BY_REGISTER, ACTUATOR_REGISTERS
from models.tree_inference import PackedForestRegressor, PackedIsolationForest
from swat.cyber_events import FEATURE_NAMES, EventFeatureStream, state_class

log = logging.getLogger("industrialmind.models.cyber")

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_WEIGHTS = os.path.join(HERE, "weights", "cyber_model.joblib")

CommandLike = Dict[str, Any]
StateLike = Dict[str, Any]


class CyberFeatureExtractor:
    """Live command -> feature vector (same EventFeatureStream as training), or None if not applicable."""

    def __init__(self) -> None:
        self._stream = EventFeatureStream()

    def reset(self) -> None:
        self._stream.reset()

    def tracked_sources(self) -> int:       # kept for the stress test's bounded-state check
        return len(self._stream._same)

    def transform(self, command: CommandLike, current_state: Optional[StateLike] = None,
                  update: bool = True) -> Optional[np.ndarray]:
        reg = command.get("register")
        if reg not in ACTUATOR_REGISTERS or command.get("value") is None:
            return None
        machine = MACHINE_BY_REGISTER[reg]
        regs = (current_state or {}).get("registers", {})
        current = regs.get(reg, regs.get(machine["name"]))
        if current is None:
            return None
        new_cls, old_cls = state_class(command["value"]), state_class(current)
        if new_cls == old_cls:
            return None                      # no on/off flip: no SWaT counterpart
        now = float(command.get("timestamp") or time.time())
        return self._stream.push(now, int(reg), new_cls, update=update)


class CyberModel:
    """Isolation Forest + supervised attack-probability forest over SWaT-derived command features."""

    def __init__(self, n_estimators: int = 100, max_samples: Union[int, str] = 256,
                 random_state: int = 42, threshold_quantile: float = 0.995) -> None:
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.random_state = random_state
        self.threshold_quantile = threshold_quantile

        self.extractor = CyberFeatureExtractor()
        self._model = None                          # sklearn IsolationForest
        self._packed: Optional[PackedIsolationForest] = None
        self._clf = None                            # sklearn RandomForestRegressor on the 0/1 attack label
        self._clf_packed: Optional[PackedForestRegressor] = None
        self.threshold: Optional[float] = None      # Isolation Forest score above which = threat
        self.clf_threshold: Optional[float] = None  # attack probability above which = threat
        self.status = "NO_MODEL"
        self.metadata: Dict[str, Any] = {}

    # ------------------------------------------------------------------ fit
    def fit(self, X_normal: np.ndarray) -> "CyberModel":
        """Isolation Forest on NORMAL events only. X: [n, len(FEATURE_NAMES)]."""
        from sklearn.ensemble import IsolationForest
        if X_normal.ndim != 2 or X_normal.shape[1] != len(FEATURE_NAMES):
            raise ValueError(f"expected [n, {len(FEATURE_NAMES)}] features, got {X_normal.shape}")
        self._model = IsolationForest(n_estimators=self.n_estimators, max_samples=self.max_samples,
                                      contamination="auto", random_state=self.random_state).fit(X_normal)
        self._packed = PackedIsolationForest(self._model)
        self.threshold = float(np.quantile(self.anomaly_scores(X_normal), self.threshold_quantile))
        self.status = "OK"
        self.metadata.update({"feature_names": list(FEATURE_NAMES), "trained_normal_events": int(X_normal.shape[0]),
                              "if_threshold_quantile": self.threshold_quantile})
        return self

    def fit_classifier(self, X: np.ndarray, y: np.ndarray, sample_weight: Optional[np.ndarray] = None,
                       n_estimators: int = 150, max_depth: int = 10, min_samples_leaf: int = 3) -> "CyberModel":
        """
        Supervised head. A regression forest on the 0/1 label: each leaf mean is the attack
        fraction, i.e. a probability estimate, and it reuses the exact packed regressor.
        """
        from sklearn.ensemble import RandomForestRegressor
        self._clf = RandomForestRegressor(n_estimators=n_estimators, max_depth=max_depth,
                                          min_samples_leaf=min_samples_leaf, random_state=self.random_state,
                                          n_jobs=-1).fit(X, y.astype(float), sample_weight=sample_weight)
        self._clf.n_jobs = 1
        self._clf_packed = PackedForestRegressor(self._clf)
        self.metadata.update({"feature_names": list(FEATURE_NAMES), "trained_labelled_events": int(X.shape[0]),
                              "attack_events_in_training": int(np.sum(y))})
        return self

    # -------------------------------------------------------------- predict
    def anomaly_scores(self, X: np.ndarray) -> np.ndarray:
        """Isolation Forest score in (0, 1]; higher = more anomalous."""
        if self._packed is None:
            raise RuntimeError("CyberModel has no trained weights")
        return -self._packed.score_samples(np.atleast_2d(X))

    def attack_probability(self, X: np.ndarray) -> np.ndarray:
        if self._clf_packed is None:
            raise RuntimeError("CyberModel has no supervised head")
        return self._clf_packed.predict(np.atleast_2d(X))

    def predict(self, X: np.ndarray) -> np.ndarray:
        """1 = threat, 0 = normal: either score above its threshold."""
        flag = self.anomaly_scores(X) > self.threshold
        if self._clf_packed is not None and self.clf_threshold is not None:
            flag = flag | (self.attack_probability(X) > self.clf_threshold)
        return flag.astype(int)

    def evaluate_payload(self, command: CommandLike, current_state: Optional[StateLike] = None) -> Dict[str, Any]:
        """Score one live command. Always returns a dict and never raises."""
        t0 = time.perf_counter()
        report: Dict[str, Any] = {"model": "CyberModel", "status": self.status, "anomaly_score": None,
                                  "threshold": self.threshold, "attack_probability": None,
                                  "clf_threshold": self.clf_threshold, "threat_flag": False, "flagged_by": []}
        try:
            features = self.extractor.transform(command, current_state)
            if features is None:
                report["status"] = "NOT_APPLICABLE" if self.status == "OK" else self.status
                report["note"] = "no SWaT-style on/off state flip: model abstains, rules still gate"
            elif self._packed is not None:
                score = float(self.anomaly_scores(features)[0])
                report["anomaly_score"] = round(score, 4)
                if score > self.threshold:
                    report["flagged_by"].append("isolation_forest")
                if self._clf_packed is not None and self.clf_threshold is not None:
                    p = float(self.attack_probability(features)[0])
                    report["attack_probability"] = round(p, 4)
                    if p > self.clf_threshold:
                        report["flagged_by"].append("classifier")
                report["threat_flag"] = bool(report["flagged_by"])
                report["status"] = "OK"
            if features is not None:
                report["features"] = {n: round(float(v), 4) for n, v in zip(FEATURE_NAMES, features)}
        except Exception:
            log.exception("CyberModel inference failed - abstaining (rules still enforce)")
            report.update(status="ERROR", anomaly_score=None, threat_flag=False, flagged_by=[])
        report["latency_ms"] = round((time.perf_counter() - t0) * 1000.0, 4)
        return report

    # ----------------------------------------------------------- persistence
    def save(self, path: str = DEFAULT_WEIGHTS) -> None:
        import joblib
        if self._model is None:
            raise RuntimeError("nothing to save - model not trained")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump({"model": self._model, "clf": self._clf, "threshold": self.threshold,
                     "clf_threshold": self.clf_threshold, "metadata": self.metadata}, path)

    @classmethod
    def load(cls, path: str = DEFAULT_WEIGHTS) -> "CyberModel":
        """Loads weights; on any failure (or a stale feature schema) returns an abstaining model."""
        inst = cls()
        if not os.path.exists(path):
            log.warning("CyberModel weights not found at %s - running rules-only (NO_MODEL)", path)
            return inst
        try:
            import joblib
            blob = joblib.load(path)
            meta = dict(blob.get("metadata", {}))
            if meta.get("feature_names") != list(FEATURE_NAMES):
                log.warning("CyberModel weights at %s use a different feature schema (%s) - ignoring them; "
                            "retrain with models.train_cyber_swat (running rules-only, NO_MODEL)",
                            path, meta.get("feature_names"))
                return inst
            inst._model = blob["model"]
            inst._packed = PackedIsolationForest(inst._model)
            inst.threshold = float(blob["threshold"])
            if blob.get("clf") is not None:
                inst._clf = blob["clf"]
                inst._clf_packed = PackedForestRegressor(inst._clf)
                inst.clf_threshold = float(blob["clf_threshold"])
            inst.metadata = meta
            inst.status = "OK"
        except Exception:
            log.exception("CyberModel weights at %s unreadable - running rules-only (NO_MODEL)", path)
            inst = cls()
        return inst


def feature_names() -> Sequence[str]:
    return list(FEATURE_NAMES)
