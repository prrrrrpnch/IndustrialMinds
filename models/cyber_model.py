"""
models/cyber_model.py - CyberModel: unsupervised anomaly detection on Modbus command traffic.

Runs ALONGSIDE the deterministic Cyber Agent (middleware/cyber_agent.py). The
agent's HMAC / whitelist / rate / replay checks remain the hard gate; this
model adds an anomaly score that catches traffic that is individually legal
but statistically unlike normal operator behaviour (odd timing, unusual
jumps, bursts below the hard rate limit, etc.).

Algorithm: Isolation Forest trained on legitimate operator traffic only, so
it needs no labelled attack data. Inference uses the packed-tree path in
models/tree_inference.py (identical scores to sklearn, ~0.1 ms).

Safe fallback: if the weights file is missing or corrupt, or inference
raises, the model ABSTAINS (status NO_MODEL / ERROR, threat_flag False) and
logs the problem. It never raises into the middleware, and the deterministic
agents continue to gate every command.
"""

from __future__ import annotations

import logging
import math
import os
import time
from collections import defaultdict, deque
from typing import Any, Deque, Dict, Iterable, List, Optional, Sequence, Tuple, Union

import numpy as np

from docs.interfaces import MACHINE_BY_REGISTER
from docs import hmac_auth
from models.tree_inference import PackedIsolationForest

log = logging.getLogger("industrialmind.models.cyber")

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_WEIGHTS = os.path.join(HERE, "weights", "cyber_model.joblib")

FEATURE_NAMES: List[str] = [
    "fc_write_single",        # FC6
    "fc_write_multiple",      # FC16
    "fc_other",
    "register_known",
    "value_norm",             # value within machine range, 0..1
    "out_of_range",           # distance outside range / span
    "delta_norm",             # |requested - current| / span
    "signature_present",
    "signature_age",          # |now - signed ts| / freshness window, clipped
    "log_inter_arrival_ms",   # since previous command from the same source
    "requests_last_1s",       # same source
    "requests_last_10s",      # same source
    "same_payload_recent",    # identical (register, value) from source within 2 s
]

CommandLike = Dict[str, Any]
StateLike = Dict[str, Any]


class CyberFeatureExtractor:
    """Turns a command (+ per-source history) into a fixed-length feature vector."""

    def __init__(self) -> None:
        self._times: Dict[str, Deque[float]] = defaultdict(deque)
        self._payloads: Dict[str, Deque[Tuple[Tuple[Any, Any], float]]] = defaultdict(deque)
        self._last: Dict[str, float] = {}
        self._last_sweep = 0.0

    def reset(self) -> None:
        self._times.clear()
        self._payloads.clear()
        self._last.clear()
        self._last_sweep = 0.0

    def _sweep(self, now: float, idle_s: float = 60.0) -> None:
        """Forget sources idle for > idle_s so many distinct IPs can't grow memory."""
        if now - self._last_sweep < 10.0:
            return
        self._last_sweep = now
        for src in [s for s, t in self._last.items() if now - t > idle_s]:
            self._last.pop(src, None)
            self._times.pop(src, None)
            self._payloads.pop(src, None)

    def tracked_sources(self) -> int:
        return len(self._last)

    def transform(self, command: CommandLike, current_state: Optional[StateLike] = None,
                  update: bool = True) -> np.ndarray:
        now = float(command.get("timestamp") or time.time())
        src = str(command.get("source_ip", ""))
        if update:
            self._sweep(now)
        fc = command.get("function_code")
        reg = command.get("register")
        value = float(command.get("value") or 0.0)
        machine = MACHINE_BY_REGISTER.get(reg)

        if machine:
            lo, hi = float(machine["min"]), float(machine["max"])
            span = (hi - lo) or 1.0
            value_norm = float(np.clip((value - lo) / span, 0.0, 1.0))
            out_of_range = max(0.0, lo - value, value - hi) / span
            current = None
            if current_state:
                regs = current_state.get("registers", {})
                current = regs.get(reg, regs.get(machine["name"]))
            delta_norm = abs(value - float(current)) / span if current is not None else 0.0
        else:
            value_norm, out_of_range, delta_norm = 0.0, 1.0, 1.0

        auth = command.get("auth")
        sig_present = 1.0 if auth and not auth.get("malformed") else 0.0
        sig_age = 0.0
        if sig_present:
            window_ms = max(1, hmac_auth.MAX_CLOCK_SKEW_MS)
            sig_age = min(5.0, abs(now * 1000 - float(auth.get("timestamp_ms", now * 1000))) / window_ms)

        times = self._times[src]
        while times and now - times[0] > 10.0:
            times.popleft()
        last = self._last.get(src)
        inter_ms = (now - last) * 1000.0 if last is not None else 60_000.0
        req_1s = sum(1 for t in times if now - t <= 1.0)
        req_10s = len(times)

        payloads = self._payloads[src]
        while payloads and now - payloads[0][1] > 2.0:
            payloads.popleft()
        key = (reg, round(value, 1))
        same_recent = 1.0 if any(p == key for p, _ in payloads) else 0.0

        if update:
            times.append(now)
            payloads.append((key, now))
            self._last[src] = now

        return np.array([
            1.0 if fc == 6 else 0.0,
            1.0 if fc == 16 else 0.0,
            0.0 if fc in (6, 16) else 1.0,
            1.0 if machine else 0.0,
            value_norm,
            min(out_of_range, 10.0),
            min(delta_norm, 10.0),
            sig_present,
            sig_age,
            math.log1p(max(0.0, min(inter_ms, 600_000.0))),
            float(req_1s),
            float(req_10s),
            same_recent,
        ], dtype=np.float64)


class CyberModel:
    """Isolation Forest anomaly detector for SCADA -> PLC commands."""

    def __init__(self, n_estimators: int = 100, max_samples: Union[int, str] = 256,
                 random_state: int = 42, threshold_quantile: float = 0.995) -> None:
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.random_state = random_state
        self.threshold_quantile = threshold_quantile

        self.extractor = CyberFeatureExtractor()
        self._model = None                         # sklearn IsolationForest
        self._packed: Optional[PackedIsolationForest] = None
        self.threshold: Optional[float] = None     # anomaly score above which = threat
        self.status = "NO_MODEL"
        self.metadata: Dict[str, Any] = {}

    # ------------------------------------------------------------------ fit
    def fit(self, X: Union[np.ndarray, Iterable[Tuple[CommandLike, StateLike]]]) -> "CyberModel":
        """
        Train on NORMAL traffic only. Accepts a feature matrix [n, n_features]
        or an iterable of (command, current_state) pairs.
        """
        from sklearn.ensemble import IsolationForest

        if not isinstance(X, np.ndarray):
            extractor = CyberFeatureExtractor()
            X = np.vstack([extractor.transform(c, s) for c, s in X])

        if X.ndim != 2 or X.shape[1] != len(FEATURE_NAMES):
            raise ValueError(f"expected [n, {len(FEATURE_NAMES)}] features, got {X.shape}")

        self._model = IsolationForest(
            n_estimators=self.n_estimators, max_samples=self.max_samples,
            contamination="auto", random_state=self.random_state,
        ).fit(X)
        self._packed = PackedIsolationForest(self._model)
        train_scores = self.anomaly_scores(X)
        self.threshold = float(np.quantile(train_scores, self.threshold_quantile))
        self.status = "OK"
        self.metadata = {
            "trained_samples": int(X.shape[0]),
            "threshold_quantile": self.threshold_quantile,
            "threshold": self.threshold,
            "feature_names": FEATURE_NAMES,
        }
        return self

    # -------------------------------------------------------------- predict
    def anomaly_scores(self, X: np.ndarray) -> np.ndarray:
        """Isolation Forest anomaly score s in (0, 1]; higher = more anomalous."""
        if self._packed is None:
            raise RuntimeError("CyberModel has no trained weights")
        return -self._packed.score_samples(np.atleast_2d(X))

    def predict(self, X: np.ndarray) -> np.ndarray:
        """1 = threat (anomalous), 0 = normal, for each row of a feature matrix."""
        return (self.anomaly_scores(X) > self.threshold).astype(int)

    def evaluate_payload(self, command: CommandLike,
                         current_state: Optional[StateLike] = None) -> Dict[str, Any]:
        """
        Score one live command. Always returns a dict and never raises.
        Per-source history is updated even when the model is unavailable so
        features stay consistent once weights are loaded.
        """
        t0 = time.perf_counter()
        report: Dict[str, Any] = {
            "model": "CyberModel",
            "status": self.status,
            "anomaly_score": None,
            "threshold": self.threshold,
            "threat_flag": False,
        }
        try:
            features = self.extractor.transform(command, current_state)
            if self._packed is not None:
                score = float(self.anomaly_scores(features)[0])
                report["anomaly_score"] = round(score, 4)
                report["threat_flag"] = bool(score > self.threshold)
                report["status"] = "OK"
            report["features"] = {n: round(float(v), 4) for n, v in zip(FEATURE_NAMES, features)}
        except Exception:
            log.exception("CyberModel inference failed - abstaining (rules still enforce)")
            report.update(status="ERROR", anomaly_score=None, threat_flag=False)
        report["latency_ms"] = round((time.perf_counter() - t0) * 1000.0, 4)
        return report

    # ----------------------------------------------------------- persistence
    def save(self, path: str = DEFAULT_WEIGHTS) -> None:
        import joblib
        if self._model is None:
            raise RuntimeError("nothing to save - model not trained")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump({"model": self._model, "threshold": self.threshold,
                     "metadata": self.metadata}, path)

    @classmethod
    def load(cls, path: str = DEFAULT_WEIGHTS) -> "CyberModel":
        """Loads weights; on any failure returns an abstaining model (safe state)."""
        inst = cls()
        if not os.path.exists(path):
            log.warning("CyberModel weights not found at %s - running rules-only (NO_MODEL)", path)
            return inst
        try:
            import joblib
            blob = joblib.load(path)
            inst._model = blob["model"]
            inst._packed = PackedIsolationForest(inst._model)
            inst.threshold = float(blob["threshold"])
            inst.metadata = dict(blob.get("metadata", {}))
            inst.status = "OK"
        except Exception:
            log.exception("CyberModel weights at %s unreadable - running rules-only (NO_MODEL)", path)
            inst = cls()
        return inst


def feature_names() -> Sequence[str]:
    return list(FEATURE_NAMES)
