"""
models/physical_model_v2.py - PhysicalModelV2: the promoted SWaT-trained physical model (advisory).

Same job and API as models/physical_model.PhysicalModel (the v1 model stays in the repo and is selectable), but a different
detector, found by the v2 experiment (docs/reports/physical_training_report_v2_swat.md):
  * a 120 s history (1 Hz) instead of 30 s: the last 30 s give the 87 v1 features (the 67 drift-robust ones are used),
    the full 120 s give long-context features (slope / std / net change per sensor, toggles per actuator);
  * cross-sensor consistency residuals (ridge regressions fitted on NORMAL windows only, swat/features_v2.ResidualModel);
  * ONE supervised head, a gradient-boosted classifier (HistGradientBoosting), trained on SWaT train + validation windows.
    There is no Isolation Forest any more (anomaly_score is None); the flag is  attack_probability > threshold  with NO persistence
    (persistence was measured and made F1 worse).
The feature code is the SAME code the trainer calls (swat/physical_features.window_features, swat/features_v2), so live == training.

Warm-up: 120 s of telemetry (the v1 model needed 30 s). Until then, and on any failure or missing weights, the model ABSTAINS
(WARMING_UP / ERROR / NO_MODEL, threat_flag False) and never raises into the middleware. Advisory: the orchestrator only turns a flag
into an ALERT; the rules decide DROP.
"""

from __future__ import annotations

import logging
import os
import time
from collections import deque
from typing import Any, Dict, Optional

import numpy as np

from models.physical_model import PhysicalModel
from models.tree_inference import PackedHistGB
from swat.features_v2 import LONG, assemble, feature_names, long_features
from swat.physical_features import SENSORS, WINDOW, Norm, window_features

log = logging.getLogger("industrialmind.models.physical_v2")

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_WEIGHTS = os.path.join(HERE, "weights", "physical_model_v2.joblib")
SCHEMA = "physical_v2/1"


def norm_from_stats(stats: Dict[str, Any]) -> Norm:
    n = Norm.__new__(Norm)
    n.mu, n.sd, n.lo, n.hi = (np.asarray(stats[k], dtype=np.float64) for k in ("mu", "sd", "lo", "hi"))
    return n


def apply_threshold_override(default: float, meta: Dict[str, Any], name: str) -> "tuple[float, Dict[str, Any]]":
    """Optional runtime operating-point override. The weights ship at their packaged false-alarm budget. A demo may prefer higher recall
    (lower threshold: more alerts) or quieter operation (higher). Set IM_PHYSICAL_THRESHOLD to a probability in [0, 1] to override WITHOUT
    retraining. The model stays advisory either way (it raises ALERT, never DROP). Invalid values are ignored. Returns (threshold, metadata)."""
    override = os.environ.get("IM_PHYSICAL_THRESHOLD", "").strip()
    if not override:
        return default, meta
    try:
        v = float(override)
    except ValueError:
        log.warning("IM_PHYSICAL_THRESHOLD=%s is not a number - ignored", override)
        return default, meta
    if not 0.0 <= v <= 1.0:
        log.warning("IM_PHYSICAL_THRESHOLD=%s out of [0,1] - ignored", override)
        return default, meta
    log.info("%s operating point overridden to %.4f via IM_PHYSICAL_THRESHOLD (shipped %.4f)", name, v, default)
    return v, {**meta, "operating_point_override": v, "shipped_threshold": float(default)}


class PhysicalModelV2(PhysicalModel):
    """120 s window, long-context + residual features, gradient-boosted attack probability."""

    def __init__(self) -> None:
        super().__init__(window_size=LONG)
        self._scorer = None
        self._packed_gb = None
        self._resid = None
        self.feature_set = "v1_long_resid"
        self.threshold = None                       # no anomaly head
        self.variant = "v2"

    def _probability(self, S: np.ndarray, A: np.ndarray) -> float:
        """S [1, LONG, 10] raw sensors, A [1, LONG, 8] actuator 0/1 -> attack probability (shared feature code)."""
        X87 = window_features(S[:, -WINDOW:], A[:, -WINDOW:], self.norm)
        XL = long_features(S, A, self.norm)
        X = assemble(self.feature_set, X87, XL, self._resid)
        if self._packed_gb is not None:
            return float(self._packed_gb.predict_proba1(X)[0])
        return float(self._scorer.predict_proba(X)[0, 1])

    def assess(self) -> Dict[str, Any]:
        t0 = time.perf_counter()
        report: Dict[str, Any] = {"model": "PhysicalModelV2", "status": self.status, "plant_state": self.status,
                                  "anomaly_score": None, "threshold": None, "attack_probability": None,
                                  "clf_threshold": self.clf_threshold, "threat_flag": False, "flagged_by": [],
                                  "bounds_violations": [], "window_fill": len(self._buf), "window_size": self.window_size}
        try:
            if self._scorer is None or self.norm is None:
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
            p = self._probability(S, A)
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
            log.exception("PhysicalModelV2 inference failed - abstaining (rules still enforce)")
            report.update(status="ERROR", plant_state="ERROR", attack_probability=None, threat_flag=False, flagged_by=[])
        report.setdefault("latency_ms", round((time.perf_counter() - t0) * 1000.0, 4))
        return report

    # v1 training API does not apply
    def fit(self, *a, **k):
        raise NotImplementedError("train with models.train_physical_v2 (candidate), then models.package_physical_v2")

    def predict(self, X: np.ndarray) -> np.ndarray:                 # X = assembled feature matrix
        return (self._scorer.predict_proba(X)[:, 1] > self.clf_threshold).astype(int)

    # ----------------------------------------------------------- persistence
    @classmethod
    def load(cls, path: str = DEFAULT_WEIGHTS) -> "PhysicalModelV2":
        inst = cls()
        if not os.path.exists(path):
            log.warning("PhysicalModelV2 weights not found at %s - rules-only (NO_MODEL)", path)
            return inst
        try:
            import joblib
            blob = joblib.load(path)
            if not isinstance(blob, dict) or blob.get("schema") != SCHEMA:
                log.warning("weights at %s are not the %s schema - ignoring (NO_MODEL)", path, SCHEMA)
                return inst
            meta = dict(blob.get("metadata", {}))
            if meta.get("feature_names") != feature_names(blob["feature_set"]):
                log.warning("weights at %s: feature schema mismatch - ignoring (NO_MODEL)", path)
                return inst
            inst._scorer, inst._resid, inst.feature_set = blob["scorer"], blob.get("residual"), blob["feature_set"]
            try:
                inst._packed_gb = PackedHistGB(inst._scorer)
            except ValueError:
                log.warning("packed inference unsupported for this scorer - using sklearn predict_proba")
            inst.norm = norm_from_stats(blob["norm_stats"])
            inst.clf_threshold = float(blob["clf_threshold"])
            inst.clf_threshold, meta = apply_threshold_override(inst.clf_threshold, meta, "PhysicalModelV2")
            inst.window_size = int(meta.get("window", LONG))
            inst._buf = deque(maxlen=inst.window_size)
            inst.metadata, inst.status = meta, "OK"
        except Exception:
            log.exception("PhysicalModelV2 weights at %s unreadable - rules-only (NO_MODEL)", path)
            inst = cls()
        return inst


def load_physical_model(version: Optional[str] = None) -> PhysicalModel:
    """The live physical model. IM_PHYSICAL_MODEL=v2 (default) | v1. v2 falling back to v1 if its weights are unusable."""
    version = (version or os.environ.get("IM_PHYSICAL_MODEL", "v2")).lower()
    if version == "v1":
        return PhysicalModel.load()
    if version == "v3":                                   # opt-in only: v2 stays the default until v3 is promoted
        from models.physical_model_v3 import PhysicalModelV3
        m3 = PhysicalModelV3.load()
        if m3.status == "OK":
            return m3
        log.warning("PhysicalModelV3 unavailable - falling back to v2")
    m = PhysicalModelV2.load()
    if m.status != "OK":
        log.warning("PhysicalModelV2 unavailable - falling back to the v1 model")
        return PhysicalModel.load()
    return m


def live_weights_path() -> str:
    """Weights file the live loader would use (v2 unless IM_PHYSICAL_MODEL=v1 or the v2 file is missing)."""
    from models.physical_model import DEFAULT_WEIGHTS as V1
    if os.environ.get("IM_PHYSICAL_MODEL", "v2").lower() == "v3":
        from models.physical_model_v3 import DEFAULT_WEIGHTS as V3
        if os.path.exists(V3):
            return V3
    if os.environ.get("IM_PHYSICAL_MODEL", "v2").lower() != "v1" and os.path.exists(DEFAULT_WEIGHTS):
        return DEFAULT_WEIGHTS
    return V1
