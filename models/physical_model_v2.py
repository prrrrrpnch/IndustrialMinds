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

from models import explain, operating_points
from models.physical_model import PhysicalModel
from models.tree_inference import PackedHistGB
from swat.features_v2 import LONG, assemble, feature_names, long_features
from swat.physical_features import ACTUATORS, SENSORS, WINDOW, Norm, window_features

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
    return v, {**meta, "operating_point_override": v, "shipped_threshold": float(meta.get("shipped_threshold", default))}


class PhysicalModelV2(PhysicalModel):
    """120 s window, long-context + residual features, gradient-boosted attack probability."""

    def __init__(self) -> None:
        super().__init__(window_size=LONG)
        self._scorer = None
        self._packed_gb = None
        self._resid = None
        self._feature_names: list = []
        self._groups: Dict[str, Any] = {}
        self._ref = None                            # features of the last window the model itself called normal
        self._ref_t: Optional[float] = None
        self.feature_set = "v1_long_resid"
        self.threshold = None                       # no anomaly head
        self.variant = "v2"

    def _features(self, S: np.ndarray, A: np.ndarray) -> np.ndarray:
        """S [n, LONG, 10] raw sensors, A [n, LONG, 8] actuator 0/1 -> the assembled feature matrix (shared feature code)."""
        X87 = window_features(S[:, -WINDOW:], A[:, -WINDOW:], self.norm)
        XL = long_features(S, A, self.norm)
        return assemble(self.feature_set, X87, XL, self._resid)

    def _score(self, X: np.ndarray) -> np.ndarray:
        """Assembled features [n, F] -> attack probability [n]."""
        if self._packed_gb is not None:
            return self._packed_gb.predict_proba1(X)
        return self._scorer.predict_proba(X)[:, 1]

    def _score_windows(self, S: np.ndarray, A: np.ndarray) -> np.ndarray:
        """Raw windows [n, LONG, ch] -> attack probability [n], recomputing every feature (the plant-wide ones included)."""
        return self._score(self._features(S, A))

    def _probability(self, S: np.ndarray, A: np.ndarray) -> float:
        return float(self._score_windows(S, A)[0])

    def _explain(self, report: Dict[str, Any], S: np.ndarray, A: np.ndarray, last_t: Optional[float]) -> None:
        """Fill in WHY. A window the model called normal becomes the reference the next flag is explained against, so the
        explanation is contrastive ('what changed since the plant last looked fine') and needs no training data at run time."""
        if not report["threat_flag"]:
            if not report["bounds_violations"]:
                self._ref, self._ref_t = (S.copy(), A.copy()), last_t
            return
        if self._ref is None or not self._groups:
            report["explanation"] = "no normal reference yet - " + explain.sentence(None, None, report["top_deviations"])
            return
        contrib = explain.contributions(self._score_windows, S, A, self._ref[0], self._ref[1], self._groups)
        stage = explain.suspect_stage(contrib)
        report["stage_contributions"] = contrib
        report["suspect_stage"] = stage
        report["reference_age_s"] = None if (self._ref_t is None or last_t is None) else round(last_t - self._ref_t, 1)
        report["explanation"] = explain.sentence(stage, contrib, report["top_deviations"])

    def assess(self) -> Dict[str, Any]:
        t0 = time.perf_counter()
        report: Dict[str, Any] = {"model": "PhysicalModelV2", "status": self.status, "plant_state": self.status,
                                  "anomaly_score": None, "threshold": None, "attack_probability": None,
                                  "clf_threshold": self.clf_threshold, "threat_flag": False, "flagged_by": [],
                                  "bounds_violations": [], "window_fill": len(self._buf), "window_size": self.window_size,
                                  "warmup_remaining_s": max(0, self.window_size - len(self._buf)),
                                  "confidence": None, "top_deviations": [], "stage_contributions": None,
                                  "suspect_stage": None, "reference_age_s": None, "explanation": None}
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
            X = self._features(S, A)
            p = float(self._score(X)[0])
            report["attack_probability"] = round(p, 4)
            if p > self.clf_threshold:
                report["flagged_by"].append("classifier")
            report["bounds_violations"] = self._bounds_violations(S[0, -1])
            report["threat_flag"] = bool(report["flagged_by"])
            report["status"] = "OK"
            report["plant_state"] = "ALERT" if (report["threat_flag"] or report["bounds_violations"]) else "NORMAL"
            report["confidence"] = explain.confidence(p, self.clf_threshold)
            report["top_deviations"] = explain.deviations(S[0, -1], SENSORS, self.norm)
            self._explain(report, S, A, last_t)
            report["latency_ms"] = round((time.perf_counter() - t0) * 1000.0, 4)
            self._cache, self._cache_t = dict(report), last_t
        except Exception:
            log.exception("PhysicalModelV2 inference failed - abstaining (rules still enforce)")
            report.update(status="ERROR", plant_state="ERROR", attack_probability=None, threat_flag=False, flagged_by=[],
                          confidence=None, top_deviations=[], stage_contributions=None, suspect_stage=None, explanation=None)
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
            inst.clf_threshold, meta = operating_points.apply_preset(inst.clf_threshold, meta, "PhysicalModelV2")
            inst.clf_threshold, meta = apply_threshold_override(inst.clf_threshold, meta, "PhysicalModelV2")
            inst._feature_names = feature_names(inst.feature_set)
            inst._groups = explain.channel_groups(SENSORS, ACTUATORS)
            inst.window_size = int(meta.get("window", LONG))
            inst._buf = deque(maxlen=inst.window_size)
            inst.metadata, inst.status = meta, "OK"
        except Exception:
            log.exception("PhysicalModelV2 weights at %s unreadable - rules-only (NO_MODEL)", path)
            inst = cls()
        return inst


def model_card(model: Optional[PhysicalModel] = None) -> Dict[str, Any]:
    """What the live physical model is, how well it was measured to work, and what it cannot do. Short enough to show in a UI;
    the long form is docs/MODEL_CARD.md. Every number comes from the weights' own metadata, never from this file."""
    m = model if model is not None else load_physical_model()
    meta = dict(getattr(m, "metadata", {}) or {})
    meta.pop("feature_names", None)
    shipped = meta.get("shipped_threshold", getattr(m, "clf_threshold", None))
    return {
        "model": type(m).__name__,
        "variant": getattr(m, "variant", None),
        "status": getattr(m, "status", "NO_MODEL"),
        "role": "advisory: a flag becomes ALERT and the command is still forwarded; it can never DROP",
        "trained_on": meta.get("trained_on"),
        "window_seconds": meta.get("window"),
        "features": len(getattr(m, "_feature_names", []) or []) or None,
        "threshold": getattr(m, "clf_threshold", None),
        "shipped_threshold": shipped,
        "operating_point": meta.get("operating_point") or {"false_alarm_budget_per_hour": meta.get("false_alarm_budget_per_hour")},
        "held_out_result": meta.get("test_block_result_at_0.5_budget") or meta.get("held_out_test_block"),
        "available_operating_points": operating_points.presets(float(meta.get("false_alarm_budget_per_hour", 0.5))),
        "known_limits": [
            "about half of real attack windows are caught: it is a second opinion, not a gate",
            "roughly one false alarm per hour of normal operation at the shipped operating point",
            "the held-out block was seen by earlier experiments, so it is held out, not a blind test",
            "only 10 attack segments in that block, so the confidence intervals are wide",
            "trained on SWaT; the digital twin is a calibrated approximation of it, not the same plant",
            "it cannot see an attacker who bypasses the middleware and writes to the PLC directly",
        ],
        "report": meta.get("report"),
    }


def load_physical_model(version: Optional[str] = None) -> PhysicalModel:
    """The live physical model. IM_PHYSICAL_MODEL=v2 (default) | v1. v2 falling back to v1 if its weights are unusable."""
    version = (version or os.environ.get("IM_PHYSICAL_MODEL", "v2")).lower()
    if version == "v1":
        return PhysicalModel.load()
    if version == "v3":                                   # opt-in only: v2 stays the default until v3 is promoted
        from research.physical_model_v3 import PhysicalModelV3
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
        from research.physical_model_v3 import DEFAULT_WEIGHTS as V3
        if os.path.exists(V3):
            return V3
    if os.environ.get("IM_PHYSICAL_MODEL", "v2").lower() != "v1" and os.path.exists(DEFAULT_WEIGHTS):
        return DEFAULT_WEIGHTS
    return V1
