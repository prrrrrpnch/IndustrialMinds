"""
research/physical_model_v3.py - PhysicalModelV3: the v3 physical model (advisory), same API and safety behaviour as PhysicalModelV2.

Opt-in: IM_PHYSICAL_MODEL=v3 (v2 stays the default until v3 has been reviewed on real data and promoted; see research/package_physical_v3.py).

What it computes from the live 120 s, 1 Hz window (all of it through research/features_v3.py, the SAME code the trainer uses):
  multi-scale dynamics -> NORMAL-ONLY consistency + PCA monitor features -> per-stage heads and global head(s) (gradient-boosted trees,
  evaluated by the packed NumPy engine) -> a small logistic stacker -> attack probability. threat_flag = probability > the packaged threshold.

Extra, for explanation, in every assessment:
  head_scores   the probability each head gave (a per-stage head that is high says which stage looks attacked)
  stage_spe     the PCA process monitor's normalised squared prediction error per stage (S1..S5; ~1 is normal, large is abnormal)
  suspect_stage the stage with the largest stage_spe, only when the model flags

The model abstains (NO_MODEL / WARMING_UP / ERROR, threat_flag False) on missing or mismatching weights, an unfilled window, or any failure,
and never raises into the middleware. It never blocks: a flag becomes an ALERT, the rules decide DROP.
"""

from __future__ import annotations

import logging
import os
import time
from collections import deque
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from models.physical_model_v2 import PhysicalModelV2, apply_threshold_override, norm_from_stats
from models.tree_inference import PackedHistGB
from research import features_v3 as F3

log = logging.getLogger("industrialmind.models.physical_v3")

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_WEIGHTS = os.path.join(HERE, "weights", "physical_model_v3.joblib")


class _SklearnHead:
    """Fallback when a head cannot be packed: same predict_proba1 interface through scikit-learn."""

    def __init__(self, model: Any) -> None:
        self.model = model

    def predict_proba1(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict_proba(np.atleast_2d(X))[:, 1]


class PhysicalModelV3(PhysicalModelV2):
    """120 s window; per-stage and global gradient-boosted heads over multi-scale + normal-model features, stacked."""

    def __init__(self) -> None:
        super().__init__()
        self._heads: Dict[str, Any] = {}                 # name -> packed (or sklearn) head, single-row path
        self._sk_heads: Dict[str, Any] = {}              # name -> the sklearn model, batch path
        self._head_meta: Dict[str, Dict[str, Any]] = {}
        self._nms: Dict[str, F3.NormalModels] = {}
        self._stack: Optional[Dict[str, Any]] = None
        self.recipe: Optional[str] = None
        self.feature_set = F3.FEATURE_VERSION
        self.variant = "v3"

    # ------------------------------------------------------------------ scoring
    def score_batch(self, Xb: np.ndarray, aux: np.ndarray, packed: bool = False
                    ) -> Tuple[np.ndarray, Dict[str, np.ndarray], Dict[str, np.ndarray]]:
        """Attack probability for n windows from their base features and AUX (shared with the benchmark). packed=True uses the packed
        single-row engine (the live path); False uses scikit-learn, which is faster for large batches.
        Returns (p [n], per-head scores, normal-model features by variant)."""
        nm = {v: m.transform(aux) for v, m in self._nms.items()}
        feats = {v: F3.assemble(Xb, f) for v, f in nm.items()}
        scores: Dict[str, np.ndarray] = {}
        for h, meta in self._head_meta.items():
            X = feats[meta["variant"]][:, meta["cols"]]
            if packed:
                scores[h] = np.concatenate([self._heads[h].predict_proba1(X[i:i + 1]) for i in range(len(X))])
            else:
                scores[h] = self._sk_heads[h].predict_proba(X)[:, 1]
        if self._stack is None:
            p = scores[next(iter(scores))]
        else:
            arr = np.stack([scores[h] for h in self._stack["heads"]], axis=1)
            p = F3.stack_predict(F3.stack_inputs(arr), self._stack["w"], self._stack["b"])
        return p, scores, nm

    def _score_window(self, S: np.ndarray, A: np.ndarray) -> Tuple[float, Dict[str, float], Dict[str, float]]:
        Xb, aux = F3.base_features(S, A, self.norm)
        p, scores, nm = self.score_batch(Xb, aux, packed=True)
        any_nm = nm.get("nl", next(iter(nm.values())))
        return float(p[0]), {h: float(v[0]) for h, v in scores.items()}, F3.stage_summary(any_nm)

    # ------------------------------------------------------------------ assessment
    def assess(self) -> Dict[str, Any]:
        t0 = time.perf_counter()
        report: Dict[str, Any] = {"model": "PhysicalModelV3", "status": self.status, "plant_state": self.status,
                                  "anomaly_score": None, "threshold": None, "attack_probability": None,
                                  "clf_threshold": self.clf_threshold, "threat_flag": False, "flagged_by": [],
                                  "head_scores": None, "stage_spe": None, "suspect_stage": None,
                                  "bounds_violations": [], "window_fill": len(self._buf), "window_size": self.window_size}
        try:
            if not self._heads or self.norm is None:
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
            p, heads, spe = self._score_window(S, A)
            report["attack_probability"] = round(p, 4)
            report["head_scores"] = {h: round(v, 4) for h, v in heads.items()}
            report["stage_spe"] = {k: round(v, 3) for k, v in spe.items()}
            if p > self.clf_threshold:
                report["flagged_by"].append("stack" if self._stack is not None else "classifier")
                report["suspect_stage"] = max(spe, key=spe.get)
            report["bounds_violations"] = self._bounds_violations(S[0, -1])
            report["threat_flag"] = bool(report["flagged_by"])
            report["status"] = "OK"
            report["plant_state"] = "ALERT" if (report["threat_flag"] or report["bounds_violations"]) else "NORMAL"
            report["latency_ms"] = round((time.perf_counter() - t0) * 1000.0, 4)
            self._cache, self._cache_t = dict(report), last_t
        except Exception:
            log.exception("PhysicalModelV3 inference failed - abstaining (rules still enforce)")
            report.update(status="ERROR", plant_state="ERROR", attack_probability=None, threat_flag=False, flagged_by=[],
                          head_scores=None, stage_spe=None, suspect_stage=None)
        report.setdefault("latency_ms", round((time.perf_counter() - t0) * 1000.0, 4))
        return report

    def fit(self, *a, **k):
        raise NotImplementedError("train with research.train_physical_v3 (candidate), then research.package_physical_v3")

    def predict(self, X: np.ndarray) -> np.ndarray:
        raise NotImplementedError("use assess() / score_batch()")

    # ------------------------------------------------------------------ persistence
    @classmethod
    def load(cls, path: Optional[str] = None) -> "PhysicalModelV3":
        path = path or DEFAULT_WEIGHTS                  # resolved at call time (testable)
        inst = cls()
        if not os.path.exists(path):
            log.warning("PhysicalModelV3 weights not found at %s - rules-only (NO_MODEL)", path)
            return inst
        try:
            import joblib
            blob = joblib.load(path)
            if not isinstance(blob, dict) or blob.get("schema") != F3.FEATURE_VERSION:
                log.warning("weights at %s are not the %s schema - ignoring (NO_MODEL)", path, F3.FEATURE_VERSION)
                return inst
            if list(blob.get("feature_names", [])) != F3.FEATURE_NAMES:
                log.warning("weights at %s: feature schema mismatch - ignoring (NO_MODEL)", path)
                return inst
            meta = dict(blob.get("metadata", {}))
            inst.norm = norm_from_stats(blob["norm_stats"])
            inst._nms = dict(blob["normal_models"])
            inst._head_meta = {h: {"variant": m["variant"], "cols": np.asarray(m["cols"])} for h, m in blob["head_meta"].items()}
            for h, model in blob["heads"].items():
                inst._sk_heads[h] = model
                try:
                    inst._heads[h] = PackedHistGB(model)
                except ValueError:
                    log.warning("head %s cannot be packed - using scikit-learn predict_proba", h)
                    inst._heads[h] = _SklearnHead(model)
            inst._stack = blob.get("stacker")
            inst.recipe = blob.get("recipe")
            inst.clf_threshold, meta = apply_threshold_override(float(blob["clf_threshold"]), meta, "PhysicalModelV3")
            inst.window_size = int(meta.get("window", F3.LONG))
            inst._buf = deque(maxlen=inst.window_size)
            inst.metadata, inst.status = meta, "OK"
        except Exception:
            log.exception("PhysicalModelV3 weights at %s unreadable - rules-only (NO_MODEL)", path)
            inst = cls()
        return inst
