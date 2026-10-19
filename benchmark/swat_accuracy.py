"""
benchmark/swat_accuracy.py - the PROMOTED physical model on the HELD-OUT SWaT test block (real data, aggregate output only).

    python -m benchmark.swat_accuracy --data-dir "C:\\IndustrialMind\\SWaT_dataset\\archive"
    python -m benchmark.swat_accuracy --fixture          # synthetic SWaT-SHAPED data: code path only, numbers meaningless

HELD-OUT = the calendar block "test" (1-2 Jan 2016) of the de-duplicated, chronological stream. The promoted model was trained on
the train block and its thresholds were set on the validation block. The test block is NOT pristine: it was also seen in the
physical training run 2 (revised protocol, see docs/reports/physical_training_report_swat_run2.md), so treat these numbers as the
model's held-out performance under that disclosed protocol, not as a fresh blind test.

What is evaluated is the live decision: the physical model's advisory flag (Isolation Forest score or classifier probability above
its threshold), which the orchestrator turns into ALERT when both rule layers pass. The cyber layer cannot be evaluated on SWaT
(no HMAC, no replay tags, no source addresses in the archive). Per-segment results are aggregates (counts, seconds): no raw rows.
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from typing import Any, Dict, List

import numpy as np
import pandas as pd

from benchmark.env import environment
from models.physical_model import PhysicalModel
from models.physical_model_v2 import load_physical_model
from swat.fusion_scenarios import physical_observations
from swat.loader import load_stream
from swat.physical_features import ACTUATORS, SENSORS, build_windows

STRIDE = 5
EPISODE_GAP_S = 30.0


def episodes(epochs: np.ndarray, flagged: np.ndarray, gap_s: float = EPISODE_GAP_S) -> int:
    t = np.sort(epochs[flagged])
    return 0 if t.size == 0 else int(1 + (np.diff(t) > gap_s).sum())


def derived(c: Dict[str, Any]) -> Dict[str, Any]:
    """Accuracy-type numbers computed from the four counts (pure arithmetic, so older records can be completed from their counts)."""
    n = c["tp"] + c["fp"] + c["fn"] + c["tn"]
    pos, neg = c["tp"] + c["fn"], c["fp"] + c["tn"]
    rec = c["tp"] / pos if pos else None
    spec = c["tn"] / neg if neg else None
    return {"accuracy": round((c["tp"] + c["tn"]) / n, 4) if n else None,
            "balanced_accuracy": round((rec + spec) / 2, 4) if rec is not None and spec is not None else None,
            "always_benign_baseline_accuracy": round(neg / n, 4) if n else None}


def add_derived(res: Dict[str, Any]) -> Dict[str, Any]:
    """Fill accuracy / balanced accuracy / baseline into every decision-rule block of a SWaT result (idempotent)."""
    for key in ("advisory_model_flag", "envelope_rule_alone (alert-only)", "model_flag_or_envelope"):
        if isinstance(res.get(key), dict) and "tp" in res[key]:
            res[key].update(derived(res[key]))
    ex = res.get("excluding_largest_segment")
    if ex and isinstance(ex.get("advisory_model_flag"), dict) and "tp" in ex["advisory_model_flag"]:
        ex["advisory_model_flag"].update(derived(ex["advisory_model_flag"]))
    return res


def confusion(y: np.ndarray, f: np.ndarray) -> Dict[str, Any]:
    tp, fp = int((y & f).sum()), int((~y & f).sum())
    fn, tn = int((y & ~f).sum()), int((~y & ~f).sum())
    prec = tp / (tp + fp) if tp + fp else None
    rec = tp / (tp + fn) if tp + fn else None
    f1 = 2 * prec * rec / (prec + rec) if prec and rec else (0.0 if prec is not None and rec is not None else None)
    r = lambda v: None if v is None else round(float(v), 4)
    out = {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": r(prec), "recall": r(rec), "f1": r(f1),
           "false_positive_rate": r(fp / (fp + tn) if fp + tn else None)}
    out.update(derived(out))
    return out


def _v1_observations(model: PhysicalModel, test: pd.DataFrame):
    X, meta = build_windows(test, model.norm, stride=STRIDE)
    if len(X) == 0:
        return None
    obs = physical_observations(model, X)
    model_flag = (obs["phys_if_score"].to_numpy() > model.threshold) | (obs["phys_p_attack"].to_numpy() > model.clf_threshold)
    return {"n": len(X), "meta": meta, "p": obs["phys_p_attack"].to_numpy(), "if_score": obs["phys_if_score"].to_numpy(),
            "model_flag": model_flag, "env_flag": obs["env_violations"].to_numpy() > 0, "rule_flag": obs["physical_pass"].to_numpy() == 0}


def _v2_observations(model, test: pd.DataFrame):
    """PhysicalModelV2 on the test block: the same feature code the live model calls, over windows with a full 120 s history."""
    from swat.features_v2 import assemble, long_features
    from swat.features_v2 import build_windows_v2
    X87, XL, meta = build_windows_v2(test, model.norm, stride=STRIDE)
    if len(X87) == 0:
        return None
    X = assemble(model.feature_set, X87, XL, model._resid)
    p = model._scorer.predict_proba(X)[:, 1]
    # envelope rule on the window's last sample: the 'last' z-score of each sensor is column <sensor>.last of the 87 features
    from swat.physical_features import FEATURE_NAMES
    cols = [FEATURE_NAMES.index(f"{t}.last") for t in SENSORS]
    raw_last = X87[:, cols] * model.norm.sd + model.norm.mu
    env = ((raw_last < model.norm.lo) | (raw_last > model.norm.hi)).any(axis=1)
    flag = p > model.clf_threshold
    return {"n": len(X87), "meta": meta, "p": p, "if_score": None, "model_flag": flag, "env_flag": env, "rule_flag": flag | env}


def _v3_observations(model, test: pd.DataFrame):
    """PhysicalModelV3 on the test block: the same feature code and scoring the live model calls (batch path)."""
    from swat import features_v3 as F3
    X87, XL, X3, AUX, meta = F3.build_windows_v3(test, model.norm, stride=STRIDE)
    if len(X87) == 0:
        return None
    p, _heads, _nm = model.score_batch(X3, AUX, packed=False)
    from swat.physical_features import FEATURE_NAMES
    cols = [FEATURE_NAMES.index(f"{t}.last") for t in SENSORS]
    raw_last = X87[:, cols] * model.norm.sd + model.norm.mu
    env = ((raw_last < model.norm.lo) | (raw_last > model.norm.hi)).any(axis=1)
    flag = p > model.clf_threshold
    return {"n": len(X87), "meta": meta, "p": p, "if_score": None, "model_flag": flag, "env_flag": env, "rule_flag": flag | env}


def evaluate(model: PhysicalModel, stream: pd.DataFrame) -> Dict[str, Any]:
    test = stream[stream["block"] == "test"].reset_index(drop=True)
    obs_fn = {"v3": _v3_observations, "v2": _v2_observations}.get(getattr(model, "variant", ""), _v1_observations)
    o = obs_fn(model, test)
    if o is None:
        return {"status": "NOT RUN: no test-block windows"}
    meta, model_flag, env_flag, flag = o["meta"], o["model_flag"], o["env_flag"], o["rule_flag"]
    y = meta["label"].to_numpy().astype(bool)
    ep = meta["epoch"].to_numpy()
    seg = meta["seg"].to_numpy()
    out: Dict[str, Any] = {"status": "OK", "block": "test (held-out calendar block)", "windows": int(o["n"]),
                           "attack_windows": int(y.sum()), "benign_windows": int((~y).sum()), "stride_s": STRIDE}
    hours = max((~y).sum() * STRIDE / 3600.0, 1e-9)
    out["benign_hours"] = round(float(hours), 3)
    out["advisory_model_flag"] = {**confusion(y, model_flag), "alarm_episodes_on_benign_windows": episodes(ep[~y], model_flag[~y]),
                                  "alarm_episodes_per_benign_hour": round(episodes(ep[~y], model_flag[~y]) / hours, 3)}
    out["envelope_rule_alone (alert-only)"] = {**confusion(y, env_flag),
                                               "alarm_episodes_per_benign_hour": round(episodes(ep[~y], env_flag[~y]) / hours, 3)}
    out["model_flag_or_envelope"] = {**confusion(y, flag), "alarm_episodes_per_benign_hour": round(episodes(ep[~y], flag[~y]) / hours, 3)}
    try:
        from sklearn.metrics import average_precision_score, roc_auc_score
        if 0 < y.sum() < len(y):
            out["roc_auc_attack_probability"] = round(float(roc_auc_score(y, o["p"])), 4)
            if o["if_score"] is not None:
                out["roc_auc_isolation_forest_score"] = round(float(roc_auc_score(y, o["if_score"])), 4)
            out["average_precision_attack_probability"] = round(float(average_precision_score(y, o["p"])), 4)
    except Exception as exc:                       # pragma: no cover
        out["auc_error"] = str(exc)
    segs: List[Dict[str, Any]] = []
    for s in sorted(set(seg[y])):
        m = (seg == s) & y
        first_attack_epoch = float(ep[m].min())
        hit = m & model_flag
        segs.append({"segment": int(s), "attack_windows": int(m.sum()), "duration_s": float(ep[m].max() - first_attack_epoch) + STRIDE,
                     "flagged_windows": int(hit.sum()), "detected": bool(hit.any()),
                     "detection_latency_s": float(ep[hit].min() - first_attack_epoch) if hit.any() else None})
    det = [s for s in segs if s["detected"]]
    lat = [s["detection_latency_s"] for s in det]
    out["segments"] = {"total": len(segs), "detected": len(det),
                       "median_detection_latency_s": float(np.median(lat)) if lat else None, "per_segment": segs}
    if segs:
        big = max(segs, key=lambda s: s["attack_windows"])
        rest = (seg != big["segment"]) | ~y
        out["excluding_largest_segment"] = {"segment": big["segment"], "share_of_attack_windows": round(big["attack_windows"] / max(1, int(y.sum())), 3),
                                            "advisory_model_flag": confusion(y[rest], model_flag[rest])}
    return out


def run(data_dir: str, fixture: bool = False, weights: str | None = None) -> Dict[str, Any]:
    if weights:
        from models.physical_model_v2 import PhysicalModelV2
        from models.physical_model_v3 import PhysicalModelV3
        model = PhysicalModelV3.load(weights)
        if model.status != "OK":
            model = PhysicalModelV2.load(weights)
        if model.status != "OK":
            model = PhysicalModel.load(weights)
    else:
        model = load_physical_model()
    if model.status != "OK":
        return {"status": f"NOT RUN: physical model not usable ({model.status})"}
    stream, info = load_stream(data_dir, SENSORS + ACTUATORS)
    res = evaluate(model, stream)
    res.update({"label": f"PROMOTED physical model ({type(model).__name__}) on the HELD-OUT SWaT test block (real data, aggregate only)" if not fixture
                else "SYNTHETIC SWaT-SHAPED FIXTURE: code path only, numbers are meaningless",
                "fixture_not_real_results": bool(fixture),
                "operating_point": {"isolation_forest_threshold": model.threshold, "classifier_threshold": model.clf_threshold, "variant": model.variant},
                "protocol_note": "test block was also seen in physical training run 2 (revised protocol): held-out, not a pristine blind test"})
    return res


def main() -> None:
    ap = argparse.ArgumentParser(description="Promoted physical model on the held-out SWaT test block.")
    ap.add_argument("--data-dir")
    ap.add_argument("--fixture", action="store_true")
    ap.add_argument("--out", default=None, help="write the JSON here")
    a = ap.parse_args()
    if a.fixture:
        from tests.swat_fixture import make_swat_archive
        d = tempfile.mkdtemp(prefix="swat-fixture-")
        make_swat_archive(d, seed=0)
    elif a.data_dir:
        d = a.data_dir
    else:
        ap.error("give --data-dir or --fixture")
    res = run(d, a.fixture)
    txt = json.dumps({k: v for k, v in res.items() if k != "segments"} | {"segments": {k: v for k, v in res.get("segments", {}).items() if k != "per_segment"}}, indent=2)
    print(txt)
    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        with open(a.out, "w") as fh:
            json.dump(res, fh, indent=2)


if __name__ == "__main__":
    main()
