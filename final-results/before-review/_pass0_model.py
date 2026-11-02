"""PASS 0B: derive the full metric set for the live physical model from the recorded held-out confusion matrix,
and MEASURE what can be measured here (model size, load time, inference latency, throughput, memory).

The SWaT archive is not in this container, so the held-out run cannot be re-executed; everything derived below comes from the
recorded confusion matrix and is arithmetic, not a new measurement. That distinction is recorded in the report.
"""
from __future__ import annotations

import json
import os
import statistics
import time
import tracemalloc

import numpy as np

ROOT = "/home/user/IndustrialMinds"
OUT = os.path.join(ROOT, "final-results", "before-review", "_raw")
os.makedirs(OUT, exist_ok=True)
res = {}

# ---------------------------------------------------------------- recorded held-out confusion matrix
rec = json.load(open(os.path.join(ROOT, "benchmarks", "swat_accuracy.json")))
m = rec["advisory_model_flag"]
TP, FP, FN, TN = m["tp"], m["fp"], m["fn"], m["tn"]
N = TP + FP + FN + TN


def safe(a, b):
    return a / b if b else None


def rnd(x, k=4):
    return None if x is None else round(x, k)


attack = {"support": TP + FN, "precision": safe(TP, TP + FP), "recall": safe(TP, TP + FN)}
benign = {"support": TN + FP, "precision": safe(TN, TN + FN), "recall": safe(TN, TN + FP)}
for c in (attack, benign):
    p, r = c["precision"], c["recall"]
    c["f1"] = safe(2 * p * r, p + r) if p and r else 0.0
attack["specificity"], benign["specificity"] = benign["recall"], attack["recall"]
attack["fpr"], attack["fnr"] = safe(FP, FP + TN), safe(FN, FN + TP)
benign["fpr"], benign["fnr"] = safe(FN, FN + TP), safe(FP, FP + TN)

w_a, w_b = attack["support"] / N, benign["support"] / N
res["heldout_swat"] = {
    "provenance": rec.get("provenance"),
    "protocol_note": rec.get("protocol_note"),
    "block": rec.get("block"),
    "samples": N, "windows": rec.get("windows"), "benign_hours": rec.get("benign_hours"),
    "confusion_matrix": {"TN": TN, "FP": FP, "FN": FN, "TP": TP},
    "per_class": {"attack": {k: rnd(v) for k, v in attack.items()},
                  "benign": {k: rnd(v) for k, v in benign.items()}},
    "accuracy": rnd(safe(TP + TN, N)),
    "balanced_accuracy": rnd((attack["recall"] + benign["recall"]) / 2),
    "macro_precision": rnd((attack["precision"] + benign["precision"]) / 2),
    "macro_recall": rnd((attack["recall"] + benign["recall"]) / 2),
    "macro_f1": rnd((attack["f1"] + benign["f1"]) / 2),
    "weighted_precision": rnd(attack["precision"] * w_a + benign["precision"] * w_b),
    "weighted_recall": rnd(attack["recall"] * w_a + benign["recall"] * w_b),
    "weighted_f1": rnd(attack["f1"] * w_a + benign["f1"] * w_b),
    "auc_roc": rec.get("roc_auc_attack_probability"),
    "average_precision": rec.get("average_precision_attack_probability"),
    "prevalence_attack": rnd(w_a),
    "imbalance_ratio": f"{benign['support']}:{attack['support']} = {round(benign['support'] / max(attack['support'], 1), 1)}:1",
    "majority_class_baseline_accuracy": rnd(safe(benign["support"], N)),
    "alarm_episodes_per_benign_hour": m.get("alarm_episodes_per_benign_hour"),
    "segments": rec.get("segments"),
    "operating_point": rec.get("operating_point"),
}
res["heldout_swat"]["accuracy_vs_baseline_delta"] = rnd(
    res["heldout_swat"]["accuracy"] - res["heldout_swat"]["majority_class_baseline_accuracy"])

# other recorded models, for the record
for name, path in (("cyber_candidate_rejected", "docs/reports/cyber_training_report_swat.json"),
                   ("physical_v2_experiment", "docs/reports/physical_training_report_v2_swat.json")):
    p = os.path.join(ROOT, path)
    if os.path.exists(p):
        d = json.load(open(p))
        res[name] = {"test": d.get("test"), "selected": d.get("selected")}

# ---------------------------------------------------------------- measured here: size, load, latency, memory
from models.physical_model_v2 import PhysicalModelV2  # noqa: E402
from swat.physical_features import ACTUATORS, SENSORS  # noqa: E402

wpath = os.path.join(ROOT, "models", "weights", "physical_model_v2.joblib")
tracemalloc.start()
t0 = time.perf_counter()
mod = PhysicalModelV2.load(wpath)
load_s = time.perf_counter() - t0
cur, peak = tracemalloc.get_traced_memory()
tracemalloc.stop()
res["model_runtime"] = {
    "weights_file_bytes": os.path.getsize(wpath),
    "weights_file_mb": round(os.path.getsize(wpath) / 1e6, 2),
    "load_seconds": round(load_s, 3),
    "heap_after_load_mb": round(cur / 1e6, 2),
    "peak_heap_during_load_mb": round(peak / 1e6, 2),
    "status": mod.status, "features": len(mod._feature_names), "window_s": mod.window_size,
    "threshold": mod.clf_threshold,
}

rng = np.random.default_rng(0)
nominal = {s: float(mod.norm.mu[i]) for i, s in enumerate(SENSORS)}
nominal.update({a: 100.0 for a in ACTUATORS})
t0 = 1e6
for i in range(130):
    r = {s: float(mod.norm.mu[j] + 0.05 * mod.norm.sd[j] * rng.standard_normal()) for j, s in enumerate(SENSORS)}
    r.update({a: 100.0 for a in ACTUATORS})
    mod.update(r, timestamp=t0 + i)

lat = []
for i in range(200):
    mod.update(nominal, timestamp=t0 + 130 + i)
    a = time.perf_counter()
    mod.assess()
    lat.append((time.perf_counter() - a) * 1000)
lat.sort()
res["model_runtime"]["inference_ms"] = {
    "n": len(lat), "mean": round(statistics.mean(lat), 3), "p50": round(lat[len(lat) // 2], 3),
    "p95": round(lat[int(len(lat) * 0.95)], 3), "p99": round(lat[int(len(lat) * 0.99)], 3), "max": round(lat[-1], 3)}
res["model_runtime"]["throughput_assess_per_s"] = round(1000.0 / statistics.mean(lat), 1)

# cold path: a flagged window costs more (it runs the stage attribution)
mod2 = PhysicalModelV2.load(wpath)


def noisy(extra=None):
    r = {s: float(mod2.norm.mu[j] + 0.05 * mod2.norm.sd[j] * rng.standard_normal()) for j, s in enumerate(SENSORS)}
    r.update({a: 100.0 for a in ACTUATORS})
    r.update(extra or {})
    return r


for i in range(130):
    mod2.update(noisy(), timestamp=t0 + i)
base_rep = mod2.assess()
res["model_runtime"]["reference_captured_on_healthy_plant"] = mod2._ref is not None
res["model_runtime"]["healthy_probability"] = base_rep.get("attack_probability")
j = SENSORS.index("LIT301")
for i in range(60):
    mod2.update(noisy({"LIT301": float(mod2.norm.mu[j] + 6 * mod2.norm.sd[j])}), timestamp=t0 + 130 + i)
flag_lat = []
for i in range(40):
    mod2.update(noisy({"LIT301": float(mod2.norm.mu[j] + 6 * mod2.norm.sd[j])}), timestamp=t0 + 190 + i)
    a = time.perf_counter()
    rep = mod2.assess()
    flag_lat.append((time.perf_counter() - a) * 1000)
flag_lat.sort()
res["model_runtime"]["inference_ms_when_flagged"] = {
    "n": len(flag_lat), "mean": round(statistics.mean(flag_lat), 3), "p50": round(flag_lat[len(flag_lat) // 2], 3),
    "p95": round(flag_lat[int(len(flag_lat) * 0.95)], 3), "max": round(flag_lat[-1], 3),
    "flagged": bool(rep["threat_flag"]), "suspect_stage": rep.get("suspect_stage")}

# ---------------------------------------------------------------- what cannot be computed, and why
res["not_computable_here"] = [
    {"metric": "a FRESH held-out evaluation (all classification metrics re-measured)",
     "why": "the SWaT archive is not in this container and never has been (see CLAUDE.md dataset policy); the numbers above "
            "are arithmetic on a confusion matrix recorded from a run the user executed on their own machine"},
    {"metric": "ROC curve / PR curve as images",
     "why": "only the aggregate confusion matrix and the scalar AUC were recorded, not the per-window scores needed to draw a curve"},
    {"metric": "MAE / RMSE", "why": "there is no regression component; the RUL regressor was removed"},
    {"metric": "per-class metrics for the cyber branch",
     "why": "the cyber branch has no model (rules only, by decision); its rule checks are specification conformance, "
            "not a classifier, and SWaT contains no network traffic to validate them against"},
]
json.dump(res, open(os.path.join(OUT, "model.json"), "w"), indent=1)
print(json.dumps(res["heldout_swat"], indent=1)[:2000])
print("\nruntime:", json.dumps(res["model_runtime"], indent=1))
