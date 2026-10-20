"""
tests/test_swat_physical.py - Phase 6: measured bounds, window features, PhysicalModel, trainer, pipeline integration.

Runs on a synthetic SWaT-SHAPED fixture (tests/swat_fixture.py): validates CODE paths and invariants only;
the fixture's metrics say nothing about real SWaT performance.

    python -m tests.test_swat_physical
"""

from __future__ import annotations

import os
import tempfile
import time

import joblib
import numpy as np

from core.interfaces import MACHINE_BY_NAME, make_command
from models.physical_model import PhysicalModel
from models.train_physical_swat import STRIDE, run
from research.train_cyber_swat import WEIGHTS_DIR
from pipeline.multi_model_pipeline import MultiModelPipeline
from swat.loader import load_stream
from swat.physical_features import (ACTUATORS, FEATURE_NAMES, SENSORS, WINDOW, Norm, actuator_class_series, build_windows,
                                    compute_bounds, window_features)
from tests.swat_fixture import make_swat_archive

fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global fails
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    fails += 0 if cond else 1


tmp = tempfile.mkdtemp(prefix="swat-phys-")
arch = os.path.join(tmp, "a")
make_swat_archive(arch, seed=0)
stream, info = load_stream(arch, SENSORS + ACTUATORS)

print("BOUNDS")
tn = stream[(stream.block == "train") & ~stream.label]
b = compute_bounds(tn[SENSORS])
check("bounds computed for every sensor from train-block normal rows only", set(b) == set(SENSORS) and all(b[s]["n"] > 1000 for s in SENSORS))
check("envelope encloses [p0.1, p99.9] and the median sits inside it",
      all(b[s]["envelope_lo"] < b[s]["p0.1"] <= b[s]["median"] <= b[s]["p99.9"] < b[s]["envelope_hi"] for s in SENSORS))
check("no train-normal row lies outside its own envelope",
      all(((tn[s] >= b[s]["envelope_lo"]) & (tn[s] <= b[s]["envelope_hi"])).all() for s in SENSORS))

print("\nFEATURES")
norm = Norm(b)
X, meta = build_windows(stream, norm, stride=STRIDE)
check("feature matrix width equals the declared schema", X.shape[1] == len(FEATURE_NAMES) == 87, str(X.shape))
check("features are finite", bool(np.isfinite(X).all()))
_ep = stream["epoch"].to_numpy()
_X1, _m1 = build_windows(stream, norm, stride=1)
_end = np.searchsorted(_ep, _m1["epoch"].to_numpy())
check("no window spans a data gap (each covers exactly 29 s from its first to its last sample)",
      len(_end) > 0 and bool(np.all(_ep[_end] - _ep[_end - (WINDOW - 1)] == WINDOW - 1)), f"{len(_end)} windows checked")
check("window blocks are chronological (train < val < test)",
      meta[meta.block == "train"].epoch.max() < meta[meta.block == "val"].epoch.min() <= meta[meta.block == "val"].epoch.max() < meta[meta.block == "test"].epoch.min())

print("\nMODEL + TRAINER (candidate only)")
out = os.path.join(tmp, "cand")
rep = run(arch, out, seed=7, fixture=True)
files = ("physical_model.joblib", "physical_training_report.json", "physical_training_report.md", "swat_bounds.json")
check("candidate weights, report and bounds files written", all(os.path.exists(os.path.join(out, f)) for f in files))
md = open(os.path.join(out, "physical_training_report.md"), encoding="utf-8").read()
check("report carries the fixture banner, provenance, bounds-rule validation and the no-RUL note",
      "SYNTHETIC FIXTURE" in md and "Feature provenance" in md and "Measured-envelope RULE" in md and "RUL" in md)
te = rep["results"]["test"]["combined_either"]
check("confusion cells add up to the test windows", te["tn"] + te["fp"] + te["fn"] + te["tp"] == rep["windows"]["by_block"]["test"]["windows"])
check("variant + regularisation chosen from a grid on validation (not test); operating curve reported", len(rep["classifier_selection"]["grid"]) == 8 and "operating_curve_test" in rep)
try:
    run(arch, WEIGHTS_DIR, seed=7, fixture=True)
    check("trainer refuses to write into models/weights", False)
except SystemExit:
    check("trainer refuses to write into models/weights", True)
pm = PhysicalModel.load(os.path.join(out, "physical_model.joblib"))
check("candidate loads (status OK) with both heads and thresholds", pm.status == "OK" and pm.clf_threshold is not None and pm.threshold is not None)
Xs = X[:2000]
d_if = np.abs(pm.anomaly_scores(Xs) - (-pm._model.score_samples(pm._sel(Xs)))).max()
d_cl = np.abs(pm.attack_probability(Xs) - pm._clf.predict(pm._sel(Xs))).max()
check("packed inference == sklearn (Isolation Forest and classifier)", d_if < 1e-12 and d_cl < 1e-12, f"{d_if:.1e} / {d_cl:.1e}")

print("\nTRAIN/LIVE CONSISTENCY")
X1, meta1 = build_windows(stream, pm.norm, stride=1)
chunk = stream["chunk"].to_numpy()
S = stream[SENSORS].to_numpy(dtype=np.float64)
A = np.column_stack([actuator_class_series(stream[a].to_numpy(dtype=np.float64), a.startswith("MV"), chunk) for a in ACTUATORS])
rng = np.random.default_rng(3)
picked = rng.choice(len(X1), 12, replace=False)
epoch_to_row = {float(e): i for i, e in enumerate(stream["epoch"].to_numpy())}
max_diff = 0.0
for k in picked:
    end = epoch_to_row[float(meta1["epoch"].iloc[k])]
    live = PhysicalModel.load(os.path.join(out, "physical_model.joblib"))
    for r in range(end - WINDOW + 1, end + 1):
        regs = {t: float(S[r, i]) for i, t in enumerate(SENSORS)}
        regs.update({t: float(A[r, i]) * 100.0 for i, t in enumerate(ACTUATORS)})
        live.update(regs, timestamp=float(stream["epoch"].iloc[r]))
    rpt = live.assess()
    expect = float(pm.anomaly_scores(X1[k:k + 1])[0])
    max_diff = max(max_diff, abs(rpt["anomaly_score"] - round(expect, 4)),
                   abs(rpt["attack_probability"] - round(float(pm.attack_probability(X1[k:k + 1])[0]), 4)))
check("live window (continuous % + 1 Hz decimation) reproduces the TRAINING scores for the same seconds", max_diff < 1e-9, f"max diff {max_diff:.1e} over 12 windows")

print("\nLIVE BEHAVIOUR")
lv = PhysicalModel.load(os.path.join(out, "physical_model.joblib"))
nominal = {t: float(b[t]["median"]) for t in SENSORS}
nominal.update({t: 100.0 for t in ACTUATORS})
t0 = 1_000_000.0
for i in range(WINDOW - 1):
    lv.update(nominal, timestamp=t0 + i)
check("WARMING_UP until the 30 s window is full", lv.assess()["status"] == "WARMING_UP" and not lv.is_warm)
lv.update(nominal, timestamp=t0 + WINDOW - 1)
r1 = lv.assess()
check("full window -> OK with both scores and a plant_state", r1["status"] == "OK" and r1["anomaly_score"] is not None
      and r1["attack_probability"] is not None and r1["plant_state"] in ("NORMAL", "ALERT"), str({k: r1[k] for k in ("status", "plant_state", "anomaly_score")}))
for j in range(40):                                   # 5 Hz poll: samples 0.2 s apart must be decimated to 1 Hz
    lv.update(nominal, timestamp=t0 + WINDOW + j * 0.2)
check("5 Hz polling is decimated to 1 Hz (window keeps its size, no early advance)", len(lv._buf) == WINDOW and lv._last_t < t0 + WINDOW + 8.0)
bad = dict(nominal, LIT301=b["LIT301"]["envelope_hi"] + 5 * b["LIT301"]["std"] + 1)
lv.update(bad, timestamp=t0 + 200.0)
lv2 = PhysicalModel.load(os.path.join(out, "physical_model.joblib"))
for i in range(WINDOW):
    lv2.update(nominal, timestamp=t0 + i)
lv2.update(bad, timestamp=t0 + WINDOW)
r2 = lv2.assess()
check("a sensor outside the measured envelope is reported in bounds_violations and raises plant_state ALERT",
      any(v["tag"] == "LIT301" for v in r2["bounds_violations"]) and r2["plant_state"] == "ALERT", str(r2["bounds_violations"]))
lv3 = PhysicalModel.load(os.path.join(out, "physical_model.joblib"))
for i in range(WINDOW):
    lv3.update(nominal, timestamp=t0 + i)
lv3.update(nominal, timestamp=t0 + WINDOW + 60.0)    # a 60 s hole in telemetry restarts the window
check("a telemetry gap longer than 5 s restarts the window", len(lv3._buf) == 1 and lv3.assess()["status"] == "WARMING_UP")
check("assess latency < 10 ms", r1["latency_ms"] < 10, f"{r1['latency_ms']} ms")
lv4 = PhysicalModel.load(os.path.join(out, "physical_model.joblib"))
lv4._packed = "broken"
for i in range(WINDOW):
    lv4.update(nominal, timestamp=t0 + i)
rb = lv4.assess()
check("an internal failure -> ERROR, no crash, no flag", rb["status"] == "ERROR" and rb["threat_flag"] is False)

print("\nSTALE / MISSING WEIGHTS")
stale = os.path.join(tmp, "stale.joblib")
blob = joblib.load(os.path.join(out, "physical_model.joblib"))
blob["metadata"] = dict(blob["metadata"], feature_names=["sd2_std"])
joblib.dump(blob, stale)
check("weights with a different feature schema are refused (NO_MODEL)", PhysicalModel.load(stale).status == "NO_MODEL")
joblib.dump({"model": object()}, os.path.join(tmp, "old.joblib"))
check("an old-style blob (no bounds, e.g. the synthetic RUL model) is refused", PhysicalModel.load(os.path.join(tmp, "old.joblib")).status == "NO_MODEL")
check("missing weights -> NO_MODEL abstain", PhysicalModel.load("/nonexistent/p.joblib").assess()["status"] == "NO_MODEL")
with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as fh:
    fh.write(b"not a model")
check("corrupt weights -> NO_MODEL, no crash", PhysicalModel.load(fh.name).status == "NO_MODEL")
os.unlink(fh.name)

print("\nPIPELINE INTEGRATION WITH AN 'OK' PHYSICAL MODEL")
import middleware.middleware_server as mw  # noqa: E402
pipe = MultiModelPipeline(physical_model=PhysicalModel.load(os.path.join(out, "physical_model.joblib")))
state_regs = {m["name"]: float(m["initial"]) for m in MACHINE_BY_NAME.values()}
for i in range(WINDOW + 2):
    pipe.ingest_telemetry({**state_regs, **nominal}, timestamp=t0 + i)
cmd = make_command("pi-1", time.time(), "127.0.0.1", 6, MACHINE_BY_NAME["P101"]["register"], 60.0)
rep2 = pipe.process_command(cmd, {"registers": dict(state_regs), "timestamp": time.time()})
pm_rep = rep2["physical"]["model"]
check("pipeline report carries the new physical-model fields and a plant_state",
      pm_rep["status"] == "OK" and rep2["physical"]["plant_state"] in ("NORMAL", "ALERT") and "bounds_violations" in pm_rep)
try:
    mw._log_live_telemetry(time.time() + 100.0, pipe)
    check("middleware [TELEMETRY] line renders with an OK model", True)
except Exception as exc:
    check("middleware [TELEMETRY] line renders with an OK model", False, repr(exc))

print("\nUPSTREAM ENVELOPE ALERT (middleware)")
calls = []
_orig_decide = mw.orchestrator.decide
mw.orchestrator.decide = lambda cv, pv, st=None: calls.append((cv, pv)) or {}
try:
    mw._last_envelope_alert.clear()
    tele = {m["name"]: m["initial"] for m in MACHINE_BY_NAME.values()}
    mw._check_upstream_envelope(dict(tele), 1000.0)
    check("nominal telemetry raises no upstream alert", calls == [])
    bad_t = dict(tele, LIT301=5000.0)
    mw._check_upstream_envelope(dict(bad_t), 1000.0)
    check("an out-of-envelope sensor raises ONE upstream DROP decision (cyber verdict None = upstream path)",
          len(calls) == 1 and calls[0][0] is None and calls[0][1]["pass"] is False and "LIT301" in calls[0][1]["reason"])
    mw._check_upstream_envelope(dict(bad_t), 1010.0)
    check("the same sensor is rate-limited (no second alert within the interval)", len(calls) == 1)
    mw._check_upstream_envelope(dict(bad_t), 1000.0 + mw.ENVELOPE_ALERT_INTERVAL + 1)
    check("...and alerts again after the interval", len(calls) == 2)
finally:
    mw.orchestrator.decide = _orig_decide

print("\nALL PASS" if fails == 0 else f"\n{fails} CHECK(S) FAILED")
raise SystemExit(1 if fails else 0)
