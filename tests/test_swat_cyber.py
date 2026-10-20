"""
tests/test_swat_cyber.py - Phase 5: SWaT loader, event extraction, feature consistency, CyberModel, trainer.

Runs on a synthetic SWaT-SHAPED fixture (tests/swat_fixture.py). These checks validate CODE paths and
invariants; the fixture's metrics say nothing about real SWaT performance.

    python -m tests.test_swat_cyber
"""

from __future__ import annotations

import math
import os
import tempfile
import time

import numpy as np
import pandas as pd

from core.interfaces import MV101, MV503, LIT101, P101, MACHINE_BY_REGISTER, make_command
from models.cyber_model import CyberModel, CyberFeatureExtractor
from research.train_cyber_swat import WEIGHTS_DIR, run
from swat.cyber_events import (ACTUATOR_COLUMNS, FEATURE_NAMES, EventFeatureStream, event_features, extract_events)
from swat.loader import SwatDataError, load_stream
from tests.swat_fixture import make_swat_archive

fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global fails
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    fails += 0 if cond else 1


tmp = tempfile.mkdtemp(prefix="swat-test-")
truth = make_swat_archive(os.path.join(tmp, "a"), seed=0)
stream, info = load_stream(os.path.join(tmp, "a"), list(ACTUATOR_COLUMNS))

print("LOADER")
check("35 attack segments recovered", info["n_segments"] == truth["n_segments"] == 35, str(info["n_segments"]))
check("split is 17/8/10 segments (train/val/test)",
      [info["blocks"][b]["segments"] for b in ("train", "val", "test")] == [17, 8, 10])
check("every duplicate timestamp dropped and all were exact copies",
      info["duplicate_timestamps_dropped"] == truth["duplicate_timestamps"] and info["duplicates_conflicting"] == 0)
check("stream is strictly increasing in time", bool((stream["epoch"].diff().dropna() > 0).all()))
check("no segment crosses midnight / straddles blocks", info["segments_crossing_midnight"] == 0 and
      stream[stream.seg > 0].groupby("seg")["block"].nunique().max() == 1)
check("blocks are chronological (train < val < test)",
      stream[stream.block == "train"].epoch.max() < stream[stream.block == "val"].epoch.min()
      <= stream[stream.block == "val"].epoch.max() < stream[stream.block == "test"].epoch.min())
check("MV101 is NaN throughout the normal period (as in the real archive)",
      bool(stream.loc[stream.period == "normal_period", "MV101"].isna().all()))
conf_dir = os.path.join(tmp, "conflict")
make_swat_archive(conf_dir, seed=0, dup_identical=False)
_, info_c = load_stream(conf_dir, list(ACTUATOR_COLUMNS) + ["LIT101"])   # the fixture perturbs a SENSOR copy
check("conflicting duplicates are detected and reported", info_c["duplicates_conflicting"] > 0, str(info_c["duplicates_conflicting"]))
try:
    load_stream(os.path.join(tmp, "nonexistent"), ["P101"])
    check("missing folder raises SwatDataError", False)
except SwatDataError:
    check("missing folder raises SwatDataError", True)

print("\nEVENTS")
base = pd.DataFrame({"epoch": np.arange(12, dtype=float), "label": False, "seg": 0, "block": "train",
                     "chunk": [0] * 6 + [1] * 6, "P101": [2, 2, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2],
                     "MV302": [2, 0, 0, 0, 1, 1, 1, 1, 0, 0, 2, 2]})
ev = extract_events(base)
p = ev[ev.tag == "P101"]
check("pump change inside a chunk is an event; the change across a chunk boundary is NOT",
      list(p.epoch) == [2.0] and list(p.turns_on) == [0], str(list(p.epoch)))
m = ev[ev.tag == "MV302"]
check("valve transit rows (state 0) are not states: exactly the 2->1 and 1->2 settles",
      list(m.epoch) == [4.0, 10.0] and list(m.turns_on) == [0, 1], str(list(m.epoch)))
fs = EventFeatureStream()
v0 = fs.push(100.0, 1, 1)
v1 = fs.push(100.5, 1, 0)
check("features: first event has the 60 s 'no previous' timing; the second (0.5 s later) sees 1 event in 1 s and 1 same-actuator event",
      abs(v0[3] - math.log1p(60000.0)) < 1e-12 and abs(v1[3] - math.log1p(500.0)) < 1e-12
      and v1[5] == 1.0 and v1[7] == 1.0 and v0[5] == 0.0)

print("\nTRAIN/LIVE FEATURE CONSISTENCY")
ev = extract_events(stream)
X = event_features(ev)
check("events extracted from every SWaT-backed actuator family", {"P101", "MV302", "P203"} <= set(ev.tag), str(sorted(set(ev.tag))))
ext = CyberFeatureExtractor()
Y = np.empty_like(X)
last_chunk = None
for i, r in enumerate(ev.itertuples()):
    if last_chunk is not None and r.chunk != last_chunk:
        ext.reset()
    last_chunk = r.chunk
    new_v, old_v = (100.0, 0.0) if r.turns_on else (0.0, 100.0)
    name = MACHINE_BY_REGISTER[r.register]["name"]
    cmd = make_command(f"e{i}", float(r.epoch), "127.0.0.1", 6, int(r.register), new_v)
    Y[i] = ext.transform(cmd, {"registers": {name: old_v}})
check("live extractor reproduces the TRAINING features exactly for the same events",
      np.allclose(X, Y, atol=1e-12), f"max diff {np.abs(X - Y).max():.1e} over {len(X)} events")

print("\nMODEL + TRAINER (candidate only)")
out = os.path.join(tmp, "cand")
rep = run(os.path.join(tmp, "a"), out, seed=7, fixture=True)
check("candidate weights and report files written", all(os.path.exists(os.path.join(out, f)) for f in
      ("cyber_model.joblib", "cyber_training_report.json", "cyber_training_report.md")))
md = open(os.path.join(out, "cyber_training_report.md"), encoding="utf-8").read()
check("report carries the fixture banner and the provenance table", "SYNTHETIC FIXTURE" in md and "Feature provenance" in md
      and "dropped" in md and "NOT evaluated here" in md)
te = rep["results"]["test"]["combined_either"]
check("confusion matrix cells add up to the test events", te["tn"] + te["fp"] + te["fn"] + te["tp"] == rep["events"]["by_block"]["test"]["events"])
tr_t, va_t = ev[ev.block == "train"].epoch.max(), ev[ev.block == "val"].epoch.min()
check("train events strictly precede validation events (no leakage across the split)", tr_t < va_t)
cm = CyberModel.load(os.path.join(out, "cyber_model.joblib"))
check("candidate loads (status OK) with both heads and thresholds", cm.status == "OK" and cm.clf_threshold is not None and cm.threshold is not None)
d_if = np.abs(cm.anomaly_scores(X) - (-cm._model.score_samples(X))).max()
d_cl = np.abs(cm.attack_probability(X) - cm._clf.predict(X)).max()
check("packed inference == sklearn (Isolation Forest and classifier)", d_if < 1e-12 and d_cl < 1e-12, f"{d_if:.1e} / {d_cl:.1e}")
try:
    run(os.path.join(tmp, "a"), WEIGHTS_DIR, seed=7, fixture=True)
    check("trainer refuses to write into models/weights", False)
except SystemExit:
    check("trainer refuses to write into models/weights", True)

print("\nLIVE SCORING / ABSTENTION")
state = {"registers": {"P101": 0.0, "MV503": 0.0, "LIT101": 500.0}}
now = time.time()
flip = cm.evaluate_payload(make_command("t1", now, "127.0.0.1", 6, P101, 100.0), state)
check("an on/off flip is scored (status OK, both scores present)", flip["status"] == "OK" and flip["anomaly_score"] is not None
      and flip["attack_probability"] is not None, str({k: flip[k] for k in ("status", "anomaly_score", "attack_probability")}))
small = cm.evaluate_payload(make_command("t2", now + 1, "127.0.0.1", 6, P101, 20.0), state)
check("a write that does not flip on/off -> NOT_APPLICABLE, no threat flag", small["status"] == "NOT_APPLICABLE" and small["threat_flag"] is False)
sens = cm.evaluate_payload(make_command("t3", now + 2, "127.0.0.1", 6, LIT101, 900.0), state)
check("a write to a sensor register -> NOT_APPLICABLE (rules drop it)", sens["status"] == "NOT_APPLICABLE")
syn = cm.evaluate_payload(make_command("t4", now + 3, "127.0.0.1", 6, MV503, 100.0), state)
check("twin-only MV503 is scored with the generic timing features", syn["status"] == "OK")
check("evaluate_payload latency < 10 ms", flip["latency_ms"] < 10, f"{flip['latency_ms']} ms")
bad = cm.evaluate_payload({"timestamp": "garbage", "register": P101, "value": 100.0}, state)
check("malformed command -> ERROR, no crash, no flag", bad["status"] == "ERROR" and bad["threat_flag"] is False)

print("\nSTALE / MISSING WEIGHTS")
import joblib
stale = os.path.join(tmp, "stale.joblib")
blob = joblib.load(os.path.join(out, "cyber_model.joblib"))
blob["metadata"] = dict(blob["metadata"], feature_names=["fc_write_single", "fc_write_multiple"])   # a different (old) schema
joblib.dump(blob, stale)
check("weights with a different feature schema are refused (NO_MODEL) instead of mis-scoring", CyberModel.load(stale).status == "NO_MODEL")
missing = CyberModel.load("/nonexistent/cyber.joblib")
check("missing weights -> NO_MODEL abstain", missing.evaluate_payload(make_command("t5", now, "127.0.0.1", 6, P101, 100.0), state)["status"] == "NO_MODEL")
with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as fh:
    fh.write(b"not a model")
corrupt = CyberModel.load(fh.name)
os.unlink(fh.name)
check("corrupt weights -> NO_MODEL, no crash", corrupt.status == "NO_MODEL")

print("\nALL PASS" if fails == 0 else f"\n{fails} CHECK(S) FAILED")
raise SystemExit(1 if fails else 0)
