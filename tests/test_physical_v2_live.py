"""
tests/test_physical_v2_live.py - the promoted PhysicalModelV2: live inference == training features, packed == sklearn, safe fallbacks.

    python -m tests.test_physical_v2_live
"""

from __future__ import annotations

import os
import tempfile
import time

import joblib
import numpy as np
import pandas as pd

from models.physical_model import PhysicalModel
from models.physical_model_v2 import DEFAULT_WEIGHTS, PhysicalModelV2, load_physical_model
from models.tree_inference import PackedHistGB
from swat.features_v2 import assemble, build_windows_v2
from swat.physical_features import ACTUATORS, SENSORS

fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global fails
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    fails += 0 if cond else 1


print("LOAD")
m = PhysicalModelV2.load()
check("the promoted v2 weights load (status OK, 120 s window, threshold 0.788)",
      m.status == "OK" and m.window_size == 120 and abs(m.clf_threshold - 0.788) < 1e-3, f"{m.status} {m.window_size} {m.clf_threshold}")
check("default factory returns v2; IM_PHYSICAL_MODEL=v1 returns the v1 model",
      isinstance(load_physical_model(), PhysicalModelV2) and type(load_physical_model("v1")) is PhysicalModel)
check("missing weights -> NO_MODEL abstain, and the factory falls back to v1",
      PhysicalModelV2.load("/nonexistent/x.joblib").status == "NO_MODEL")
with tempfile.TemporaryDirectory() as d:
    bad = os.path.join(d, "bad.joblib")
    joblib.dump({"schema": "other"}, bad)
    check("weights of another schema are ignored (NO_MODEL)", PhysicalModelV2.load(bad).status == "NO_MODEL")
ab = PhysicalModelV2.load("/nonexistent/x.joblib").assess()
check("abstaining model never flags", ab["threat_flag"] is False and ab["status"] == "NO_MODEL")

print("\nPACKED INFERENCE")
blob = joblib.load(DEFAULT_WEIGHTS)
gb = blob["scorer"]
rng = np.random.default_rng(0)
X = rng.normal(size=(300, len(blob["metadata"]["feature_names"]))) * rng.uniform(0.1, 5, len(blob["metadata"]["feature_names"]))
diff = float(np.abs(PackedHistGB(gb).predict_proba1(X) - gb.predict_proba(X)[:, 1]).max())
check("PackedHistGB reproduces sklearn predict_proba", diff < 1e-9, f"max diff {diff:.1e}")

print("\nLIVE == TRAINING FEATURES")
n = 400
norm = m.norm
r = np.random.default_rng(1)
S = norm.mu + norm.sd * r.normal(size=(n, len(SENSORS))) * 0.7 + np.cumsum(r.normal(size=(n, len(SENSORS))) * 0.02, axis=0) * norm.sd
Araw = np.where(r.random((n, len(ACTUATORS))) < 0.15, 1.0, 2.0)               # SWaT states: 2 = on, 1 = off
stream = pd.DataFrame(S, columns=SENSORS)
for i, a in enumerate(ACTUATORS):
    stream[a] = Araw[:, i]
stream["epoch"] = np.arange(n, dtype=float)
stream["label"], stream["seg"], stream["block"], stream["chunk"] = False, 0, "test", 0
X87, XL, meta = build_windows_v2(stream, norm, stride=7)
Xf = assemble(m.feature_set, X87, XL, m._resid)
expect = gb.predict_proba(Xf)[:, 1]
worst, picked = 0.0, [0, len(Xf) // 2, len(Xf) - 1]
for k in picked:
    end = int(meta["epoch"].iloc[k])
    live = PhysicalModelV2.load()
    for row in range(end - 119, end + 1):
        regs = {t: float(S[row, i]) for i, t in enumerate(SENSORS)}
        regs.update({t: (100.0 if Araw[row, i] == 2 else 0.0) for i, t in enumerate(ACTUATORS)})
        live.update(regs, timestamp=1_000_000.0 + row)
    rep = live.assess()
    worst = max(worst, abs(rep["attack_probability"] - round(float(expect[k]), 4)))
check("a live 120 s window reproduces the TRAINING probability for the same seconds", worst < 1e-9, f"max diff {worst:.1e} over {len(picked)} windows")

print("\nLIVE BEHAVIOUR")
lv = PhysicalModelV2.load()
nominal = {t: float(norm.mu[i]) for i, t in enumerate(SENSORS)}
nominal.update({t: 100.0 for t in ACTUATORS})
t0 = 2_000_000.0
for i in range(119):
    lv.update(nominal, timestamp=t0 + i)
check("WARMING_UP until the 120 s window is full", lv.assess()["status"] == "WARMING_UP" and not lv.is_warm)
lv.update(nominal, timestamp=t0 + 119)
r1 = lv.assess()
check("full window -> OK with an attack probability, no anomaly score, v2 model name",
      r1["status"] == "OK" and r1["attack_probability"] is not None and r1["anomaly_score"] is None and r1["model"] == "PhysicalModelV2",
      str({k: r1[k] for k in ("status", "plant_state", "attack_probability")}))
check("flag logic: flagged iff probability > threshold", r1["threat_flag"] == (r1["attack_probability"] > lv.clf_threshold))
for j in range(40):
    lv.update(nominal, timestamp=t0 + 120 + j * 0.2)
check("5 Hz polling is decimated to 1 Hz", len(lv._buf) == 120 and lv._last_t < t0 + 128)
lv2 = PhysicalModelV2.load()
for i in range(120):
    lv2.update(nominal, timestamp=t0 + i)
lv2.update(dict(nominal, LIT301=float(norm.hi[SENSORS.index("LIT301")]) + 5 * float(norm.sd[SENSORS.index("LIT301")])), timestamp=t0 + 120)
r2 = lv2.assess()
check("a sensor outside the measured envelope is reported and raises plant_state ALERT",
      any(v["tag"] == "LIT301" for v in r2["bounds_violations"]) and r2["plant_state"] == "ALERT")
lv2.update(nominal, timestamp=t0 + 500.0)          # a 6 min hole: window restarts
check("a telemetry gap > 5 s restarts the window", len(lv2._buf) == 1 and lv2.assess()["status"] == "WARMING_UP")
tt = []
lv3 = PhysicalModelV2.load()
for i in range(130):
    lv3.update(nominal, timestamp=t0 + i)
for i in range(30):
    lv3.update(nominal, timestamp=t0 + 130 + i)
    a = time.perf_counter()
    lv3.assess()
    tt.append((time.perf_counter() - a) * 1000)
check("assess() is fast enough for the decision path (mean < 3 ms)", float(np.mean(tt)) < 3.0, f"mean {np.mean(tt):.2f} ms, max {np.max(tt):.2f} ms")

print("\nOPERATING-POINT OVERRIDE (IM_PHYSICAL_THRESHOLD)")
shipped = PhysicalModelV2.load().clf_threshold
os.environ["IM_PHYSICAL_THRESHOLD"] = "0.5"
try:
    ov = PhysicalModelV2.load()
    check("a valid override in [0,1] replaces the threshold", abs(ov.clf_threshold - 0.5) < 1e-9
          and ov.metadata.get("operating_point_override") == 0.5 and ov.status == "OK")
    for bad in ("9", "-1", "abc", ""):
        os.environ["IM_PHYSICAL_THRESHOLD"] = bad
        m = PhysicalModelV2.load()
        check(f"an invalid override ({bad!r}) is ignored, threshold stays shipped",
              abs(m.clf_threshold - shipped) < 1e-9)
finally:
    os.environ.pop("IM_PHYSICAL_THRESHOLD", None)

print("\nALL PASS" if fails == 0 else f"\n{fails} CHECK(S) FAILED")
raise SystemExit(1 if fails else 0)
