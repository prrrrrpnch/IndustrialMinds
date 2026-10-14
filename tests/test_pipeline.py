"""
tests/test_pipeline.py - MultiModelPipeline checks (checklist section 4).

    python -m tests.test_pipeline
"""

from __future__ import annotations

import os
import tempfile
import threading
import time

os.environ.setdefault("IM_LOG_DIR", tempfile.mkdtemp(prefix="im-pipe-"))

import numpy as np  # noqa: E402

from docs.netconfig import LOOPBACK  # documented loopback default
from docs import hmac_auth  # noqa: E402
from docs.interfaces import (MACHINES, NUM_REGISTERS, MV101, P101, LIT101, P203, P205, UV401,  # noqa: E402
                             MV302, P302, P402, P501, MV503, make_command)
from middleware import cyber_agent, orchestrator, physical_agent  # noqa: E402
from models.telemetry_generator import generate_stream  # noqa: E402
from pipeline.multi_model_pipeline import MultiModelPipeline  # noqa: E402

orchestrator._forward_decision_to_dashboard = lambda payload: None
PASSED = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    assert cond, name
    PASSED.append(name)


def signed(reg: int, value: float, ip: str = LOOPBACK, tx: str = "t") -> dict:
    p = hmac_auth.parse_frame(hmac_auth.build_frame(reg, value))
    return make_command(tx, time.time(), ip, 16, reg, p["raw_value"] / 10.0, raw_value=p["raw_value"], auth=p["auth"])


def state(over: dict | None = None) -> dict:
    regs = {m["register"]: m["initial"] for m in MACHINES}
    regs.update(over or {})
    return {"registers": regs, "setpoints": dict(regs), "timestamp": time.time() - 10}


pipe = MultiModelPipeline()
stream = generate_stream(pipe.physical_model.window_size + 5, seed=3)["values"]
_t0 = time.time() - len(stream)
for k, row in enumerate(stream):   # explicit timestamps 1 s apart so 1 Hz decimation keeps every sample
    pipe.ingest_telemetry({i: v for i, v in enumerate(row)}, timestamp=_t0 + k)

# --- concurrency: record which thread runs each branch ---------------------
seen = {}
orig_c, orig_p = cyber_agent.check, physical_agent.check_command


def spy_c(cmd: dict) -> dict:
    seen["cyber"] = (threading.current_thread().name, time.perf_counter())
    time.sleep(0.05)
    seen["cyber_end"] = time.perf_counter()
    return orig_c(cmd)


def spy_p(cmd: dict, st: dict) -> dict:
    seen["physical"] = (threading.current_thread().name, time.perf_counter())
    time.sleep(0.05)
    seen["physical_end"] = time.perf_counter()
    return orig_p(cmd, st)


cyber_agent.check, physical_agent.check_command = spy_c, spy_p
cyber_agent.reset_state()
t0 = time.perf_counter()
rep = pipe.process_command(signed(MV101, 33.0), state())
elapsed = time.perf_counter() - t0
cyber_agent.check, physical_agent.check_command = orig_c, orig_p

check("both branches run on pipeline worker threads",
      seen["cyber"][0].startswith("im-pipeline") and seen["physical"][0].startswith("im-pipeline")
      and seen["cyber"][0] != seen["physical"][0], f"{seen['cyber'][0]} / {seen['physical'][0]}")
overlap = min(seen["cyber_end"], seen["physical_end"]) - max(seen["cyber"][1], seen["physical"][1])
check("branches execute concurrently (overlapping)", overlap > 0.03 and elapsed < 0.09,
      f"2 x 50 ms branches finished in {elapsed*1000:.0f} ms")

# --- unified report ---------------------------------------------------------
cyber_agent.reset_state()
rep = pipe.process_command(signed(MV101, 33.0), state())
keys_ok = {"decision", "cyber", "physical", "timings_ms", "mode"} <= set(rep)
check("unified report has decision + cyber + physical + timings", keys_ok)
check("cyber section has rule verdict, model score and threat flags",
      {"rule_verdict", "model", "threat_flags"} <= set(rep["cyber"])
      and "anomaly_score" in rep["cyber"]["model"])   # value may be None (NO_MODEL) - not asserted
check("physical section has rule verdict, model report and plant state",
      {"rule_verdict", "model", "plant_state"} <= set(rep["physical"])
      and rep["physical"]["plant_state"] in ("NORMAL", "ALERT", "WARMING_UP", "NO_MODEL", "ERROR")
      and {"status", "plant_state", "threat_flag", "bounds_violations"} <= set(rep["physical"]["model"]),
      f"state={rep['physical']['plant_state']} model={rep['physical']['model']['status']}")
check("health_report() returns the physical model assessment",
      pipe.health_report()["model"] == "PhysicalModel")
check("legit command -> PASS", rep["decision"]["verdict"] == "PASS")

cyber_agent.reset_state()
rep = pipe.process_command(signed(P203, 85.0), state({P203: 75.0, P101: 15.0}))
check("cross-register attack (ACID_OVERDOSE_LOW_FLOW) still DROPped through pipeline",
      rep["decision"]["verdict"] == "DROP" and "CROSS_REGISTER_VIOLATION:ACID_OVERDOSE_LOW_FLOW" in rep["decision"]["reason"],
      rep["decision"]["reason"][:70])

# write to a sensor register: signed, trusted, in-bounds - still DROPped by the physical rules
for reg in (LIT101, 18):   # LIT101 (raw tank level) and PIT501 (RO feed pressure)
    cyber_agent.reset_state()
    rep = pipe.process_command(signed(reg, 50.0, tx=f"s{reg}"), state())
    check(f"write to sensor register {reg} DROPped (WRITE_TO_SENSOR_REGISTER)",
          rep["decision"]["verdict"] == "DROP" and "WRITE_TO_SENSOR_REGISTER" in rep["decision"]["reason"],
          rep["decision"]["reason"][:60])

# more cross-stage rules through the whole pipeline, plus a recovery that PASSes
for rid, base, reg, val in [
        ("RAW_PUMP_DRY_RUN", {MV101: 5.0, P101: 55.0}, P101, 65.0),
        ("UF_PUMP_DEADHEAD", {MV302: 5.0, P302: 50.0}, P302, 65.0),
        ("CHLORINE_BREAKTHROUGH", {UV401: 5.0, P205: 70.0}, P205, 85.0),
        ("RO_FEED_STARVATION", {P402: 5.0, P501: 50.0}, P501, 65.0)]:
    cyber_agent.reset_state()
    rep = pipe.process_command(signed(reg, val, tx=rid), state(base))
    check(f"{rid} DROPped through pipeline",
          rep["decision"]["verdict"] == "DROP" and f"CROSS_REGISTER_VIOLATION:{rid}" in rep["decision"]["reason"])
    cyber_agent.reset_state()
    rep = pipe.process_command(signed(reg, base[reg], tx=rid + "-fix"), state({**base, reg: val}))
    check(f"{rid} recovery move towards safety PASSes", rep["decision"]["verdict"] == "PASS",
          rep["decision"]["reason"][:60])

cyber_agent.reset_state()
rep = pipe.process_command(make_command("u", time.time(), LOOPBACK, 6, MV101, 33.0, raw_value=330), state())
check("unsigned command still DROPped (HMAC gate unchanged)", rep["decision"]["reason"].startswith("HMAC_MISSING"))

# --- fail closed --------------------------------------------------------------
physical_agent.check_command = lambda c, s: 1 / 0
cyber_agent.reset_state()
rep = pipe.process_command(signed(MV101, 33.0), state())
physical_agent.check_command = orig_p
check("agent exception -> fail closed (DROP AGENT_ERROR)",
      rep["decision"]["verdict"] == "DROP" and rep["decision"]["reason"].startswith("AGENT_ERROR"),
      rep["decision"]["reason"])

# --- enforce mode -------------------------------------------------------------
enf = MultiModelPipeline(cyber_model=pipe.cyber_model, physical_model=pipe.physical_model,
                         enforce_cyber_model=True)
pipe.cyber_model.extractor.reset()
cyber_agent.reset_state()
last = None
now = time.time()
for i in range(4):   # fast signed burst: under the 5/s hard limit, but abnormal
    c = signed(MV101, 33.0 + 3 * i, tx=f"e{i}")
    c["timestamp"] = now + i * 0.02
    last = enf.process_command(c, state())
# Weights may be stale/absent (NO_MODEL: the model abstains), so only the contract is
# asserted: rules allowed it, and any DROP in this mode can only be an ML_ANOMALY one.
check("ENFORCE mode: rules allow the burst; a DROP could only come from the ML gate",
      last["cyber"]["rule_verdict"]["pass"]
      and (last["decision"]["verdict"] == "PASS" or last["decision"]["reason"].startswith("ML_ANOMALY")),
      f"{last['decision']['verdict']} model={last['cyber']['model']['status']}")
check("MONITOR mode is the default", pipe.enforce_cyber_model is False)

# --- latency --------------------------------------------------------------------
lat = []
for i in range(300):
    cyber_agent.reset_state()
    lat.append(pipe.process_command(signed(MV101, 33.0), state())["timings_ms"]["total"])
check("pipeline p95 latency < 10 ms", np.percentile(lat, 95) < 10,
      f"p50={np.percentile(lat,50):.2f} p95={np.percentile(lat,95):.2f} ms")

pipe.shutdown(); enf.shutdown()
print(f"\nAll {len(PASSED)} pipeline checks passed")
