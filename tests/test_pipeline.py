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

from docs import hmac_auth  # noqa: E402
from docs.interfaces import MACHINES, HEATER_TEMP, COOLING_VALVE, make_command  # noqa: E402
from middleware import cyber_agent, orchestrator, physical_agent  # noqa: E402
from models.telemetry_generator import generate_stream  # noqa: E402
from pipeline.multi_model_pipeline import MultiModelPipeline  # noqa: E402

orchestrator._forward_decision_to_dashboard = lambda payload: None
PASSED = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    assert cond, name
    PASSED.append(name)


def signed(reg: int, value: float, ip: str = "127.0.0.1", tx: str = "t") -> dict:
    p = hmac_auth.parse_frame(hmac_auth.build_frame(reg, value))
    return make_command(tx, time.time(), ip, 16, reg, p["raw_value"] / 10.0, raw_value=p["raw_value"], auth=p["auth"])


def state(over: dict | None = None) -> dict:
    regs = {m["register"]: m["initial"] for m in MACHINES}
    regs.update(over or {})
    return {"registers": regs, "setpoints": dict(regs), "timestamp": time.time() - 10}


pipe = MultiModelPipeline()
stream = generate_stream(pipe.physical_model.window_size + 5, seed=3)["values"]
for row in stream:
    pipe.ingest_telemetry({i: v for i, v in enumerate(row)})

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
rep = pipe.process_command(signed(COOLING_VALVE, 46.0), state())
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
rep = pipe.process_command(signed(COOLING_VALVE, 46.0), state())
keys_ok = {"decision", "cyber", "physical", "timings_ms", "mode"} <= set(rep)
check("unified report has decision + cyber + physical + timings", keys_ok)
check("cyber section has rule verdict, model score and threat flags",
      {"rule_verdict", "model", "threat_flags"} <= set(rep["cyber"])
      and rep["cyber"]["model"]["anomaly_score"] is not None)
check("physical section has rule verdict, per-machine health and health state",
      len(rep["physical"]["model"]["machines"]) == 10 and rep["physical"]["health_state"] in
      ("HEALTHY", "DEGRADING", "CRITICAL"), rep["physical"]["health_state"])
check("legit command -> PASS", rep["decision"]["verdict"] == "PASS")

cyber_agent.reset_state()
rep = pipe.process_command(signed(HEATER_TEMP, 112.0), state({HEATER_TEMP: 102.0, COOLING_VALVE: 20.0}))
check("cross-register attack still DROPped through pipeline",
      rep["decision"]["verdict"] == "DROP" and "CROSS_REGISTER_VIOLATION" in rep["decision"]["reason"])

cyber_agent.reset_state()
rep = pipe.process_command(make_command("u", time.time(), "127.0.0.1", 6, 2, 46.0, raw_value=460), state())
check("unsigned command still DROPped (HMAC gate unchanged)", rep["decision"]["reason"].startswith("HMAC_MISSING"))

# --- fail closed --------------------------------------------------------------
physical_agent.check_command = lambda c, s: 1 / 0
cyber_agent.reset_state()
rep = pipe.process_command(signed(COOLING_VALVE, 46.0), state())
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
    c = signed(COOLING_VALVE, 46.0 + 3 * i, tx=f"e{i}")
    c["timestamp"] = now + i * 0.02
    last = enf.process_command(c, state())
check("ENFORCE mode: ML anomaly can DROP what rules allowed",
      last["cyber"]["rule_verdict"]["pass"] and last["decision"]["reason"].startswith("ML_ANOMALY"),
      f"score={last['cyber']['model']['anomaly_score']}")
check("MONITOR mode is the default", pipe.enforce_cyber_model is False)

# --- latency --------------------------------------------------------------------
lat = []
for i in range(300):
    cyber_agent.reset_state()
    lat.append(pipe.process_command(signed(COOLING_VALVE, 46.0), state())["timings_ms"]["total"])
check("pipeline p95 latency < 10 ms", np.percentile(lat, 95) < 10,
      f"p50={np.percentile(lat,50):.2f} p95={np.percentile(lat,95):.2f} ms")

pipe.shutdown(); enf.shutdown()
print(f"\nAll {len(PASSED)} pipeline checks passed")
