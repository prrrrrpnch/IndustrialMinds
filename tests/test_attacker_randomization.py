"""
tests/test_attacker_randomization.py - Phase 8 Definition of Done: the attacker produces measurably varying
attack parameters (not identical payloads each run). Offline: no network, plans only (+ in-process agents).

    python -m tests.test_attacker_randomization            # prints the distribution table
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from collections import Counter

os.environ.setdefault("IM_LOG_DIR", tempfile.mkdtemp(prefix="im-atk-"))

import numpy as np  # noqa: E402

from attacker import scenarios  # noqa: E402
from attacker.scenarios import TYPES, make_plan  # noqa: E402
from core import hmac_auth# noqa: E402
from core.interfaces import ACTUATOR_REGISTERS, MACHINES, MACHINE_BY_REGISTER, make_command  # noqa: E402
from core.netconfig import LOOPBACK  # noqa: E402
from middleware import cyber_agent, orchestrator  # noqa: E402
from pipeline.multi_model_pipeline import MultiModelPipeline  # noqa: E402

orchestrator._forward_decision_to_dashboard = lambda payload: None
fails = 0
N = 200


def check(name: str, cond: bool, detail: str = "") -> None:
    global fails
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    fails += 0 if cond else 1


def numeric_params(p: dict) -> dict:
    out = {}
    for k, v in p.items():
        if isinstance(v, bool):
            continue
        if isinstance(v, (int, float)):
            out[k] = float(v)
    return out


print(f"DISTRIBUTION CHECK ({N} runs per type, seeds 0..{N - 1})")
plans = {t: [make_plan(t, s) for s in range(N)] for t in TYPES}
for t, ps in plans.items():
    targets = Counter(p["params"].get("target") or p["params"].get("rule") for p in ps)
    nums = {k: [numeric_params(p["params"]).get(k) for p in ps] for k in numeric_params(ps[0]["params"])}
    cols = {k: [x for x in v if x is not None] for k, v in nums.items()}
    print(f"\n  {t}  [{TYPES[t]}]  distinct targets: {len(targets)}")
    for k, v in cols.items():
        print(f"      {k:<22} min {min(v):9.3f}  median {float(np.median(v)):9.3f}  max {max(v):9.3f}  std {float(np.std(v)):8.3f}  unique {len(set(v))}")
    uniq_payloads = len({json.dumps(p["steps"], sort_keys=True) for p in ps})
    check(f"{t}: payloads differ between runs", uniq_payloads >= 0.95 * N, f"{uniq_payloads}/{N} unique step lists")
    check(f"{t}: target varies", len(targets) >= (3 if t != "cross-register" else 4), f"{len(targets)} distinct")
    varying = [k for k, v in cols.items() if len(set(v)) > 1 and float(np.std(v)) > 0]
    check(f"{t}: at least 2 numeric parameters vary (timing / intensity / size)", len(varying) >= 2, ",".join(varying))

print("\nCORRECTNESS")
check("same (type, seed) gives the same plan", all(make_plan(t, 11) == make_plan(t, 11) for t in TYPES))
check("different seeds give different plans", all(make_plan(t, 11) != make_plan(t, 12) for t in TYPES))
check("every plan is labelled swat-derived or synthetic-extension, and says where its ranges came from",
      all(p["origin"] in ("swat-derived", "synthetic-extension") and p["ranges_from"] for ps in plans.values() for p in ps))
check("origins match the documented split",
      {t for t, o in TYPES.items() if o == "synthetic-extension"} == {"flood", "replay", "impossible-command"})
reg_ok = all(s["register"] in ACTUATOR_REGISTERS for ps in plans.values() for p in ps for s in p["steps"])
check("randomised attacks target actuator registers only (sensor writes stay a fixed named probe)", reg_ok)
check("step times are non-decreasing and values representable on the wire (<= 6553.5, >= 0)",
      all(all(a["t"] <= b["t"] for a, b in zip(p["steps"], p["steps"][1:])) and all(0 <= s["value"] <= 6553.5 for s in p["steps"])
          for ps in plans.values() for p in ps))
inb = all(MACHINE_BY_REGISTER[s["register"]]["min"] <= s["value"] <= MACHINE_BY_REGISTER[s["register"]]["max"]
          for t in ("freeze", "ramp", "cross-register", "flood", "replay") for p in plans[t] for s in p["steps"])
check("freeze/ramp/cross-register/flood/replay values stay inside the register bounds (only impossible-command leaves them)", inb)
check("impossible-command values are all out of bounds",
      all(s["value"] > MACHINE_BY_REGISTER[s["register"]]["max"] for p in plans["impossible-command"] for s in p["steps"]))
check("flood offered rate exceeds the cyber rate limit", all(p["params"]["offered_rate_per_s"] > cyber_agent.RATE_LIMIT_PER_SEC
                                                             for p in plans["flood"]))
prof = {"attacker_ranges": {"ramp_total_fraction": [0.5, 0.6]}}
check("a SWaT attack profile overrides the ramp range and is reported",
      all(make_plan("ramp", s, profile=prof)["ranges_from"].startswith("docs/swat_attack_profile") for s in range(3)))

print("\nRULE SANITY (synthetic-extension types through the REAL agents, in-process)")
pipe = MultiModelPipeline()


def to_cmd(step: dict, frame=None, ip: str = LOOPBACK) -> dict:
    frame = frame or hmac_auth.build_frame(step["register"], step["value"])
    p = hmac_auth.parse_frame(frame)
    return make_command("t", time.time(), ip, 16, step["register"], p["raw_value"] / 10.0, raw_value=p["raw_value"], auth=p["auth"]), frame


def state() -> dict:
    regs = {m["register"]: m["initial"] for m in MACHINES}
    return {"registers": regs, "setpoints": dict(regs), "timestamp": time.time() - 10}


def run(plan: dict) -> list:
    cyber_agent.reset_state()
    sent, out = {}, []
    for i, st in enumerate(plan["steps"]):                     # no sleeping: offered rate is what the limiter sees
        cmd, fr = to_cmd(st, sent.get(st.get("ref")))
        sent[i] = fr
        out.append(pipe.process_command(cmd, state())["decision"])
    return out


imp = [run(plans["impossible-command"][s]) for s in range(15)]
check("impossible-command: every randomised run is DROPped", all(any(d["verdict"] == "DROP" for d in r) for r in imp))
fl = [run(plans["flood"][s]) for s in range(15)]
check("flood: every randomised run trips RATE_LIMIT_EXCEEDED", all(any(d["reason"] == "RATE_LIMIT_EXCEEDED" for d in r) for r in fl))
rp = [run(plans["replay"][s]) for s in range(15)]
# (run() sends without sleeping, so a long replay burst can also meet the rate limiter first; both are refusals)
check("replay: every replayed frame is refused and every run is caught by REPLAY_DETECTED at least once",
      all(all(d["verdict"] == "DROP" for d in r[1:]) and any(d["reason"].startswith("REPLAY") for d in r[1:]) for r in rp),
      repr(Counter(d["reason"].split(":")[0] for r in rp for d in r[1:]).most_common(2)))

print("\nALL PASS" if fails == 0 else f"\n{fails} CHECK(S) FAILED")
raise SystemExit(1 if fails else 0)
