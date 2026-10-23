"""
benchmark/invariants_ab.py - what did adding the physical-invariant rules change in the running system? A before/after on the digital twin.

    python -m benchmark.invariants_ab [--scenario-seeds 5] [--healthy-hours 3] [--healthy-seeds 3]

BEFORE = the system as it was: the SWaT-trained v2 model's flag OR the measured-envelope rule (the two physical alarm sources).
AFTER  = BEFORE OR the invariant rules (config/invariants_twin.json at its calibrated theta). Everything else is identical, so the difference
is exactly what the invariants add. Measured on the TWIN: a synthetic plant, so this says what the change does to THIS demonstration system and
nothing about SWaT. The model is SWaT-trained and the invariants are twin-fitted (SWaT-fitted rules do not describe the twin), which is disclosed
in the report. Real-SWaT detection of the invariants is a separate, still-open measurement (tools/fit_invariants --data-dir).

Measured: detection rate and delay of five synthetic actuator attacks over several seeds, false-alarm episodes per hour on fresh healthy runs,
and the cost added to a decision (end-to-end process_command latency with and without the monitor, and the monitor's per-sample update).
Writes docs/reports/invariants_ab_report.md and benchmarks/invariants_ab.json.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional

ROOT = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
os.environ.setdefault("IM_LOG_DIR", tempfile.mkdtemp(prefix="im-ab-"))

import numpy as np  # noqa: E402

from benchmark.env import environment  # noqa: E402
from core.interfaces import MACHINE_BY_NAME, MACHINES  # noqa: E402
from models.invariant_monitor import DEFAULT_FILE, InvariantMonitor  # noqa: E402
from models.physical_model_v2 import load_physical_model  # noqa: E402
from plc.twin import PlantTwin  # noqa: E402
from swat import scoring as SC  # noqa: E402
from swat.invariants import InvariantSet  # noqa: E402
from tools.twin_domain_gap import SCENARIOS  # noqa: E402

OUT_JSON = os.path.join(ROOT, "benchmarks", "invariants_ab.json")
OUT_MD = os.path.join(ROOT, "docs", "reports", "invariants_ab_report.md")
SETTLE_S = 600
AFTER_S = 900


def _reg(name: str) -> int:
    return MACHINE_BY_NAME[name]["register"]


def _freeze(name: str):
    def f(regs: Dict[int, float], k: int, held: Dict[str, float]) -> None:
        held.setdefault(name, regs[_reg(name)])
        regs[_reg(name)] = held[name]
    return f


def _bias(name: str, delta: float):
    def f(regs: Dict[int, float], k: int, held: Dict[str, float]) -> None:
        regs[_reg(name)] += delta
    return f


def _ramp(name: str, per_s: float):
    def f(regs: Dict[int, float], k: int, held: Dict[str, float]) -> None:
        regs[_reg(name)] += per_s * k
    return f


def _dead(name: str):
    def f(regs: Dict[int, float], k: int, held: Dict[str, float]) -> None:
        regs[_reg(name)] = 0.0
    return f


# SENSOR TAMPERING: the plant is untouched, the readings the middleware sees are altered (a spoofed, frozen or failed sensor).
SENSOR_ATTACKS = {
    "freeze LIT101 (level sensor stuck at its last value)": _freeze("LIT101"),
    "bias FIT201 +0.4 m3/h (flow meter reads high)": _bias("FIT201", 0.4),
    "ramp LIT301 +0.3 mm/s (level creeps up, 270 mm in 15 min)": _ramp("LIT301", 0.3),
    "step LIT401 +100 mm (level jumps)": _bias("LIT401", 100.0),
    "FIT101 reads zero (inflow meter fails)": _dead("FIT101"),
}


def _sources(model_report: Dict[str, Any], mon_report: Dict[str, Any]) -> Dict[str, bool]:
    ok = model_report.get("status") == "OK"
    return {"model": bool(ok and model_report.get("threat_flag")), "envelope": bool(ok and model_report.get("bounds_violations")),
            "invariants": bool(mon_report.get("status") == "OK" and mon_report.get("threat_flag"))}


def run_twin(model, inv: InvariantSet, seed: int, seconds: int, changes: Optional[Dict[str, float]] = None, change_at: Optional[int] = None,
             tamper=None) -> Dict[str, List[int]]:
    """Per-second alarm times by source over one twin run (sensor noise on), with an optional synthetic actuator attack at `change_at`."""
    tw = PlantTwin(noise=True, seed=seed)
    mon = InvariantMonitor(inv, inv.theta, "ab")
    model.reset_window()
    times: Dict[str, List[int]] = {"model": [], "envelope": [], "invariants": []}
    held: Dict[str, float] = {}
    for t in range(seconds):
        if changes and change_at is not None and t == change_at:
            for tag, v in changes.items():
                tw.set_target(MACHINE_BY_NAME[tag]["register"], v)
        for _ in range(10):
            tw.step(0.1)
        regs = tw.values()
        if tamper is not None and change_at is not None and t >= change_at:
            tamper(regs, t - change_at, held)
        model.update(regs, timestamp=float(t))
        mon.update(regs, timestamp=float(t))
        src = _sources(model.assess(), mon.assess())
        for k, on in src.items():
            if on:
                times[k].append(t)
    return times


def _first_after(ts: List[int], t0: int) -> Optional[int]:
    after = [t - t0 for t in ts if t >= t0]
    return after[0] if after else None


def _episodes(ts: List[int]) -> int:
    return SC.count_episodes(np.array(ts, dtype=float), np.ones(len(ts), bool)) if ts else 0


def scenarios(model, inv: InvariantSet, seeds: List[int], family: str = "actuator") -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    items = SCENARIOS.items() if family == "actuator" else SENSOR_ATTACKS.items()
    for name, spec in items:
        rows = []
        for sd in seeds:
            tm = (run_twin(model, inv, sd, SETTLE_S + AFTER_S, spec, SETTLE_S) if family == "actuator"
                  else run_twin(model, inv, sd, SETTLE_S + AFTER_S, {}, SETTLE_S, tamper=spec))
            first = {k: _first_after(v, SETTLE_S) for k, v in tm.items()}
            before = [x for x in (first["model"], first["envelope"]) if x is not None]
            after = [x for x in (first["model"], first["envelope"], first["invariants"]) if x is not None]
            pre = {k: sum(1 for t in v if t < SETTLE_S) for k, v in tm.items()}
            rows.append({"seed": sd, "first": first, "before": min(before) if before else None, "after": min(after) if after else None, "alarm_seconds_before_attack": pre})
        out[name] = {"changes": spec if family == "actuator" else "sensor tampering", "runs": rows}
    return out


def healthy(model, inv: InvariantSet, seeds: List[int], hours: float) -> Dict[str, Any]:
    secs = int(hours * 3600)
    per, tot = [], {"model": 0, "envelope": 0, "invariants": 0, "before": 0, "after": 0}
    for sd in seeds:
        tm = run_twin(model, inv, sd, secs)
        before = sorted(set(tm["model"]) | set(tm["envelope"]))
        after = sorted(set(before) | set(tm["invariants"]))
        row = {"seed": sd, "hours": hours, **{k: _episodes(v) for k, v in tm.items()}, "before": _episodes(before), "after": _episodes(after),
               "seconds_alarmed": {"before": len(before), "after": len(after), "invariants": len(tm["invariants"])}}
        per.append(row)
        for k in tot:
            tot[k] += row[k]
    h = hours * len(seeds)
    return {"hours_total": h, "per_seed": per, "episodes_per_hour": {k: round(v / h, 3) for k, v in tot.items()}}


def overhead(n: int = 1500) -> Dict[str, Any]:
    """Cost added to a decision: process_command end to end with and without the monitor, and the monitor's own per-sample update."""
    from core import hmac_auth
    from core.interfaces import P101, make_command
    from middleware import cyber_agent, orchestrator
    from pipeline.multi_model_pipeline import MultiModelPipeline
    orchestrator._forward_decision_to_dashboard = lambda payload: None
    inv = InvariantSet.load(DEFAULT_FILE)
    S = {m["register"]: m["initial"] for m in MACHINES}
    state = {"registers": dict(S), "setpoints": dict(S), "timestamp": time.time() - 10}

    def signed(i: int):
        p = hmac_auth.parse_frame(hmac_auth.build_frame(P101, 70.0))
        return make_command(f"ab{i}", time.time(), "127.0.0.1", 16, P101, p["raw_value"] / 10.0, raw_value=p["raw_value"], auth=p["auth"])

    p_off, mon = MultiModelPipeline(invariants=None), InvariantMonitor(inv, inv.theta)
    p_on = MultiModelPipeline(invariants=mon)
    for pipe in (p_off, p_on):
        for t in range(200):                                             # fill both windows so the models are warm
            pipe.ingest_telemetry({k: v for k, v in S.items()}, timestamp=10_000.0 + t)
    off, on = [], []
    for i in range(n):                                                   # interleaved, so drift in machine load hits both equally
        for pipe, sink in ((p_off, off), (p_on, on)) if i % 2 == 0 else ((p_on, on), (p_off, off)):
            cyber_agent.reset_state()
            c = signed(i)
            t0 = time.perf_counter()
            pipe.process_command(c, state)
            sink.append((time.perf_counter() - t0) * 1000.0)
    regs = {m["register"]: m["initial"] for m in MACHINES}
    t0 = time.perf_counter()
    m2 = InvariantMonitor(inv, inv.theta)
    for t in range(600):
        m2.update(regs, timestamp=float(t))
    update_ms = (time.perf_counter() - t0) * 1000.0 / 600
    t0 = time.perf_counter()
    for _ in range(20000):
        m2.merge_into({"status": "OK", "threat_flag": False, "flagged_by": []})
    merge_us = (time.perf_counter() - t0) * 1e6 / 20000
    q = lambda xs, p: round(float(np.percentile(xs, p)), 3)
    return {"n": n, "without": {"p50": q(off, 50), "p95": q(off, 95), "p99": q(off, 99), "mean": round(statistics.mean(off), 3)},
            "with": {"p50": q(on, 50), "p95": q(on, 95), "p99": q(on, 99), "mean": round(statistics.mean(on), 3)},
            "monitor_update_ms_per_sample": round(update_ms, 3), "merge_into_us": round(merge_us, 2), "invariants": len(inv)}


def summarise(scn: Dict[str, Any]) -> Dict[str, Any]:
    rows = [r for s in scn.values() for r in s["runs"]]
    n = len(rows)
    det = lambda key: sum(1 for r in rows if (r[key] if key in ("before", "after") else r["first"][key]) is not None)
    med = lambda key: statistics.median([(r[key] if key in ("before", "after") else r["first"][key]) for r in rows if (r[key] if key in ("before", "after") else r["first"][key]) is not None] or [float("nan")])
    newly = sum(1 for r in rows if r["before"] is None and r["after"] is not None)
    paired = [(r["before"], r["after"]) for r in rows if r["before"] is not None]
    return {"runs": n, "newly_detected_by_invariants": newly,
            "paired_median_delay_s": None if not paired else {"before": statistics.median(b for b, _ in paired), "after": statistics.median(a for _, a in paired), "runs": len(paired)},
            **{k: {"detected": det(k), "rate": round(det(k) / n, 3), "median_delay_s": None if det(k) == 0 else round(med(k), 1)}
                          for k in ("model", "envelope", "invariants", "before", "after")}}


def _val(r: Dict[str, Any], key: str):
    return r[key] if key in ("before", "after") else r["first"][key]


def _family(title: str, scn: Dict[str, Any], sm: Dict[str, Any]) -> List[str]:
    L = [f"## {title}", "", "| alarm source | attacks detected | median delay among the runs it detected (s) |", "|---|---|---|"]
    for k, label in (("model", "v2 model flag"), ("envelope", "measured-envelope rule"), ("invariants", "physical invariants"), ("before", "**BEFORE** (model OR envelope)"), ("after", "**AFTER** (plus invariants)")):
        L.append(f"| {label} | {sm[k]['detected']}/{sm['runs']} ({sm[k]['rate']:.0%}) | {sm[k]['median_delay_s']} |")
    L += ["", "| attack | runs | model | envelope | invariants | BEFORE detected / median delay (s) | AFTER detected / median delay (s) |", "|---|---|---|---|---|---|---|"]
    for name, s in scn.items():
        runs = s["runs"]
        cnt = lambda key: sum(1 for r in runs if _val(r, key) is not None)
        md = lambda key: (lambda xs: "-" if not xs else f"{statistics.median(xs):.0f}")([_val(r, key) for r in runs if _val(r, key) is not None])
        L.append(f"| {name} | {len(runs)} | {cnt('model')} | {cnt('envelope')} | {cnt('invariants')} | {cnt('before')} / {md('before')} | {cnt('after')} / {md('after')} |")
    return L + [""]


def render(res: Dict[str, Any]) -> str:
    env, ov, hl, sm, ss = res["environment"], res["overhead"], res["healthy"], res["summary"], res["sensor_summary"]
    d = lambda a, b: "" if a is None or b is None else format(b - a, "+.1f")
    L = ["# What the physical-invariant rules changed: before / after on the twin", "",
         "> **TWIN MEASUREMENT (synthetic plant) - NOT SWaT detection performance.** The model is SWaT-trained; the invariants are fitted on the twin because SWaT-fitted rules do not describe its time-compressed tank dynamics.", "",
         f"Generated by `python -m benchmark.invariants_ab` on {env['generated_utc']} UTC, commit `{env['git_commit']}`{' (dirty tree)' if env['git_dirty'] else ''}, Python {env['python']}. "
         "**BEFORE** = v2 model flag OR the measured-envelope rule (the system as it was). **AFTER** = BEFORE OR the invariant rules at their calibrated theta "
         f"({res['theta']}). Nothing else differs, so the difference is exactly what the invariants add. Two kinds of synthetic attack, {sm['runs']} runs each "
         f"(5 attacks x {sm['runs'] // 5} seeds): **actuator attacks** change the plant itself; **sensor tampering** alters only what the middleware reads (freeze, bias, ramp, step, dead meter).", "",
         "## Headline", "", "| metric | before | after | change |", "|---|---|---|---|",
         f"| actuator attacks detected | {sm['before']['detected']}/{sm['runs']} ({sm['before']['rate']:.0%}) | {sm['after']['detected']}/{sm['runs']} ({sm['after']['rate']:.0%}) | {sm['after']['detected'] - sm['before']['detected']:+d} |",
         f"| actuator attacks: runs caught ONLY thanks to the invariants | - | - | {sm['newly_detected_by_invariants']} |",
         f"| actuator attacks: median delay on the runs BEFORE already caught (s) | {sm['paired_median_delay_s']['before'] if sm['paired_median_delay_s'] else '-'} | {sm['paired_median_delay_s']['after'] if sm['paired_median_delay_s'] else '-'} | {d(sm['paired_median_delay_s']['before'], sm['paired_median_delay_s']['after']) if sm['paired_median_delay_s'] else ''} |",
         f"| **sensor tampering detected** | {ss['before']['detected']}/{ss['runs']} ({ss['before']['rate']:.0%}) | {ss['after']['detected']}/{ss['runs']} ({ss['after']['rate']:.0%}) | {ss['after']['detected'] - ss['before']['detected']:+d} |",
         f"| sensor tampering: runs caught ONLY thanks to the invariants | - | - | {ss['newly_detected_by_invariants']} |",
         f"| sensor tampering: median delay on the runs BEFORE already caught (s) | {ss['paired_median_delay_s']['before'] if ss['paired_median_delay_s'] else '-'} | {ss['paired_median_delay_s']['after'] if ss['paired_median_delay_s'] else '-'} | {d(ss['paired_median_delay_s']['before'], ss['paired_median_delay_s']['after']) if ss['paired_median_delay_s'] else ''} |",
         f"| false-alarm episodes per healthy hour ({hl['hours_total']:.0f} h, fresh runs) | {hl['episodes_per_hour']['before']} | {hl['episodes_per_hour']['after']} | {hl['episodes_per_hour']['after'] - hl['episodes_per_hour']['before']:+.3f} |",
         f"| decision latency p50 / p95 (ms, process_command, n={ov['n']}) | {ov['without']['p50']} / {ov['without']['p95']} | {ov['with']['p50']} / {ov['with']['p95']} | {ov['with']['p50'] - ov['without']['p50']:+.3f} / {ov['with']['p95'] - ov['without']['p95']:+.3f} |", "",
         f"Cost of the monitor itself: {ov['monitor_update_ms_per_sample']} ms per telemetry sample (once per second, off the decision path) and {ov['merge_into_us']} microseconds per decision to merge its cached verdict; {ov['invariants']} invariants loaded. "
         "Both pipelines were timed interleaved on the same machine; a difference of a few hundredths of a millisecond in either direction is noise.", ""]
    L += _family("Actuator attacks (the plant itself is changed)", res["scenarios"], sm)
    L += _family("Sensor tampering (only the readings are altered)", res["sensor_scenarios"], ss)
    L += ["## False alarms on healthy runs", "", "| seed | hours | model | envelope | invariants | BEFORE episodes | AFTER episodes |", "|---|---|---|---|---|---|---|"]
    for r in hl["per_seed"]:
        L.append(f"| {r['seed']} | {r['hours']} | {r['model']} | {r['envelope']} | {r['invariants']} | {r['before']} | {r['after']} |")
    L += ["", "## How to read this", "",
          "- A gain appears only where the previous system was blind. If BEFORE already catches an attack, the invariants add nothing for it, and that is a legitimate result.",
          "- The twin is not SWaT: the model's numbers on the twin are a domain-gap measurement, and the invariants were fitted on the twin itself. Neither says anything about SWaT.",
          "- **Still open: invariant detection and false alarms on real SWaT** (`python -m tools.fit_invariants --data-dir <SWaT>`, `python -m benchmark.swat_protocol --data-dir <SWaT>`). Until that runs, no SWaT improvement can be claimed for this change.",
          "- The shipped v2 model, its threshold and the rule layers are unchanged by this build: its SWaT numbers (F1 0.485, 8/10 attacks, 1.17 false-alarm episodes per hour) are exactly what they were.", ""]
    return "\n".join(L)


def main() -> None:
    ap = argparse.ArgumentParser(description="Before/after of the invariant rules on the digital twin.")
    ap.add_argument("--scenario-seeds", type=int, default=5)
    ap.add_argument("--healthy-hours", type=float, default=3.0)
    ap.add_argument("--healthy-seeds", type=int, default=3)
    ap.add_argument("--latency-n", type=int, default=1500)
    ap.add_argument("--out-dir", help="write here instead of the repo report paths")
    a = ap.parse_args()
    model = load_physical_model()
    if model.status != "OK":
        raise SystemExit(f"the physical model is not usable (status {model.status}); the before/after needs it")
    inv = InvariantSet.load(DEFAULT_FILE)
    t0 = time.time()
    seeds = [21 + i for i in range(a.scenario_seeds)]
    scn = scenarios(model, inv, seeds, "actuator")
    sens = scenarios(model, inv, seeds, "sensor")
    hl = healthy(model, inv, [41 + i for i in range(a.healthy_seeds)], a.healthy_hours)
    ov = overhead(a.latency_n)
    res = {"label": "TWIN MEASUREMENT - NOT SWaT performance", "theta": inv.theta, "invariant_file": os.path.relpath(DEFAULT_FILE, ROOT), "model": getattr(model, "variant", "v2"),
           "scenarios": scn, "sensor_scenarios": sens, "summary": summarise(scn), "sensor_summary": summarise(sens), "healthy": hl, "overhead": ov, "seconds": round(time.time() - t0, 1), "environment": environment()}
    jpath, mpath = (OUT_JSON, OUT_MD) if not a.out_dir else (os.path.join(a.out_dir, "invariants_ab.json"), os.path.join(a.out_dir, "invariants_ab_report.md"))
    os.makedirs(os.path.dirname(jpath), exist_ok=True)
    os.makedirs(os.path.dirname(mpath), exist_ok=True)
    with open(jpath, "w") as fh:
        json.dump(res, fh, indent=1, default=float)
    md = render(res)
    with open(mpath, "w") as fh:
        fh.write(md)
    print(md)
    print(f"\nWrote {jpath} and {mpath} in {res['seconds']} s.")


if __name__ == "__main__":
    main()
