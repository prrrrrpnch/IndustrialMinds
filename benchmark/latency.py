"""
benchmark/latency.py - reproducible per-hop latency of the REAL pipeline (in-process, deterministic workload).

    python -m benchmark.latency [--n 3000] [--warmup 300] [--repeats 3] [--seed 7] [--out benchmarks]
    python -m benchmark.latency --live            # also the Modbus round trip against a running middleware

WHAT IS MEASURED. Each command goes through MultiModelPipeline.process_command (cyber and physical branches on worker threads,
rule agents, the SWaT-trained physical model on a warm 30 s window fed from the twin, the orchestrator, the packet-trace
builder). Wrapper timers record, per command, the wall time of each hop with time.perf_counter(): cyber rules, cyber model,
physical rules, physical model, orchestrator, trace build, and the total. The two branches overlap, so the per-hop times do not
add up to the total (the `branches` row is their wall time).
WHAT IS NOT. No sockets: this is the decision latency, not the network. --live adds a client-side Modbus round trip.
WORKLOAD. Fixed seed; 70 % legitimate in-bounds commands, 30 % attacks (tamper, unsigned, replay, out-of-bounds, untrusted source,
cross-register); a telemetry sample is fed to the physical model about once per virtual second, so model refreshes are included.
Latencies depend on the machine: the environment is saved next to the numbers.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import threading
import time
from collections import defaultdict
from contextlib import contextmanager
from typing import Any, Dict, List

import numpy as np

from benchmark import workload as W
from benchmark.env import environment
from docs import hmac_auth
from docs.interfaces import CROSS_REGISTER_RULES, MACHINE_BY_REGISTER, to_raw
from middleware import cyber_agent, orchestrator, physical_agent
from middleware import trace as tracer
from pipeline import multi_model_pipeline as mmp

HOPS = ["cyber_rules", "cyber_model", "physical_rules", "physical_model", "orchestrator", "trace_build", "branches", "total"]


def build_commands(n: int, seed: int) -> List[Dict[str, Any]]:
    rng = np.random.default_rng(seed)
    acts, sens = W.actuators(), W.sensors()
    regs = W.nominal_registers()
    items, t = [], W.T0
    for i in range(n):
        t += 0.3
        kind = rng.choice(["legit", "tamper", "unsigned", "replay", "oob", "untrusted", "cross"], p=[0.70, 0.05, 0.05, 0.05, 0.05, 0.05, 0.05])
        reg = int(rng.choice(acts))
        lo, hi = W.bounds(reg)
        cur = regs[reg]
        tx = f"lat-{i}"
        state = W.make_state(regs, t - 10.0)
        if kind == "legit":
            cmd = W.signed(reg, float(np.clip(cur + rng.uniform(-3, 3), lo, hi)), t, tx=tx)
        elif kind == "tamper":
            fr = hmac_auth.build_frame(reg, cur, timestamp_ms=int(t * 1000))
            fr[2] = to_raw(min(hi, cur + 20))
            if fr[2] == to_raw(cur):
                fr[2] += 1
            cmd = W.signed(reg, 0, t, tx=tx, frame=fr)
        elif kind == "unsigned":
            cmd = W.unsigned(reg, cur, t, tx=tx)
        elif kind == "replay":
            fr = hmac_auth.build_frame(reg, cur, timestamp_ms=int(t * 1000))
            items.append({"cmd": W.signed(reg, 0, t - 0.01, tx=tx + "a", frame=fr), "state": state, "kind": "replay-original"})
            cmd = W.signed(reg, 0, t, tx=tx, frame=fr)
        elif kind == "oob":
            cmd = W.signed(reg, float(hi * rng.uniform(1.2, 8)), t, tx=tx)
        elif kind == "untrusted":
            cmd = W.signed(reg, cur, t, ip=f"{W.UNTRUSTED_PREFIX}{int(rng.integers(1, 250))}.{int(rng.integers(1, 250))}", tx=tx)
        else:
            rule = CROSS_REGISTER_RULES[int(rng.integers(len(CROSS_REGISTER_RULES)))]
            (r1, op1, th1), (r2, op2, th2) = rule["conditions"][0], rule["conditions"][1]
            st = dict(regs)
            st[r2] = th2 + 5 if op2 == ">=" else max(0.0, th2 - 5)
            st[r1] = th1 - 3 if op1 == ">=" else th1 + 3
            state = W.make_state(st, t - 10.0)
            cmd = W.signed(r1, th1 + 2 if op1 == ">=" else max(0.0, th1 - 2), t, tx=tx)
        items.append({"cmd": cmd, "state": state, "kind": kind})
    return items


@contextmanager
def instrumented(pipe: mmp.MultiModelPipeline, sink: Dict[str, Dict[str, float]]):
    """Wrap the hop functions with perf_counter timers (restored on exit). sink[tx_id][hop] = seconds."""
    local = threading.local()          # the physical branch runs rules then the model on one worker thread

    def wrap(owner, name, hop, tx_of):
        orig = getattr(owner, name)

        def timed(*a, **k):
            t = time.perf_counter()
            try:
                return orig(*a, **k)
            finally:
                tx = tx_of(*a, **k)
                local.tx = tx
                sink[tx][hop] = time.perf_counter() - t
        setattr(owner, name, timed)
        return owner, name, orig

    def wrap_model(owner, name, hop):
        orig = getattr(owner, name)

        def timed(*a, **k):
            t = time.perf_counter()
            try:
                return orig(*a, **k)
            finally:
                sink[getattr(local, "tx", "?")][hop] = time.perf_counter() - t
        setattr(owner, name, timed)
        return owner, name, orig

    patches = [
        wrap(cyber_agent, "check", "cyber_rules", lambda cmd: cmd["tx_id"]),
        wrap(physical_agent, "check_command", "physical_rules", lambda cmd, st: cmd["tx_id"]),
        wrap(pipe.cyber_model, "evaluate_payload", "cyber_model", lambda cmd, st: cmd["tx_id"]),
        wrap_model(pipe.physical_model, "assess", "physical_model"),
        wrap(orchestrator, "decide", "orchestrator", lambda c, p, *a, **k: p["tx_id"]),
        wrap(tracer, "build_trace", "trace_build", lambda cmd, *a, **k: cmd["tx_id"]),
    ]
    try:
        yield
    finally:
        for owner, name, orig in patches:
            setattr(owner, name, orig)


def stats(xs: List[float]) -> Dict[str, Any]:
    a = np.asarray(xs, float) * 1000.0
    if a.size == 0:
        return {"n": 0}
    return {"n": int(a.size), "mean_ms": round(float(a.mean()), 4), "p50_ms": round(float(np.percentile(a, 50)), 4),
            "p95_ms": round(float(np.percentile(a, 95)), 4), "p99_ms": round(float(np.percentile(a, 99)), 4), "max_ms": round(float(a.max()), 4)}


def run_once(n: int, warmup: int, seed: int, raw_rows: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
    from plc.twin import PlantTwin
    orchestrator._forward_decision_to_dashboard = lambda payload: None     # no dashboard in a benchmark
    pipe = mmp.MultiModelPipeline()
    twin = PlantTwin(noise=True, seed=seed)
    vt = W.T0 - 60.0
    for _ in range(45):                       # warm the 30 s window with real twin telemetry, one sample per virtual second
        for _ in range(10):
            twin.step(0.1)
        vt += 1.0
        pipe.ingest_telemetry(twin.values(), timestamp=vt)
    items = build_commands(n + warmup, seed)
    sink: Dict[str, Dict[str, float]] = defaultdict(dict)
    per: List[Dict[str, Any]] = []
    last_tel = W.T0
    with instrumented(pipe, sink):
        for i, it in enumerate(items):
            cmd = it["cmd"]
            while cmd["timestamp"] - last_tel >= 1.0:           # ~1 Hz telemetry in virtual time
                for _ in range(10):
                    twin.step(0.1)
                last_tel += 1.0
                pipe.ingest_telemetry(twin.values(), timestamp=last_tel)
            cyber_agent.reset_state() if it["kind"] not in ("replay-original",) and i % 50 == 0 else None
            t0 = time.perf_counter()
            rep = pipe.process_command(cmd, it["state"])
            total = time.perf_counter() - t0
            if i < warmup:
                sink.pop(cmd["tx_id"], None)
                continue
            h = sink.pop(cmd["tx_id"], {})
            h["total"] = total
            h["branches"] = rep["timings_ms"]["branches"] / 1000.0
            per.append({"kind": it["kind"], "verdict": rep["decision"]["verdict"], **h})
            if raw_rows is not None:
                raw_rows.append({"i": i, "kind": it["kind"], "verdict": rep["decision"]["verdict"],
                                 **{k: round(h.get(k, float("nan")) * 1000, 4) for k in HOPS}})
    pipe.shutdown()
    by_verdict = defaultdict(list)
    for r in per:
        by_verdict[r["verdict"]].append(r["total"])
    return {"commands": len(per), "hops": {h: stats([r[h] for r in per if h in r]) for h in HOPS},
            "total_by_verdict": {v: stats(x) for v, x in sorted(by_verdict.items())},
            "verdict_counts": {v: len(x) for v, x in sorted(by_verdict.items())}}


def run_live(n: int = 300) -> Dict[str, Any]:
    """Client-side round trip of a signed FC16 write to a RUNNING middleware (includes sockets and the Modbus server)."""
    from pymodbus.client import ModbusTcpClient
    from docs import netconfig
    from docs.interfaces import FRAME_BASE, MV101
    c = ModbusTcpClient(netconfig.MIDDLEWARE_HOST, port=netconfig.MIDDLEWARE_PORT, timeout=2)
    if not c.connect():
        return {"status": "NOT RUN: no middleware reachable at the configured address"}
    xs = []
    try:
        for i in range(n):
            v = 50.0 + (i % 5) * 0.1
            t = time.perf_counter()
            c.write_registers(address=FRAME_BASE, values=hmac_auth.build_frame(MV101, v), slave=1)
            xs.append(time.perf_counter() - t)
            time.sleep(0.25)              # stay under the 5 requests/s source limit
    finally:
        c.close()
    return {"status": "OK", "writes": n, "round_trip": stats(xs)}


def run(n: int = 3000, warmup: int = 300, repeats: int = 3, seed: int = 7, live: bool = False, out: str | None = None) -> Dict[str, Any]:
    raw: List[Dict[str, Any]] = []
    runs = [run_once(n, warmup, seed + r, raw if r == 0 else None) for r in range(repeats)]
    agg: Dict[str, Any] = {}
    for h in HOPS:
        p95 = [r["hops"][h]["p95_ms"] for r in runs if r["hops"][h].get("n")]
        mean = [r["hops"][h]["mean_ms"] for r in runs if r["hops"][h].get("n")]
        if mean:
            agg[h] = {"mean_ms": round(float(np.mean(mean)), 4), "mean_ms_min_max_over_repeats": [min(mean), max(mean)],
                      "p95_ms": round(float(np.mean(p95)), 4), "p95_ms_min_max_over_repeats": [min(p95), max(p95)],
                      "p99_ms": round(float(np.mean([r["hops"][h]["p99_ms"] for r in runs])), 4),
                      "p50_ms": round(float(np.mean([r["hops"][h]["p50_ms"] for r in runs])), 4)}
    result = {"label": "In-process decision latency of the real pipeline on a constructed workload (no sockets).",
              "config": {"commands_per_repeat": n, "warmup": warmup, "repeats": repeats, "seed": seed,
                         "mix": "70% legitimate, 30% attacks (tamper, unsigned, replay, out-of-bounds, untrusted source, cross-register)"},
              "hops": agg, "repeats": [{"seed": seed + i, **r} for i, r in enumerate(runs)], "environment": environment()}
    if live:
        result["live_modbus_round_trip"] = run_live()
    if out:
        os.makedirs(out, exist_ok=True)
        with open(os.path.join(out, "latency_raw.csv"), "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=["i", "kind", "verdict"] + HOPS)
            w.writeheader()
            w.writerows(raw)
    return result


def main() -> None:
    ap = argparse.ArgumentParser(description="Reproducible per-hop latency benchmark.")
    ap.add_argument("--n", type=int, default=3000)
    ap.add_argument("--warmup", type=int, default=300)
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--live", action="store_true")
    ap.add_argument("--out", default="benchmarks")
    a = ap.parse_args()
    res = run(a.n, a.warmup, a.repeats, a.seed, a.live, a.out)
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, "latency.json"), "w") as fh:
        json.dump(res, fh, indent=2)
    print(f"{'hop':<16}{'mean':>9}{'p50':>9}{'p95':>9}{'p99':>9}   (ms; mean of {a.repeats} repeats)")
    for h, s in res["hops"].items():
        print(f"{h:<16}{s['mean_ms']:>9.4f}{s['p50_ms']:>9.4f}{s['p95_ms']:>9.4f}{s['p99_ms']:>9.4f}")
    print(f"\nWrote {a.out}/latency.json and latency_raw.csv")


if __name__ == "__main__":
    main()
