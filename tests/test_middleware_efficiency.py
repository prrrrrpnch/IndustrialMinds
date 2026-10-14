"""
tests/test_middleware_efficiency.py - middleware stress test and benchmark.

Pushes thousands of multivariate payloads (a 20-register telemetry sample plus
a SCADA command) through the REAL middleware entry point
(middleware_server._process_write -> MultiModelPipeline -> agents + models ->
orchestrator -> PLC forward), and measures:

    * per-message service latency: mean, p50, p95, p99, max
    * end-to-end latency including queue wait, queue depth (backpressure)
    * throughput: fixed-rate run (stability) and back-to-back run (capacity)
    * RSS memory growth per 1000 messages (leak check) and CPU usage

Phases
    1. sustained  - a producer thread offers payloads at --rate msg/s into a
                    queue, one consumer thread (like the middleware's single
                    Modbus event loop) drains it.
    2. capacity   - payloads processed back-to-back to find max throughput.

Traffic mix: legitimate signed commands from --sources SCADA hosts, plus
unsigned / tampered / forged / out-of-bounds / untrusted-source / write-to-sensor /
cross-register attacks (--attack-ratio).

Results: logs/middleware_benchmark_<timestamp>.json (full breakdown) and one
appended row in logs/middleware_benchmark.csv. Exit code 1 if a target fails.

    python -m models.train_models                 # once
    python -m tests.test_middleware_efficiency    # defaults: 2400 sustained + 2000 capacity

What is NOT measured: the PLC write is an in-memory stub (use --live-plc to
forward to a real PLC on :5020) and dashboard forwarding is off unless
--with-dashboard, so the numbers are the middleware's own processing cost.
"""

from __future__ import annotations

import argparse
import csv
import gc
import json
import logging
import os
import queue
import sys
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(PROJECT_ROOT, "logs")

sys.path.insert(0, PROJECT_ROOT)

import importlib  # noqa: E402

from docs import netconfig  # noqa: E402
from docs.netconfig import LOOPBACK  # noqa: E402  documented loopback default

# Must be set before middleware modules are imported (read at import time).
# Legit SCADA hosts are 127.20.x.x; untrusted attackers use 127.30.x.x.
TRUSTED_NET = "127.20.0.0/16"
os.environ.setdefault("IM_TRUSTED_SOURCES", LOOPBACK + "," + TRUSTED_NET)
os.environ.setdefault("IM_LOG_DIR", os.path.join(LOG_DIR, "benchmark_attack_log"))
importlib.reload(netconfig)   # netconfig already read the env at import; re-read it

import numpy as np  # noqa: E402
import psutil  # noqa: E402

from docs import hmac_auth  # noqa: E402
from docs.interfaces import (  # noqa: E402
    ACTUATOR_REGISTERS, SENSOR_REGISTERS, FRAME_BASE, MACHINES, NUM_REGISTERS,
    P101, P203, to_raw,
)
from middleware import cyber_agent, orchestrator  # noqa: E402
import middleware.middleware_server as mw  # noqa: E402
from models.telemetry_generator import generate_stream  # noqa: E402
from pipeline.multi_model_pipeline import get_pipeline  # noqa: E402

log = logging.getLogger("industrialmind.benchmark")

TARGET_MEAN_MS = 10.0
LEAK_LIMIT_MB_PER_1K = 2.0
THROUGHPUT_CV_LIMIT = 0.15


# ---------------------------------------------------------------------------
# Test doubles for things outside the middleware
# ---------------------------------------------------------------------------

class _OkResult:
    def isError(self) -> bool:
        return False


class InMemoryPLC:
    """Stands in for the PLC Modbus client: accepts writes instantly."""

    def __init__(self) -> None:
        self.writes = 0

    def write_register(self, register: int, raw: int) -> _OkResult:
        self.writes += 1
        return _OkResult()


# ---------------------------------------------------------------------------
# Payload generation
# ---------------------------------------------------------------------------

ATTACK_KINDS = ["unsigned", "tampered", "forged", "out_of_bounds", "untrusted", "cross_register",
                "sensor_write"]


# Normal operation stays inside a safe operating envelope (fraction of range)
# so legitimate traffic never forms an unsafe cross-register combination.
# Every actuator stays within 30..75 % of its range, so no "<=" side of any
# CROSS_REGISTER_RULES entry (<= 10 / <= 20) and no ">=" side (>= 60..80) can
# line up with its partner.
SAFE_ENVELOPE = {reg: (0.3, 0.75) for reg in ACTUATOR_REGISTERS}


def build_payloads(n: int, seed: int, attack_ratio: float, n_sources: int,
                   rate: float = 300.0) -> List[Dict[str, Any]]:
    """
    Each payload = one 20-register telemetry sample + one Modbus write.

    Legitimate traffic behaves like real operators: each SCADA host sends at
    most 4 commands per second (planned at the offered `rate`), never resends
    an identical value, and the plant stays inside SAFE_ENVELOPE.
    """
    rng = np.random.default_rng(seed)
    telemetry = generate_stream(n, seed=seed, failing={8: 0.3, 2: 0.6}, envelopes=SAFE_ENVELOPE)["values"]
    sources = [f"127.20.{i // 250}.{i % 250 + 1}" for i in range(n_sources)]
    recent: Dict[str, List[float]] = {s: [] for s in sources}      # planned send times
    sent: Dict[Tuple[str, int], List[Tuple[float, float]]] = {}      # (ip, reg) -> [(t, value)]
    wrong_key = b"attacker-guessed-key-000000000000000000000"
    payloads: List[Dict[str, Any]] = []

    for i in range(n):
        tel = telemetry[i]
        reg = int(ACTUATOR_REGISTERS[int(rng.integers(len(ACTUATOR_REGISTERS)))])   # only actuators are commanded
        m = MACHINES[reg]
        span = m["max"] - m["min"]
        # Operator setpoints are always inside the machine range, even when the
        # (noisy, wearing) measured value is momentarily outside it.
        value = float(np.clip(tel[reg] + rng.normal(0, 0.01 * span), m["min"], m["max"]))
        value = round(value, 1)
        t_plan = i / rate
        for _ in range(50):
            ip = sources[int(rng.integers(n_sources))]
            recent[ip] = [t for t in recent[ip] if t_plan - t < 1.0]
            if len(recent[ip]) < 4:
                break
        recent[ip].append(t_plan)
        hist = [(t, v) for t, v in sent.get((ip, reg), []) if t_plan - t < 2.5]
        used = {v for _, v in hist}                      # operators don't resend identical setpoints
        if value in used:
            for k in range(1, 1000):
                cands = [round(value + d * 0.1 * k, 1) for d in (1, -1)]
                free = [c for c in cands if m["min"] <= c <= m["max"] and c not in used]
                if free:
                    value = free[0]
                    break
        hist.append((t_plan, value))
        sent[(ip, reg)] = hist
        kind = "normal"
        if rng.random() < attack_ratio:
            kind = ATTACK_KINDS[int(rng.integers(len(ATTACK_KINDS)))]

        # Frames are signed at SEND time (see sign()), like a real SCADA, so
        # the signed timestamp is fresh however long the run is.
        address, fc, sign_value, key, tamper = FRAME_BASE, 16, value, None, False
        if kind == "unsigned":
            address, fc = reg, 6
        elif kind == "tampered":
            tamper = True
        elif kind == "forged":
            key = wrong_key
        elif kind == "out_of_bounds":
            sign_value = m["max"] * 1.5
        elif kind == "untrusted":
            ip = f"127.30.{int(rng.integers(255))}.{int(rng.integers(1, 255))}"
        elif kind == "cross_register":
            # ACID_OVERDOSE_LOW_FLOW: HCl pump P203 creeps up to 80 % (a tiny, in-rate
            # move) while the raw-water pump P101 is at 15 %.
            tel = tel.copy()
            tel[P203], tel[P101] = 79.9, 15.0
            reg, sign_value = P203, 80.0
        elif kind == "sensor_write":
            # signed, trusted, in-bounds - but it targets a read-only sensor register
            reg = int(SENSOR_REGISTERS[int(rng.integers(len(SENSOR_REGISTERS)))])
            sign_value = float(MACHINES[reg]["initial"])

        payloads.append({"kind": kind, "ip": ip, "address": address, "fc": fc, "telemetry": tel,
                         "register": reg, "value": sign_value, "key": key, "tamper": tamper})
    return payloads


# ---------------------------------------------------------------------------
# One message through the real middleware
# ---------------------------------------------------------------------------

def sign(payload: Dict[str, Any]) -> List[int]:
    """What the sender puts on the wire, built at send time."""
    if payload["address"] != FRAME_BASE:
        return [to_raw(payload["value"])]
    frame = hmac_auth.build_frame(payload["register"], payload["value"], key=payload["key"])
    if payload["tamper"]:
        frame[2] = min(65535, frame[2] + 500)
    return frame


def process(payload: Dict[str, Any]) -> Tuple[float, str, str]:
    """Returns (service_ms, verdict, reason code). Signing is the sender's cost, not timed."""
    wire = sign(payload)
    t0 = time.perf_counter()

    # 1. telemetry sample -> middleware state + PhysicalModel window
    with mw._state_lock:
        for reg in range(NUM_REGISTERS):
            mw._plc_state["registers"][reg] = float(payload["telemetry"][reg])
        mw._plc_state["timestamp"] = time.time()
    get_pipeline().ingest_telemetry(mw._plc_state["registers"])

    # 2. Modbus write -> full security pipeline
    before = len(orchestrator._decision_log)
    mw._process_write(payload["address"], wire,
                      {"source_ip": payload["ip"], "source_port": 50000, "function_code": payload["fc"]})

    service_ms = (time.perf_counter() - t0) * 1000.0

    # Emulate the PLC confirming instantly so pending setpoints don't accumulate
    # (plant dynamics are out of scope here - see benchmark/ for detection quality).
    with mw._state_lock:
        mw._pending_commands.clear()

    if len(orchestrator._decision_log) > before:
        decision = orchestrator._decision_log[before]
        verdict, reason = decision["verdict"], str(decision["reason"]).split(":", 1)[0]
    else:
        verdict, reason = "?", "?"
    # Keep the in-memory decision log from growing for the whole run.
    if len(orchestrator._decision_log) > 1000:
        del orchestrator._decision_log[:-10]
    return service_ms, verdict, reason


# ---------------------------------------------------------------------------
# Phases
# ---------------------------------------------------------------------------

def rss_mb(proc: psutil.Process) -> float:
    return proc.memory_info().rss / (1024 * 1024)


def pct(a: List[float], q: float) -> float:
    return float(np.percentile(a, q)) if a else 0.0


def latency_stats(a: List[float]) -> Dict[str, float]:
    return {"mean": round(float(np.mean(a)), 4), "p50": round(pct(a, 50), 4), "p95": round(pct(a, 95), 4),
            "p99": round(pct(a, 99), 4), "max": round(float(np.max(a)), 4), "min": round(float(np.min(a)), 4)}


def run_sustained(payloads: List[Dict[str, Any]], rate: float, proc: psutil.Process) -> Dict[str, Any]:
    q: "queue.Queue[Tuple[float, Dict[str, Any]]]" = queue.Queue()
    service: List[float] = []
    e2e: List[float] = []
    slow: List[List[float]] = []          # [wall-clock time, service ms] for messages > 10 ms
    verdicts: Dict[str, Dict[str, int]] = {}
    drop_reasons: Dict[str, Dict[str, int]] = {}
    depth: List[Tuple[float, int]] = []
    rss: List[Tuple[int, float]] = []
    done_at: List[float] = []
    errors = 0
    stop = threading.Event()

    def producer() -> None:
        start = time.perf_counter()
        for i, p in enumerate(payloads):
            due = start + i / rate
            delay = due - time.perf_counter()
            if delay > 0:
                time.sleep(delay)
            q.put((time.perf_counter(), p))
        stop.set()

    def consumer() -> None:
        nonlocal errors
        n = 0
        while not (stop.is_set() and q.empty()):
            try:
                enq, p = q.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                ms, verdict, reason = process(p)
            except Exception:
                errors += 1
                log.exception("message failed")
                continue
            now = time.perf_counter()
            if ms > 10.0:
                slow.append([round(time.time(), 3), round(ms, 2)])
            service.append(ms)
            e2e.append((now - enq) * 1000.0)
            done_at.append(now)
            k = verdicts.setdefault(p["kind"], {})
            k[verdict] = k.get(verdict, 0) + 1
            if verdict == "DROP":
                r = drop_reasons.setdefault(p["kind"], {})
                r[reason] = r.get(reason, 0) + 1
            n += 1
            if n % 50 == 0 or (stop.is_set() and q.empty()):
                depth.append((now, q.qsize()))
            if n % 200 == 0:
                rss.append((n, rss_mb(proc)))
                log.info("sustained %5d/%d  depth=%d  p95=%.2fms  rss=%.1fMB",
                         n, len(payloads), q.qsize(), pct(service[-200:], 95), rss[-1][1])

    gc.collect()
    rss.append((0, rss_mb(proc)))
    proc.cpu_percent(None)
    cpu0 = proc.cpu_times()
    t0 = time.perf_counter()
    threads = [threading.Thread(target=producer), threading.Thread(target=consumer)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    wall = time.perf_counter() - t0
    cpu_pct = proc.cpu_percent(None)
    cpu1 = proc.cpu_times()

    # throughput stability over 1-second windows
    windows = np.floor((np.array(done_at) - done_at[0])).astype(int) if done_at else np.array([])
    per_sec = np.bincount(windows)[:-1] if len(windows) else np.array([])
    cv = float(per_sec.std() / per_sec.mean()) if len(per_sec) > 1 and per_sec.mean() else 0.0

    ns = np.array([x[0] for x in rss], dtype=float)
    ms = np.array([x[1] for x in rss], dtype=float)
    # Leak slope over the LAST THIRD: bounded caches (e.g. 65 s replay-nonce
    # retention) legitimately grow early in a run and then plateau.
    tail = len(ns) * 2 // 3
    slope = float(np.polyfit(ns[tail:], ms[tail:], 1)[0] * 1000) if len(ns) - tail >= 3 else 0.0

    max_depth = max((d for _, d in depth), default=0)
    late_depth = [d for _, d in depth[len(depth) // 2:]]

    return {
        "messages": len(service),
        "errors": errors,
        "offered_rate_msg_s": rate,
        "achieved_throughput_msg_s": round(len(service) / wall, 1),
        "throughput_per_second_windows": per_sec.tolist(),
        "throughput_cv": round(cv, 4),
        "wall_seconds": round(wall, 2),
        "service_latency_ms": latency_stats(service),
        "messages_over_10ms": int(sum(1 for x in service if x > 10.0)),
        "slow_messages": slow,
        "end_to_end_latency_ms": latency_stats(e2e),
        "queue": {"max_depth": int(max_depth), "final_depth": int(depth[-1][1]) if depth else 0,
                  "mean_depth_second_half": round(float(np.mean(late_depth)) if late_depth else 0.0, 2)},
        "memory": {"rss_start_mb": round(ms[0], 1), "rss_end_mb": round(ms[-1], 1),
                   "rss_growth_mb_per_1000_msgs_last_third": round(slope, 3),
                   "samples": [[int(a), round(b, 1)] for a, b in rss]},
        "cpu": {"process_cpu_percent": round(cpu_pct, 1),
                "cpu_seconds_user": round(cpu1.user - cpu0.user, 2),
                "cpu_seconds_system": round(cpu1.system - cpu0.system, 2),
                "cpu_ms_per_message": round((cpu1.user - cpu0.user + cpu1.system - cpu0.system)
                                            * 1000 / max(1, len(service)), 3)},
        "state_sizes_end": {
            "cyber_agent_sources": len(cyber_agent._request_timestamps),
            "cyber_agent_nonces": len(cyber_agent._seen_nonces),
            "cyber_model_sources": get_pipeline().cyber_model.extractor.tracked_sources(),
            "orchestrator_decision_log": len(orchestrator._decision_log),
        },
        "verdicts_by_kind": verdicts,
        "drop_reasons_by_kind": drop_reasons,
    }


def run_capacity(payloads: List[Dict[str, Any]], proc: psutil.Process) -> Dict[str, Any]:
    service: List[float] = []
    rss0 = rss_mb(proc)
    t0 = time.perf_counter()
    for i, p in enumerate(payloads):
        service.append(process(p)[0])  # capacity: time compressed, rate-limit drops expected
        if (i + 1) % 500 == 0:
            log.info("capacity %5d/%d  p95=%.2fms", i + 1, len(payloads), pct(service[-500:], 95))
    wall = time.perf_counter() - t0
    return {"messages": len(service), "wall_seconds": round(wall, 2),
            "max_throughput_msg_s": round(len(service) / wall, 1),
            "service_latency_ms": latency_stats(service),
            "rss_delta_mb": round(rss_mb(proc) - rss0, 2)}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Industrial Mind middleware stress test")
    ap.add_argument("--payloads", type=int, default=2400, help="sustained-phase payloads (>= 2000)")
    ap.add_argument("--capacity-payloads", type=int, default=2000)
    ap.add_argument("--rate", type=float, default=300.0, help="offered msg/s in sustained phase")
    ap.add_argument("--attack-ratio", type=float, default=0.15)
    ap.add_argument("--sources", type=int, default=200, help="number of legitimate SCADA hosts")
    ap.add_argument("--seed", type=int, default=2026)
    ap.add_argument("--live-plc", action="store_true", help="forward PASSed writes to a real PLC on :5020")
    ap.add_argument("--with-dashboard", action="store_true", help="also POST every decision to the dashboard")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s - %(message)s")
    logging.getLogger("industrialmind.middleware").setLevel(logging.WARNING)   # no per-message lines
    logging.getLogger("pymodbus").setLevel(logging.WARNING)

    os.makedirs(LOG_DIR, exist_ok=True)
    proc = psutil.Process()

    if args.live_plc:
        from pymodbus.client import ModbusTcpClient
        mw._plc_client = ModbusTcpClient(netconfig.PLC_HOST, port=netconfig.PLC_PORT)
        if not mw._plc_client.connect():
            log.error("--live-plc: cannot reach PLC on %s:%s", netconfig.PLC_HOST, netconfig.PLC_PORT)
            return 2
    else:
        mw._plc_client = InMemoryPLC()

    if not args.with_dashboard:
        orchestrator._forward_decision_to_dashboard = lambda payload: None

    pipe = get_pipeline()
    log.info("Models: CyberModel=%s PhysicalModel=%s", pipe.cyber_model.status, pipe.physical_model.status)

    log.info("Generating %d + %d payloads (seed %d, attack ratio %.0f%%, %d SCADA sources)",
             args.payloads, args.capacity_payloads, args.seed, args.attack_ratio * 100, args.sources)
    sustained_payloads = build_payloads(args.payloads, args.seed, args.attack_ratio, args.sources, args.rate)
    capacity_payloads = build_payloads(args.capacity_payloads, args.seed + 1, args.attack_ratio, args.sources,
                                       args.rate)

    # Long-lived test data (tens of thousands of payloads) must not be walked by
    # every full GC - the real middleware never holds it. Same freeze the
    # middleware applies to its startup objects.
    gc.collect()
    gc.freeze()

    # Warm-up: fill the PhysicalModel window, JIT caches, thread pool.
    for p in build_payloads(pipe.physical_model.window_size + 20, args.seed + 99, 0.0, args.sources, args.rate):
        process(p)
    cyber_agent.reset_state()

    log.info("Phase 1: sustained load at %.0f msg/s", args.rate)
    sustained = run_sustained(sustained_payloads, args.rate, proc)
    cyber_agent.reset_state()
    log.info("Phase 2: back-to-back capacity run")
    capacity = run_capacity(capacity_payloads, proc)

    s_lat = sustained["service_latency_ms"]
    checks = {
        "payload_count_>=_2000": sustained["messages"] >= 2000,
        "no_processing_errors": sustained["errors"] == 0,
        f"mean_service_latency_<_{TARGET_MEAN_MS}ms": s_lat["mean"] < TARGET_MEAN_MS,
        f"p95_service_latency_<_{TARGET_MEAN_MS}ms": s_lat["p95"] < TARGET_MEAN_MS,
        f"p99_service_latency_<_{TARGET_MEAN_MS}ms": s_lat["p99"] < TARGET_MEAN_MS,
        # Queue stability needs MEAN service time below the arrival interval;
        # p99 spikes are fine as long as the queue drains (checked below).
        "mean_service_<_arrival_interval": s_lat["mean"] < 1000.0 / args.rate,
        # Backpressure = queue that does not drain. Transient spikes (a GC pause)
        # may queue a few dozen messages briefly; they must clear and must not
        # push end-to-end p99 past the edge target.
        "no_backpressure (queue keeps draining, e2e p99 < 10 ms)":
            sustained["queue"]["mean_depth_second_half"] < 2
            and sustained["queue"]["final_depth"] == 0
            and sustained["end_to_end_latency_ms"]["p99"] < TARGET_MEAN_MS,
        f"throughput_stable (cv < {THROUGHPUT_CV_LIMIT})": sustained["throughput_cv"] < THROUGHPUT_CV_LIMIT,
        "achieved_rate_>=_95%_of_offered": sustained["achieved_throughput_msg_s"] >= 0.95 * args.rate,
        f"no_memory_leak (< {LEAK_LIMIT_MB_PER_1K} MB / 1000 msgs)":
            sustained["memory"]["rss_growth_mb_per_1000_msgs_last_third"] < LEAK_LIMIT_MB_PER_1K,
        "capacity_mean_latency_<_10ms": capacity["service_latency_ms"]["mean"] < TARGET_MEAN_MS,
        "all_attack_payloads_dropped": all(
            v.get("PASS", 0) == 0 for k, v in sustained["verdicts_by_kind"].items() if k != "normal"),
        "legit_payloads_pass_rate_>=_99%": (
            sustained["verdicts_by_kind"].get("normal", {}).get("PASS", 0)
            >= 0.99 * sum(sustained["verdicts_by_kind"].get("normal", {}).values())),
    }

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    result = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "config": vars(args),
        "environment": {"python": sys.version.split()[0], "cpu_count": psutil.cpu_count(),
                        "machines": NUM_REGISTERS,
                        "cyber_model": pipe.cyber_model.status, "physical_model": pipe.physical_model.status,
                        "pipeline_mode": "ENFORCE" if pipe.enforce_cyber_model else "MONITOR",
                        "plc": "live" if args.live_plc else "in-memory stub",
                        "dashboard_forwarding": args.with_dashboard},
        "sustained": sustained,
        "capacity": capacity,
        "checks": checks,
        "passed": all(checks.values()),
    }

    json_path = os.path.join(LOG_DIR, f"middleware_benchmark_{stamp}.json")
    with open(json_path, "w") as fh:
        json.dump(result, fh, indent=2)

    csv_path = os.path.join(LOG_DIR, "middleware_benchmark.csv")
    row = {
        "timestamp": result["timestamp"], "payloads": sustained["messages"], "offered_rate": args.rate,
        "throughput_msg_s": sustained["achieved_throughput_msg_s"],
        "capacity_msg_s": capacity["max_throughput_msg_s"],
        "mean_ms": s_lat["mean"], "p50_ms": s_lat["p50"], "p95_ms": s_lat["p95"], "p99_ms": s_lat["p99"],
        "max_ms": s_lat["max"], "e2e_p99_ms": sustained["end_to_end_latency_ms"]["p99"],
        "max_queue_depth": sustained["queue"]["max_depth"], "throughput_cv": sustained["throughput_cv"],
        "rss_end_mb": sustained["memory"]["rss_end_mb"],
        "rss_growth_mb_per_1k": sustained["memory"]["rss_growth_mb_per_1000_msgs_last_third"],
        "cpu_percent": sustained["cpu"]["process_cpu_percent"],
        "cpu_ms_per_msg": sustained["cpu"]["cpu_ms_per_message"],
        "passed": result["passed"], "json": os.path.basename(json_path),
    }
    new = not os.path.exists(csv_path)
    with open(csv_path, "a", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(row))
        if new:
            w.writeheader()
        w.writerow(row)

    log.info("=" * 64)
    log.info("Sustained: %d msgs @ %.1f msg/s (offered %.0f), cv=%.3f",
             sustained["messages"], sustained["achieved_throughput_msg_s"], args.rate, sustained["throughput_cv"])
    log.info("Service latency ms  mean=%.3f p50=%.3f p95=%.3f p99=%.3f max=%.3f",
             s_lat["mean"], s_lat["p50"], s_lat["p95"], s_lat["p99"], s_lat["max"])
    log.info("End-to-end p99 %.3f ms, max queue depth %d (final %d), %d msgs > 10 ms",
             sustained["end_to_end_latency_ms"]["p99"], sustained["queue"]["max_depth"],
             sustained["queue"]["final_depth"], sustained["messages_over_10ms"])
    log.info("Capacity: %.1f msg/s back-to-back (mean %.3f ms)", capacity["max_throughput_msg_s"],
             capacity["service_latency_ms"]["mean"])
    log.info("Memory: %.1f -> %.1f MB, %.3f MB/1000 msgs; CPU %.1f%% (%.3f ms CPU/msg)",
             sustained["memory"]["rss_start_mb"], sustained["memory"]["rss_end_mb"],
             sustained["memory"]["rss_growth_mb_per_1000_msgs_last_third"],
             sustained["cpu"]["process_cpu_percent"], sustained["cpu"]["cpu_ms_per_message"])
    for name, ok in checks.items():
        log.info("  [%s] %s", "PASS" if ok else "FAIL", name)
    log.info("JSON -> %s", json_path)
    log.info("CSV  -> %s", csv_path)

    get_pipeline().shutdown()
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
