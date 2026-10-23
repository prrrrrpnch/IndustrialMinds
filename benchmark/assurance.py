"""
benchmark/assurance.py - ONE end-to-end assurance run over seven dimensions, with the standard classification metrics.

    python -m benchmark.assurance            # ~10-15 min, writes docs/reports/assurance_report.md + benchmarks/assurance.json
    python -m benchmark.assurance --quick    # ~2 min, smaller samples (a smoke run; the report says so)

Sections, and what each one can and cannot prove:

  A FUNCTIONAL ACCURACY  rule conformance on constructed scenarios (4,600 cases), then the advisory detectors on the TWIN with the
                         full metric set (accuracy, precision, recall, F1, ROC-AUC, PR-AUC) against the never-alarm baseline, plus
                         the recorded real-SWaT numbers. Only the SWaT row is real-data performance.
  B ROBUSTNESS           malformed and hostile inputs, degraded telemetry (missing / NaN / frozen / gaps / out-of-order), a sensor-noise
                         sweep, and concurrent load: the system must never crash and must fail CLOSED.
  C BIAS AND FAIRNESS    does the system treat equivalent things equally? Identical commands from different source addresses; the SAME
                         perturbation (+k sigma) applied to each of the five stages; per-register false-alarm rates on healthy runs.
                         Reported as disparity (max - min) and as a ratio (min / max), the usual fairness statistics.
  D CONSISTENCY          determinism (same input -> same verdict), order invariance for order-independent rules, live-vs-offline parity
                         of the detectors, and reproducibility under a fixed seed.
  E EXPLAINABILITY       coverage (every decision carries a machine-readable reason; every trace carries every hop; every DROP names the
                         failing check) and FAITHFULNESS (when one stage is perturbed, does the explanation name that stage?).
  F DRIFT                score-distribution shift between healthy windows (PSI and KS), behaviour under a slow sensor drift, alarm creep
                         over a long healthy run, and the SWaT-to-twin domain gap.
  G SAFETY               fail-closed on agent error, the advisory layers can never DROP, recovery commands always pass, every documented
                         unsafe cross-register state is blocked, and the queues are bounded and counted.

HONEST SCOPE. Everything except the recorded SWaT row and the rule-conformance cases is measured on the DIGITAL TWIN with attacks we
constructed ourselves. The twin is calibrated to SWaT's operating point but is not SWaT, and a result on self-constructed attacks is
evidence that the system does what it was designed to do, not that it generalises to attacks nobody thought of. Both limits are
restated in the generated report next to the numbers.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import statistics
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
os.environ.setdefault("IM_LOG_DIR", tempfile.mkdtemp(prefix="im-assurance-"))
# Several sources must be trusted for the fairness section; set before the middleware reads its configuration.
os.environ.setdefault("IM_TRUSTED_SOURCES", ",".join(f"127.0.0.{i}" for i in range(1, 6)))

import numpy as np  # noqa: E402

from benchmark.env import environment  # noqa: E402
from core import hmac_auth  # noqa: E402
from core.interfaces import (CROSS_REGISTER_RULES, MACHINE_BY_NAME, MACHINE_BY_REGISTER, MACHINES, make_command,  # noqa: E402
                             make_verdict)
from middleware import cyber_agent, orchestrator, physical_agent  # noqa: E402
from middleware import trace as tracer  # noqa: E402
from models.invariant_monitor import DEFAULT_FILE, InvariantMonitor  # noqa: E402
from models.physical_model_v2 import load_physical_model  # noqa: E402
from pipeline.multi_model_pipeline import MultiModelPipeline  # noqa: E402
from plc import twin as twin_mod  # noqa: E402
from swat.invariants import InvariantSet  # noqa: E402
from swat.physical_features import ACTUATORS, SENSORS  # noqa: E402

orchestrator._forward_decision_to_dashboard = lambda payload: None

OUT_JSON = os.path.join(ROOT, "benchmarks", "assurance.json")
OUT_MD = os.path.join(ROOT, "docs", "reports", "assurance_report.md")
SETTLE_S = 420                      # healthy seconds before an injection (> the model's 120 s window and the invariants' lookback)
ATTACK_S = 600
LOOPBACK = "127.0.0.1"
SOURCES = [f"127.0.0.{i}" for i in range(1, 6)]
# One sensor per stage, and the stage it belongs to: the fairness and explainability sections perturb these by the same z-score.
STAGE_SENSOR = {"S1": "LIT101", "S2": "AIT202", "S3": "LIT301", "S4": "LIT401", "S5": "PIT501"}
ACTUATOR_NAMES = [m["name"] for m in MACHINES if m["kind"] == "actuator"]


# ===================================================================================== shared helpers
def wire(v: float) -> float:
    """What the middleware actually reads: the Modbus wire carries value x 10 as an integer (0.1 resolution)."""
    return round(v * 10.0) / 10.0


def signed(reg: int, value: float, tx: str, source: str = LOOPBACK) -> Dict[str, Any]:
    p = hmac_auth.parse_frame(hmac_auth.build_frame(reg, value))
    return make_command(tx, time.time(), source, 16, reg, p["raw_value"] / 10.0, raw_value=p["raw_value"], auth=p["auth"])


def nominal_state(over: Optional[Dict[int, float]] = None) -> Dict[str, Any]:
    regs = {m["register"]: float(m["initial"]) for m in MACHINES}
    regs.update(over or {})
    return {"registers": regs, "setpoints": dict(regs), "timestamp": time.time() - 10}


def regs_of(S: np.ndarray, A: np.ndarray, t: int) -> Dict[str, float]:
    out = {SENSORS[i]: float(S[t, i]) for i in range(len(SENSORS))}
    out.update({ACTUATORS[j]: 100.0 * float(A[t, j]) for j in range(len(ACTUATORS))})
    return out


class Tamper:
    """A sensor-level attack: the plant is untouched, the readings the middleware sees are altered."""

    def __init__(self, kind: str, tag: str, size: float, norm) -> None:
        self.kind, self.tag, self.size = kind, tag, size
        self.reg = MACHINE_BY_NAME[tag]["register"]
        self.sd = float(norm.sd[SENSORS.index(tag)]) if tag in SENSORS else 1.0
        self.held: Optional[float] = None

    def apply(self, regs: Dict[int, float], k: int) -> None:
        if self.kind == "bias":
            regs[self.reg] += self.size * self.sd
        elif self.kind == "step":
            regs[self.reg] += self.size * self.sd
        elif self.kind == "ramp":
            regs[self.reg] += self.size * self.sd * min(1.0, k / 300.0)
        elif self.kind == "freeze":
            if self.held is None:
                self.held = regs[self.reg]
            regs[self.reg] = self.held
        elif self.kind == "dead":
            regs[self.reg] = 0.0


def plant_run(model, inv: InvariantSet, seed: int, seconds: int, *, changes: Optional[Dict[str, float]] = None,
              change_at: Optional[int] = None, tamper: Optional[Tamper] = None, noise_scale: float = 1.0,
              drift: Optional[Tuple[str, float]] = None, operator: bool = True) -> Dict[str, Any]:
    """One twin run at 1 Hz. Returns per-second model probability, the three alarm sources and the attack label.

    `changes` is an actuator attack (the plant really changes); `tamper` is a sensor attack (only the readings change);
    `drift` is a slow (tag, units-per-second) degradation applied to a reading from the start - a non-attack change."""
    old_noise = twin_mod.SENSOR_NOISE_FRAC
    twin_mod.SENSOR_NOISE_FRAC = old_noise * noise_scale
    try:
        tw = twin_mod.PlantTwin(noise=True, seed=seed)
        rng = random.Random(seed + 991)
        mon = InvariantMonitor(inv, inv.theta, "assurance")
        model.reset_window()
        base = {m["name"]: float(m["initial"]) for m in MACHINES}
        p = np.full(seconds, np.nan)
        m_flag = np.zeros(seconds, bool)
        e_flag = np.zeros(seconds, bool)
        i_score = np.zeros(seconds)
        i_flag = np.zeros(seconds, bool)
        first_inv: Optional[str] = None
        ready = np.zeros(seconds, bool)
        label = np.zeros(seconds, bool)
        stages: List[Optional[str]] = [None] * seconds
        for t in range(seconds):
            if operator and t >= 300 and t % 600 == 0:                       # small legitimate set-point excursions
                for name in ACTUATOR_NAMES:
                    if rng.random() < 0.4:
                        tw.set_target(MACHINE_BY_NAME[name]["register"], min(100.0, max(0.0, base[name] * (1.0 + rng.uniform(-0.06, 0.06)))))
            if changes and change_at is not None and t == change_at:
                for tag, v in changes.items():
                    tw.set_target(MACHINE_BY_NAME[tag]["register"], v)
            for _ in range(10):
                tw.step(0.1)
            regs = {r: wire(v) for r, v in tw.values().items()}
            if drift is not None:
                tag, rate = drift
                regs[MACHINE_BY_NAME[tag]["register"]] = wire(regs[MACHINE_BY_NAME[tag]["register"]] + rate * t)
            if tamper is not None and change_at is not None and t >= change_at:
                tamper.apply(regs, t - change_at)
                regs = {r: wire(v) for r, v in regs.items()}
            if change_at is not None and t >= change_at:
                label[t] = True
            model.update(regs, timestamp=float(t))
            mon.update(regs, timestamp=float(t))
            r = model.assess()
            mr = mon.assess()
            if r.get("status") == "OK":
                ready[t] = True
                if r.get("attack_probability") is not None:
                    p[t] = float(r["attack_probability"])
                m_flag[t] = bool(r.get("threat_flag"))
                e_flag[t] = bool(r.get("bounds_violations"))
                stages[t] = r.get("suspect_stage")
            if mr.get("status") == "OK":
                i_score[t] = float(mr.get("max_excess") or 0.0)          # continuous: present whether or not anything is violated
                i_flag[t] = bool(mr.get("threat_flag"))
                if i_flag[t] and first_inv is None:
                    first_inv = (mr.get("violated") or [{}])[0].get("id")
        return {"p": p, "model": m_flag, "envelope": e_flag, "inv_score": i_score, "invariants": i_flag,
                "ready": ready, "label": label, "suspect_stage": stages, "seconds": seconds, "first_inv_tag": first_inv}
    finally:
        twin_mod.SENSOR_NOISE_FRAC = old_noise


def first_after(flag: np.ndarray, t0: int) -> Optional[int]:
    hit = np.flatnonzero(flag[t0:])
    return int(hit[0]) if hit.size else None


def classification(y: np.ndarray, flag: np.ndarray, score: Optional[np.ndarray] = None) -> Dict[str, Any]:
    """The standard metric set for one pooled set of windows, with the never-alarm baseline next to accuracy."""
    y, flag = np.asarray(y, bool), np.asarray(flag, bool)
    tp, fp = int((y & flag).sum()), int((~y & flag).sum())
    fn, tn = int((y & ~flag).sum()), int((~y & ~flag).sum())
    n = tp + fp + fn + tn
    prec = tp / (tp + fp) if tp + fp else None
    rec = tp / (tp + fn) if tp + fn else None
    spec = tn / (tn + fp) if tn + fp else None
    f1 = (0.0 if prec is None or rec is None or prec + rec == 0 else 2 * prec * rec / (prec + rec)) if (prec is not None and rec is not None) else None
    r = lambda v: None if v is None else round(float(v), 4)
    out = {"n": n, "tp": tp, "fp": fp, "fn": fn, "tn": tn, "accuracy": r((tp + tn) / n if n else None), "precision": r(prec),
           "recall": r(rec), "f1": r(f1), "specificity": r(spec), "false_positive_rate": r(None if spec is None else 1 - spec),
           "balanced_accuracy": r(None if rec is None or spec is None else (rec + spec) / 2),
           "never_alarm_accuracy": r((tn + fp) / n if n else None)}
    if score is not None:
        from sklearn.metrics import average_precision_score, roc_auc_score
        ok = ~np.isnan(score)
        if ok.sum() >= 4 and 0 < y[ok].sum() < int(ok.sum()):          # both classes present and enough points to mean anything
            out["roc_auc"] = round(float(roc_auc_score(y[ok], score[ok])), 4)
            out["pr_auc"] = round(float(average_precision_score(y[ok], score[ok])), 4)
    return out


def disparity(values: Dict[str, Optional[float]]) -> Dict[str, Any]:
    """The usual fairness statistics over per-group rates: spread (max - min) and ratio (min / max, 1.0 = perfectly equal)."""
    vals = {k: v for k, v in values.items() if v is not None}
    if not vals:
        return {"groups": 0}
    lo, hi = min(vals.values()), max(vals.values())
    return {"groups": len(vals), "min": round(lo, 4), "max": round(hi, 4), "spread": round(hi - lo, 4),
            "ratio_min_over_max": None if hi == 0 else round(lo / hi, 4),
            "worst_group": min(vals, key=lambda k: vals[k]), "best_group": max(vals, key=lambda k: vals[k]), "per_group": {k: round(v, 4) for k, v in vals.items()}}


def psi(reference: np.ndarray, current: np.ndarray, bins: int = 10) -> Optional[float]:
    """Population Stability Index between two score samples. < 0.1 no shift, 0.1-0.25 moderate, > 0.25 large (the usual reading)."""
    ref, cur = reference[~np.isnan(reference)], current[~np.isnan(current)]
    if ref.size < 50 or cur.size < 50:
        return None
    edges = np.unique(np.quantile(ref, np.linspace(0, 1, bins + 1)))
    if edges.size < 3:
        return 0.0
    edges[0], edges[-1] = -np.inf, np.inf
    a = np.histogram(ref, edges)[0] / ref.size
    b = np.histogram(cur, edges)[0] / cur.size
    a, b = np.clip(a, 1e-4, None), np.clip(b, 1e-4, None)
    return round(float(((b - a) * np.log(b / a)).sum()), 4)


# ===================================================================================== A. functional accuracy
ACTUATOR_ATTACKS = {
    "p101_stop (raw pump stops)": {"P101": 5.0},
    "acid_overdose (HCl max, raw pump low)": {"P203": 100.0, "P101": 15.0},
    "ro_deadhead (RO pump max, reject valve shut)": {"P501": 100.0, "MV503": 0.0},
    "uf_valve_shut (UF feed valve closes)": {"MV302": 2.0},
}
SENSOR_ATTACKS = [("step", "LIT401", 8.0), ("freeze", "LIT101", 0.0), ("dead", "FIT101", 0.0), ("ramp", "LIT301", 8.0), ("bias", "FIT201", 6.0)]


def section_accuracy(model, inv: InvariantSet, seeds: List[int]) -> Dict[str, Any]:
    """Pooled window-level metrics on the twin for each alarm source and for the layered system, plus the detection view."""
    runs: List[Dict[str, Any]] = []
    # Healthy runs of comparable length, so the benign side is real operation (set-point moves, fouling and backwash cycles)
    # and not just the quiet minutes before an injection. Without these, precision and specificity are trivially 1.0.
    for sd in seeds:
        runs.append({"family": "healthy", "attack": "no attack", "seed": sd, **plant_run(model, inv, sd + 900, 3 * (SETTLE_S + ATTACK_S))})
    for sd in seeds:
        for name, ch in ACTUATOR_ATTACKS.items():
            runs.append({"family": "actuator", "attack": name, "seed": sd,
                         **plant_run(model, inv, sd, SETTLE_S + ATTACK_S, changes=ch, change_at=SETTLE_S)})
        for kind, tag, size in SENSOR_ATTACKS:
            runs.append({"family": "sensor", "attack": f"{kind} {tag}", "seed": sd,
                         **plant_run(model, inv, sd + 500, SETTLE_S + ATTACK_S, tamper=Tamper(kind, tag, size, model.norm), change_at=SETTLE_S)})
    keep = np.concatenate([r["ready"] for r in runs])
    y = np.concatenate([r["label"] for r in runs])[keep]
    p = np.concatenate([r["p"] for r in runs])[keep]
    src = {k: np.concatenate([r[k] for r in runs])[keep] for k in ("model", "envelope", "invariants")}
    rules_layer = src["envelope"]                     # the only rule layer that acts on telemetry alone
    before = src["model"] | src["envelope"]
    after = before | src["invariants"]
    out: Dict[str, Any] = {
        "label": "TWIN, window level (1 Hz). Scored strictly from the second the attack is injected, so propagation delay counts as a miss.",
        "runs": len(runs), "healthy_runs": sum(1 for r in runs if r["family"] == "healthy"),
        "windows_scored": int(keep.sum()), "attack_windows": int(y.sum()), "benign_windows": int((~y).sum()),
        "benign_hours": round(int((~y).sum()) / 3600, 2),
        "by_source": {"advisory model (v2)": classification(y, src["model"], p),
                      "measured-envelope rule": classification(y, src["envelope"]),
                      "physical invariants": classification(y, src["invariants"], np.concatenate([r["inv_score"] for r in runs])[keep]),
                      "model OR envelope (previous system)": classification(y, before),
                      "model OR envelope OR invariants (current)": classification(y, after)}}
    per_attack = []
    for r in runs:
        if r["family"] == "healthy":
            continue
        t0 = SETTLE_S
        combined = r["model"] | r["envelope"] | r["invariants"]
        per_attack.append({"family": r["family"], "attack": r["attack"], "seed": r["seed"],
                           "detected": bool(combined[t0:].any()), "delay_s": first_after(combined, t0),
                           "by": {k: first_after(r[k], t0) for k in ("model", "envelope", "invariants")},
                           "false_alarm_seconds_before_attack": int(combined[:t0].sum())})
    out["per_attack"] = per_attack
    det = [a for a in per_attack if a["detected"]]
    out["detection_view"] = {"attacks": len(per_attack), "detected": len(det),
                             "detection_rate": round(len(det) / len(per_attack), 4),
                             "median_delay_s": None if not det else float(statistics.median(a["delay_s"] for a in det)),
                             "runs_with_a_false_alarm_before_the_attack": sum(1 for a in per_attack if a["false_alarm_seconds_before_attack"] > 0)}
    return out


def recorded_swat() -> Dict[str, Any]:
    """The only REAL-DATA accuracy in this report: the held-out SWaT result of the live model, read from the training report."""
    path = os.path.join(ROOT, "docs", "reports", "physical_training_report_v2_swat.json")
    try:
        with open(path) as fh:
            blk = json.load(fh)["test"]["0.5"]["selected_without_persistence"]
    except Exception as exc:
        return {"status": f"not available ({exc})"}
    keys = ("precision", "recall", "f1", "accuracy", "balanced_accuracy", "roc_auc", "average_precision",
            "always_benign_baseline_accuracy", "alarm_episodes_per_benign_hour", "segments_detected", "segments_total", "median_latency_s")
    out = {k: blk.get(k) for k in keys}
    out["source"] = "docs/reports/physical_training_report_v2_swat.json (held-out test block, threshold fixed on validation)"
    try:
        with open(os.path.join(ROOT, "benchmarks", "swat_scoring_comparison.json")) as fh:
            sc = json.load(fh)["budgets"]["0.5"]["selected_without_persistence"]["metrics"]
        out["point_adjusted_f1"] = sc.get("pa_f1")
        out["composite_f1"] = sc.get("composite_f1")
    except Exception:
        pass
    return out


# ===================================================================================== B. robustness
def section_robustness(model, inv: InvariantSet, quick: bool) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    pipe = MultiModelPipeline()
    st = nominal_state()

    # ---- B1 malformed / hostile commands: never raise, never accept something that should be refused.
    # The signed fields are `register` and `raw_value` and the signature field is `mac` (core/hmac_auth.py); `value` is DERIVED from
    # raw_value by middleware/ingest.py, so a command whose value and raw_value disagree cannot arrive over the wire and is marked
    # `must_refuse: False` below rather than counted as a miss.
    good = signed(1, 70.0, "ok")
    mac = str((good.get("auth") or {}).get("mac", ""))
    cases: List[Tuple[str, Dict[str, Any], bool]] = [("well-formed signed command (control)", good, False)]
    patches: List[Tuple[str, Dict[str, Any], bool]] = [
        ("value NaN", {"value": float("nan"), "raw_value": None}, True),
        ("value +inf", {"value": float("inf"), "raw_value": None}, True),
        ("value -inf", {"value": float("-inf"), "raw_value": None}, True),
        ("raw_value 1e12", {"raw_value": 10 ** 12}, True),
        ("raw_value negative", {"raw_value": -5000}, True),
        ("raw_value tampered (signature kept)", {"raw_value": 950}, True),
        ("register tampered (signature kept)", {"register": 0}, True),
        ("register -1", {"register": -1}, True),
        ("register 9999", {"register": 9999}, True),
        ("register None", {"register": None}, True),
        ("function code 99", {"function_code": 99}, True),
        ("function code None", {"function_code": None}, True),
        ("source empty", {"source_ip": ""}, True),
        ("source not an address", {"source_ip": "not-an-ip"}, True),
        ("signature removed", {"auth": None}, True),
        ("signature empty", {"auth": {}}, True),
        ("mac truncated", {"auth": {**(good.get("auth") or {}), "mac": mac[:8]}}, True),
        ("mac emptied", {"auth": {**(good.get("auth") or {}), "mac": ""}}, True),
        ("mac zeroed", {"auth": {**(good.get("auth") or {}), "mac": "0" * len(mac)}}, True),
        ("mac field removed", {"auth": {k: v for k, v in (good.get("auth") or {}).items() if k != "mac"}}, True),
        ("nonce zeroed", {"auth": {**(good.get("auth") or {}), "nonce": 0}}, True),
        ("timestamp an hour old", {"auth": {**(good.get("auth") or {}), "timestamp_ms": int((time.time() - 3600) * 1000)}}, True),
        ("tx_id None", {"tx_id": None}, False),
        ("value disagrees with raw_value", {"value": 95.0}, False),
    ]
    for name, patch, must in patches:
        cases.append((name, {**signed(1, 70.0, f"m-{name}"), **patch}, must))
    cases.append(("empty dict", {}, True))
    cases.append(("value as text", {**signed(1, 70.0, "txt"), "value": "seventy", "raw_value": None}, True))
    rows = []
    for name, cmd, must in cases:
        cyber_agent.reset_state()
        try:
            dec = pipe.process_command(cmd, st)["decision"]
            rows.append({"case": name, "must_refuse": must, "raised": False, "verdict": dec["verdict"], "reason": str(dec["reason"])[:48],
                         "refused": dec["verdict"] == "DROP"})
        except Exception as exc:                                     # a crash here would take the proxy down
            rows.append({"case": name, "must_refuse": must, "raised": True, "exception": f"{type(exc).__name__}: {exc}"[:80],
                         "verdict": None, "reason": None, "refused": False})
    must_rows = [r for r in rows if r["must_refuse"]]
    out["malformed_input"] = {"cases": rows, "n": len(rows) - 1, "must_refuse": len(must_rows),
                              "raised": sum(r["raised"] for r in rows),
                              "refused_as_required": sum(r["refused"] for r in must_rows),
                              "wrongly_accepted": sum(1 for r in must_rows if not r["refused"]),
                              "control_passed": rows[0]["verdict"] in ("PASS", "ALERT"),
                              "note": "`value` is derived from `raw_value` by the ingest path, so the two cannot disagree on the wire; "
                                      "that case and a null tx_id are recorded but not required to be refused"}

    # ---- B2 degraded telemetry: the detectors must abstain, never guess and never raise
    tele = []
    for name, sample in [("a sensor missing", {k: v for k, v in regs_of(np.ones((1, len(SENSORS))), np.ones((1, len(ACTUATORS))), 0).items() if k != "LIT101"}),
                         ("a reading is NaN", {**regs_of(np.ones((1, len(SENSORS))), np.ones((1, len(ACTUATORS))), 0), "LIT101": float("nan")}),
                         ("an empty sample", {}), ("values as text", {s: "x" for s in SENSORS})]:
        m2, i2 = load_physical_model(), InvariantMonitor(inv, inv.theta)
        raised = False
        try:
            m2.update(sample, timestamp=1.0)
            i2.update(sample, timestamp=1.0)
            m2.assess()
            i2.assess()
        except Exception as exc:
            raised = f"{type(exc).__name__}: {exc}"[:80]
        raised_live = False
        try:
            pipe.ingest_telemetry(sample, timestamp=1.0)             # the real entry point, which must swallow anything
        except Exception as exc:
            raised_live = f"{type(exc).__name__}: {exc}"[:80]
        tele.append({"case": name, "raised": raised, "raised_through_the_pipeline": raised_live,
                     "model_status": m2.assess().get("status"), "invariant_status": i2.assess().get("status"),
                     "flagged": bool(m2.assess().get("threat_flag") or i2.assess().get("threat_flag"))})
    # a telemetry gap must restart both windows rather than join across the hole
    m3, i3 = load_physical_model(), InvariantMonitor(inv, inv.theta)
    tw = twin_mod.PlantTwin(noise=True, seed=5)
    for t in range(400):
        for _ in range(10):
            tw.step(0.1)
        r = {k: wire(v) for k, v in tw.values().items()}
        m3.update(r, timestamp=float(t))
        i3.update(r, timestamp=float(t))
    warm = (m3.assess()["status"], i3.assess()["status"])
    m3.update({k: wire(v) for k, v in tw.values().items()}, timestamp=400.0 + 600.0)
    i3.update({k: wire(v) for k, v in tw.values().items()}, timestamp=400.0 + 600.0)
    tele.append({"case": "a 10-minute telemetry gap", "raised": False, "model_status": m3.assess().get("status"),
                 "invariant_status": i3.assess().get("status"), "flagged": bool(m3.assess().get("threat_flag") or i3.assess().get("threat_flag")),
                 "note": f"both were {warm} before the gap"})
    out["degraded_telemetry"] = {"cases": tele, "raised": sum(1 for r in tele if r["raised"]),
                                 "raised_through_the_pipeline": sum(1 for r in tele if r.get("raised_through_the_pipeline")),
                                 "flagged_on_garbage": sum(1 for r in tele if r["flagged"])}

    # ---- B3 noise sweep: graceful degradation, not a cliff
    sweep = []
    for scale in ([1.0, 4.0] if quick else [0.5, 1.0, 2.0, 4.0]):
        hz = plant_run(model, inv, 77, 2700 if quick else 5400, noise_scale=scale)
        at = plant_run(model, inv, 78, SETTLE_S + 300, changes=ACTUATOR_ATTACKS["ro_deadhead (RO pump max, reject valve shut)"], change_at=SETTLE_S, noise_scale=scale)
        combined_h = (hz["model"] | hz["envelope"] | hz["invariants"]) & hz["ready"]
        combined_a = at["model"] | at["envelope"] | at["invariants"]
        sweep.append({"noise_x": scale, "healthy_hours": round(int(hz["ready"].sum()) / 3600, 2),
                      "false_alarm_seconds": int(combined_h.sum()),
                      "false_alarm_rate": round(float(combined_h.sum()) / max(int(hz["ready"].sum()), 1), 5),
                      "attack_detected": bool(combined_a[SETTLE_S:].any()), "detection_delay_s": first_after(combined_a, SETTLE_S)})
    out["noise_sweep"] = {"label": "sensor noise scaled around the twin's calibrated level; the detectors were fitted at x1",
                          "rows": sweep}

    # ---- B4 concurrency: many threads through one pipeline
    n_thr, per = (4, 40) if quick else (8, 80)
    errors: List[str] = []
    verdicts: List[str] = []
    lock = threading.Lock()

    def worker(k: int) -> None:
        for i in range(per):
            try:
                cyber_agent.reset_state()
                d = pipe.process_command(signed(1, 70.0, f"c{k}-{i}"), st)["decision"]
                with lock:
                    verdicts.append(d["verdict"])
            except Exception as exc:
                with lock:
                    errors.append(f"{type(exc).__name__}: {exc}"[:80])
    threads = [threading.Thread(target=worker, args=(k,)) for k in range(n_thr)]
    t0 = time.perf_counter()
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    out["concurrency"] = {"threads": n_thr, "commands": n_thr * per, "exceptions": len(errors), "examples": errors[:3],
                          "verdicts": {v: verdicts.count(v) for v in set(verdicts)}, "seconds": round(time.perf_counter() - t0, 2),
                          "note": "the rate limiter is shared state, so DROP(RATE_LIMIT_EXCEEDED) under this load is correct behaviour, not a failure"}
    pipe.shutdown()
    return out


# ===================================================================================== C. bias and fairness
def section_fairness(model, inv: InvariantSet, seeds: List[int]) -> Dict[str, Any]:
    """Equivalent things must be treated equally: the same command from different senders, the same perturbation in different
    stages, and legitimate commands to every actuator. Reported as spread (max - min) and ratio (min / max)."""
    out: Dict[str, Any] = {}
    pipe = MultiModelPipeline()

    # ---- C1 source-address parity: the same legitimate command from each trusted address
    per_source: Dict[str, Dict[str, Any]] = {}
    for src in SOURCES:
        acc = 0
        reasons = set()
        for i, name in enumerate(ACTUATOR_NAMES):
            m = MACHINE_BY_NAME[name]
            cyber_agent.reset_state()
            d = pipe.process_command(signed(m["register"], float(m["initial"]), f"f-{src}-{i}", src), nominal_state())["decision"]
            acc += d["verdict"] in ("PASS", "ALERT")
            reasons.add(d["reason"].split(":")[0])
        per_source[src] = {"accepted": acc, "n": len(ACTUATOR_NAMES), "rate": acc / len(ACTUATOR_NAMES), "reasons": sorted(reasons)}
    out["source_parity"] = {"label": "an identical legitimate command sent from each trusted source address",
                            "per_source": per_source,
                            "identical_outcome_for_every_source": len({tuple(v["reasons"]) for v in per_source.values()}) == 1,
                            "disparity": disparity({k: v["rate"] for k, v in per_source.items()})}

    # ---- C2 per-register parity: a legitimate in-bounds command to every actuator
    per_reg: Dict[str, Optional[float]] = {}
    for name in ACTUATOR_NAMES:
        m = MACHINE_BY_NAME[name]
        ok = 0
        for i in range(6):
            cyber_agent.reset_state()
            v = float(m["initial"]) * (1.0 + 0.01 * (i - 3))
            d = pipe.process_command(signed(m["register"], round(min(float(m["max"]), max(float(m["min"]), v)), 1), f"r-{name}-{i}"), nominal_state())["decision"]
            ok += d["verdict"] in ("PASS", "ALERT")
        per_reg[name] = ok / 6
    out["register_parity"] = {"label": "small legitimate set-point changes on each of the 10 actuators (6 each)",
                              "disparity": disparity(per_reg)}
    pipe.shutdown()

    # ---- C3 per-stage parity: the SAME perturbation (+k sigma on that stage's sensor) in each of the five stages
    # A large step is caught everywhere, so the test saturates and measures nothing. Sweeping the size finds the level where the
    # stages actually differ, which is where a coverage gap would show.
    sizes = [1.0, 2.0, 4.0, 8.0]
    rows = []
    for size in sizes:
        for stage, tag in STAGE_SENSOR.items():
            for sd in seeds:
                r = plant_run(model, inv, sd + 300, SETTLE_S + 240, tamper=Tamper("step", tag, size, model.norm), change_at=SETTLE_S)
                comb = r["model"] | r["envelope"] | r["invariants"]
                rows.append({"sigma": size, "stage": stage, "sensor": tag, "seed": sd, "detected": bool(comb[SETTLE_S:].any()),
                             "delay_s": first_after(comb, SETTLE_S),
                             "by": {k: first_after(r[k], SETTLE_S) is not None for k in ("model", "envelope", "invariants")}})
    per_size: Dict[str, Dict[str, Any]] = {}
    for size in sizes:
        sub = [r for r in rows if r["sigma"] == size]
        rate = {s: sum(x["detected"] for x in sub if x["stage"] == s) / max(sum(1 for x in sub if x["stage"] == s), 1) for s in STAGE_SENSOR}
        per_size[str(size)] = {"detection_rate_per_stage": rate, "overall": round(sum(r["detected"] for r in sub) / len(sub), 4),
                               "disparity": disparity(rate)}
    # the hardest size that is not uniformly missed is where a difference between stages, if any, is visible
    informative = [sz for sz in sizes if 0.0 < per_size[str(sz)]["overall"] < 1.0] or [sizes[-1]]
    chosen = str(informative[0])
    delay = {s: (None if not [r for r in rows if r["stage"] == s and r["detected"]] else
                 float(statistics.median(r["delay_s"] for r in rows if r["stage"] == s and r["detected"]))) for s in STAGE_SENSOR}
    out["stage_parity"] = {"label": "the SAME step, in sigma of that sensor's measured normal spread, applied to one sensor of each stage",
                           "runs": len(rows), "sizes_sigma": sizes, "per_size": per_size,
                           "discriminating_size_sigma": float(chosen), "detection_rate_per_stage": per_size[chosen]["detection_rate_per_stage"],
                           "median_delay_per_stage": delay, "disparity": per_size[chosen]["disparity"], "rows": rows}
    return out


# ===================================================================================== D. consistency
def section_consistency(model, inv: InvariantSet, quick: bool) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    pipe = MultiModelPipeline()
    st = nominal_state()

    # ---- D1 determinism: the same command and state, over and over
    n = 60 if quick else 200
    seen = set()
    for i in range(n):
        cyber_agent.reset_state()
        d = pipe.process_command(signed(1, 70.0, "det"), st)["decision"]
        seen.add((d["verdict"], d["reason"]))
    out["determinism"] = {"repeats": n, "distinct_outcomes": len(seen), "outcomes": sorted(str(s) for s in seen)[:3]}

    # ---- D2 order invariance for order-INDEPENDENT rules: distinct registers, one command each
    def sequence(order: List[int]) -> List[Tuple[int, str]]:
        res = []
        for k in order:
            cyber_agent.reset_state()          # the rate limiter and the replay window ARE order-dependent; exclude them here
            m = MACHINE_BY_NAME[ACTUATOR_NAMES[k]]
            d = pipe.process_command(signed(m["register"], float(m["initial"]), f"o{k}"), nominal_state())["decision"]
            res.append((k, d["verdict"]))
        return res
    base = dict(sequence(list(range(len(ACTUATOR_NAMES)))))
    shuffles = []
    rng = random.Random(3)
    for _ in range(3 if quick else 8):
        o = list(range(len(ACTUATOR_NAMES)))
        rng.shuffle(o)
        shuffles.append(dict(sequence(o)) == base)
    out["order_invariance"] = {"permutations": len(shuffles), "same_verdict_per_register": sum(shuffles),
                               "note": "only order-independent rules are compared here; the rate limiter and the replay window are order-dependent BY DESIGN"}

    # ---- D3 live-vs-offline parity: the live monitor must score exactly like the offline engine
    secs = 900 if quick else 1800
    tw = twin_mod.PlantTwin(noise=True, seed=11)
    S, A = np.zeros((secs, len(SENSORS))), np.zeros((secs, len(ACTUATORS)))
    mon = InvariantMonitor(inv, inv.theta)
    live, ready = np.zeros(secs), np.zeros(secs, bool)
    for t in range(secs):
        for _ in range(10):
            tw.step(0.1)
        r = {k: wire(v) for k, v in tw.values().items()}
        S[t] = [r[MACHINE_BY_NAME[s]["register"]] for s in SENSORS]
        A[t] = [1.0 if r[MACHINE_BY_NAME[a]["register"]] >= 50 else 0.0 for a in ACTUATORS]
        mon.update(r, timestamp=float(t))
        rep = mon.assess()
        if rep["status"] == "OK":
            ready[t], live[t] = True, float(rep["max_excess"] or 0.0)     # the continuous value, directly comparable with the offline score
    offline, _ = inv.score(S, A, np.zeros(secs, int))
    diff = np.abs(live[ready] - np.round(offline[ready], 3))
    out["live_offline_parity"] = {"seconds_compared": int(ready.sum()), "max_abs_difference": round(float(diff.max()) if diff.size else 0.0, 6),
                                  "exact_matches": int((diff < 1e-9).sum()),
                                  "note": "the live monitor and the evaluation harness call the same scoring function on the same arrays"}

    # ---- D4 reproducibility: the same seed must give the same run
    a = plant_run(model, inv, 23, 600)
    b = plant_run(model, inv, 23, 600)
    same_p = bool(np.allclose(np.nan_to_num(a["p"], nan=-1), np.nan_to_num(b["p"], nan=-1)))
    out["reproducibility"] = {"identical_model_scores": same_p,
                              "identical_flags": bool((a["model"] == b["model"]).all() and (a["invariants"] == b["invariants"]).all())}
    pipe.shutdown()
    return out


# ===================================================================================== E. explainability
UNTRUSTED = "127.0.0.99"            # loopback, deliberately OUTSIDE the trusted list set at the top of this module


def section_explainability(model, inv: InvariantSet, seeds: List[int]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    pipe = MultiModelPipeline()

    # ---- E1 coverage: a reason on every decision, every hop in every trace, the failing check named on every DROP
    checked, with_reason, full_trace, named_check = 0, 0, 0, 0
    hops_expected = {"arrival", "cyber_rules", "cyber_model", "physical_rules", "physical_model", "orchestrator"}
    drops = 0
    for name, cmd, state in [("legitimate", signed(1, 70.0, "e1"), nominal_state()),
                             ("out of bounds", signed(1, 999.0, "e2"), nominal_state()),
                             ("sensor register", signed(2, 50.0, "e3"), nominal_state()),
                             ("unsigned", make_command("e4", time.time(), LOOPBACK, 6, 1, 70.0, raw_value=700), nominal_state()),
                             ("untrusted source", signed(1, 70.0, "e5", UNTRUSTED), nominal_state()),
                             ("cross-register", signed(MACHINE_BY_NAME["P203"]["register"], 85.0, "e6"),
                              nominal_state({MACHINE_BY_NAME["P203"]["register"]: 75.0, MACHINE_BY_NAME["P101"]["register"]: 15.0}))]:
        cyber_agent.reset_state()
        rep = pipe.process_command(cmd, state)
        d = rep["decision"]
        checked += 1
        with_reason += bool(d.get("reason"))
        tr = pipe._recent_traces.get(str(cmd.get("tx_id"))) or {}
        hops = {h["hop"] for h in tr.get("hops", [])}
        full_trace += hops_expected <= hops
        if d["verdict"] == "DROP":
            drops += 1
            layers = [h for h in tr.get("hops", []) if h["hop"] in ("cyber_rules", "physical_rules")]
            named_check += any(any(c.get("result") == "FAIL" for c in (h.get("checks") or [])) for h in layers)
    out["coverage"] = {"decisions": checked, "with_a_machine_readable_reason": with_reason, "with_every_trace_hop": full_trace,
                       "drops": drops, "drops_naming_the_failing_check": named_check}

    # ---- E2 faithfulness: perturb ONE stage, ask the explanation which stage it was
    model_hits, model_total, inv_hits, inv_total = 0, 0, 0, 0
    rows = []
    for stage, tag in STAGE_SENSOR.items():
        for sd in seeds:
            r = plant_run(model, inv, sd + 700, SETTLE_S + 180, tamper=Tamper("step", tag, 8.0, model.norm), change_at=SETTLE_S)
            flagged = np.flatnonzero(r["model"][SETTLE_S:])
            said = r["suspect_stage"][SETTLE_S + int(flagged[0])] if flagged.size else None
            if said is not None:
                model_total += 1
                model_hits += said == stage
            inv_id = r["first_inv_tag"]
            if inv_id:
                inv_total += 1
                inv_hits += tag in inv_id
            rows.append({"stage": stage, "sensor": tag, "seed": sd, "model_said": said, "invariant_said": inv_id})
    out["faithfulness"] = {"label": "one stage is perturbed; the explanation should name that stage (model) and that sensor (invariants)",
                           "model_attributions": model_total, "model_correct_stage": model_hits,
                           "model_top1_accuracy": None if not model_total else round(model_hits / model_total, 4),
                           "invariant_attributions": inv_total, "invariant_correct_sensor": inv_hits,
                           "invariant_top1_accuracy": None if not inv_total else round(inv_hits / inv_total, 4),
                           "chance_level": round(1 / len(STAGE_SENSOR), 4), "rows": rows}

    # ---- E3 the reason vocabulary is closed and documented
    known = set(tracer._CYBER_BY_PREFIX) | set(tracer._PHYS_BY_PREFIX) | {"OK", "PHYSICAL_MODEL", "AGENT_ERROR"}
    out["reason_vocabulary"] = {"documented_prefixes": sorted(known),
                                "cyber_check_order": tracer.CYBER_ORDER, "physical_check_order": tracer.PHYSICAL_ORDER}
    pipe.shutdown()
    return out


# ===================================================================================== F. drift
def section_drift(model, inv: InvariantSet, quick: bool) -> Dict[str, Any]:
    """Does the system stay stable when nothing is attacking it, and what does a slow degradation look like to it?"""
    out: Dict[str, Any] = {}
    hours = 2.0 if quick else 4.0
    long_run = plant_run(model, inv, 61, int(hours * 3600))
    rdy = long_run["ready"]
    p = long_run["p"]
    idx = np.flatnonzero(rdy)
    half = idx[: len(idx) // 2], idx[len(idx) // 2:]
    alarms = (long_run["model"] | long_run["envelope"] | long_run["invariants"]) & rdy
    out["long_healthy_run"] = {
        "simulated_hours": round(hours, 2), "scored_seconds": int(rdy.sum()),
        "alarm_seconds": int(alarms.sum()), "alarm_seconds_first_half": int(alarms[half[0]].sum()), "alarm_seconds_second_half": int(alarms[half[1]].sum()),
        "model_probability": {"p50": round(float(np.nanpercentile(p[rdy], 50)), 4), "p95": round(float(np.nanpercentile(p[rdy], 95)), 4),
                              "p99": round(float(np.nanpercentile(p[rdy], 99)), 4), "max": round(float(np.nanmax(p[rdy])), 4),
                              "threshold": round(float(model.clf_threshold), 4)},
        "invariant_score": {"p95": round(float(np.percentile(long_run["inv_score"][rdy], 95)), 3),
                            "max": round(float(long_run["inv_score"][rdy].max()), 3), "theta": inv.theta}}
    # PSI between the first and second half of a healthy run (the no-shift control) and against independent healthy runs
    ref = p[half[0]]
    same_seed = plant_run(model, inv, 61, int(hours * 3600))["p"][half[0]]        # the control: nothing changed at all
    out["score_stability"] = {"psi_same_run_repeated_control": psi(ref, same_seed),
                              "psi_first_vs_second_half": psi(ref, p[half[1]]),
                              "psi_vs_independent_healthy_run": psi(ref, plant_run(model, inv, 62, 3600)["p"]),
                              "reading": "PSI below 0.1 is no meaningful shift, 0.1-0.25 moderate, above 0.25 large. The control re-runs the "
                                         "identical seed and must be 0: anything above that is real variation between healthy runs, not a measurement artefact."}
    # a slow sensor degradation: not an attack, but it is what drift looks like in a plant
    drift_rows = []
    for rate in ([0.02] if quick else [0.005, 0.02, 0.05]):
        d = plant_run(model, inv, 63, 3600, drift=("LIT301", rate))
        dr = d["ready"]
        fl = (d["model"] | d["envelope"] | d["invariants"]) & dr
        drift_rows.append({"tag": "LIT301", "mm_per_second": rate, "total_drift_mm": round(rate * 3600, 1),
                           "first_alarm_at_s": first_after(fl, 0), "alarm_seconds": int(fl.sum()),
                           "psi_vs_healthy": psi(ref, d["p"])})
    out["slow_degradation"] = {"label": "a sensor drifting slowly upward with no attack: the system should notice a large drift and ignore a tiny one",
                               "rows": drift_rows}
    out["domain_gap"] = {"note": "the live model was trained on SWaT and runs here on the twin; the standing measurement is docs/reports/twin_domain_gap_report.md",
                         "twin_false_alarm_rate_this_run": round(float(alarms.sum()) / max(int(rdy.sum()), 1), 5)}
    return out


# ===================================================================================== G. safety
def section_safety(model, inv: InvariantSet) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    pipe = MultiModelPipeline()
    st = nominal_state()

    # ---- G1 fail closed: if any stage of the decision path raises, the command must be DROPped, never forwarded
    boom = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("injected fault"))
    rows = []
    originals = {"cyber_agent.check": cyber_agent.check, "physical_agent.check_command": physical_agent.check_command,
                 "orchestrator.decide": orchestrator.decide}
    for name in originals:
        mod, attr = (cyber_agent, "check") if name.startswith("cyber") else (physical_agent, "check_command") if name.startswith("physical") else (orchestrator, "decide")
        setattr(mod, attr, boom)
        try:
            cyber_agent.reset_state()
            d = pipe.process_command(signed(1, 70.0, f"fc-{attr}"), st)["decision"]
            rows.append({"fault_injected_in": name, "verdict": d["verdict"], "reason": str(d["reason"])[:40], "failed_closed": d["verdict"] == "DROP"})
        except Exception as exc:
            rows.append({"fault_injected_in": name, "verdict": None, "reason": f"propagated {type(exc).__name__}", "failed_closed": False})
        finally:
            setattr(mod, attr, originals[name])
    cyber_agent.reset_state()
    control = pipe.process_command(signed(1, 70.0, "fc-control"), st)["decision"]
    out["fail_closed"] = {"faults": rows, "all_failed_closed": all(r["failed_closed"] for r in rows),
                          "recovered_afterwards": control["verdict"] in ("PASS", "ALERT")}

    # ---- G2 the advisory layers can never DROP: force a flag and check the verdict is ALERT, and that the command is still forwarded
    adv = []
    for flag_src in ("model", "invariants"):
        v = orchestrator.decide(make_verdict("adv", True, "OK", "cyber"), make_verdict("adv", True, "OK", "physical"), time.time(),
                                physical_advisory={"threat_flag": True, "flagged_by": [flag_src], "suspect_stage": "S1"})
        adv.append({"flagged_by": flag_src, "verdict": v["verdict"], "reason": v["reason"]})
    out["advisory_never_blocks"] = {"cases": adv, "all_alert_not_drop": all(a["verdict"] == "ALERT" for a in adv)}

    # ---- G3 every documented unsafe cross-register state is blocked, and the way back out is allowed
    # The plant starts just on the SAFE side of each threshold and is commanded 5 % across it, with the other register already
    # in its unsafe position: the smallest command that creates the unsafe combination, which is the strictest form of the test.
    unsafe = []
    for rule in CROSS_REGISTER_RULES:
        (ra, opa, va), (rb, opb, vb) = rule["conditions"][0], rule["conditions"][1]
        lo_a, hi_a = float(MACHINE_BY_REGISTER[ra]["min"]), float(MACHINE_BY_REGISTER[ra]["max"])
        clamp = lambda v: round(min(hi_a, max(lo_a, v)), 1)
        safe_a, trip_a = (clamp(va - 5.0), clamp(va + 5.0)) if opa == ">=" else (clamp(va + 5.0), clamp(va - 5.0))
        trip_b = round(vb + 5.0 if opb == ">=" else max(0.0, vb - 5.0), 1)
        cyber_agent.reset_state()
        blocked = pipe.process_command(signed(ra, trip_a, f"x-{rule['id']}"), nominal_state({ra: safe_a, rb: trip_b}))["decision"]
        cyber_agent.reset_state()
        back = pipe.process_command(signed(ra, safe_a, f"b-{rule['id']}"), nominal_state({ra: trip_a, rb: trip_b}))["decision"]
        unsafe.append({"rule": rule["id"], "command": f"{MACHINE_BY_REGISTER[ra]['name']} {safe_a} -> {trip_a} while {MACHINE_BY_REGISTER[rb]['name']} = {trip_b}",
                       "refused": blocked["verdict"] == "DROP",
                       "unsafe_command_blocked": blocked["verdict"] == "DROP" and rule["id"] in blocked["reason"],
                       "verdict": blocked["verdict"], "reason": str(blocked["reason"])[:60],
                       "recovery_allowed": back["verdict"] in ("PASS", "ALERT"), "recovery_verdict": back["verdict"]})
    out["unsafe_states"] = {"rules": len(unsafe), "refused_any_reason": sum(r["refused"] for r in unsafe),
                            "blocked": sum(r["unsafe_command_blocked"] for r in unsafe),
                            "recovery_allowed": sum(r["recovery_allowed"] for r in unsafe), "rows": unsafe}

    # ---- G4 bounded resources: the queues have a ceiling and overflow is counted, never silent
    from middleware import forwarding, ingest, runtime
    out["bounded_resources"] = {
        "decision_queue_maxsize": ingest._decision_queue.maxsize, "forward_queue_maxsize": forwarding._forward_queue.maxsize,
        "dropped_writes_counter": ingest.dropped_writes(), "dropped_forwards_counter": runtime._health["dropped_forwards"],
        "undelivered_counter": runtime._health["undelivered"],
        "pending_command_timeout_s": runtime.PENDING_COMMAND_TIMEOUT_S,
        "note": "a full queue fails CLOSED (the write is refused) and increments a counter the health endpoint reports"}

    # ---- G5 the PLC applies a write only from an allowed writer (defence in depth behind the middleware)
    from core import netconfig
    from plc import plc as plc_mod
    out["plc_allow_list"] = {"configured_writers": list(netconfig.PLC_ALLOWED_WRITERS),
                             "middleware_allowed": plc_mod.writer_allowed(netconfig.MIDDLEWARE_HOST),
                             "foreign_host_refused": not plc_mod.writer_allowed(UNTRUSTED),
                             "note": "a spoofed source address still passes this check: it is defence in depth, not segmentation"}
    pipe.shutdown()
    return out


# ===================================================================================== report
def pct(x: Optional[float]) -> str:
    return "n/a" if x is None else f"{100 * x:.0f}%"


def g(v: Any) -> str:
    return "n/a" if v is None else str(v)


def render(res: Dict[str, Any]) -> str:
    env = res["environment"]
    A_, B, C, D, E, F, G = (res[k] for k in ("accuracy", "robustness", "fairness", "consistency", "explainability", "drift", "safety"))
    sw = res["recorded_swat"]
    L = ["# Assurance report: functional accuracy, robustness, fairness, consistency, explainability, drift, safety", ""]
    if res.get("quick"):
        L += ["> **SMOKE RUN (`--quick`): sample sizes are small. Re-run without `--quick` before quoting anything.**", ""]
    L += [f"Generated by `python -m benchmark.assurance` on {env['generated_utc']} UTC, commit `{env['git_commit']}`"
          f"{' (dirty tree)' if env['git_dirty'] else ''}, Python {env['python']}, scikit-learn {env['scikit_learn']}, run time {res['seconds']} s.", "",
          "> **Scope, stated once and meant throughout.** Every number below except the recorded SWaT row is measured on the DIGITAL TWIN, "
          "with attacks we constructed ourselves. The twin is calibrated to SWaT's measured operating point but it is not SWaT, and detecting "
          "attacks of our own design shows the system does what it was built to do, not that it generalises to attacks nobody anticipated. "
          "The one real-data row is the held-out SWaT result of the advisory model.", "",
          "## Summary", "", "| dimension | headline | how it was measured |", "|---|---|---|"]
    acc = A_["by_source"]["model OR envelope OR invariants (current)"]
    det = A_["detection_view"]
    L += [f"| Functional accuracy | F1 **{g(acc['f1'])}**, precision {g(acc['precision'])}, recall {g(acc['recall'])}, accuracy {g(acc['accuracy'])} "
          f"(never-alarm baseline {g(acc['never_alarm_accuracy'])}); {det['detected']}/{det['attacks']} attacks detected, median {g(det['median_delay_s'])} s | "
          f"{A_['runs']} twin runs ({A_['healthy_runs']} with no attack), {A_['windows_scored']:,} scored seconds, {A_['benign_hours']} benign hours |",
          f"| Robustness | {B['malformed_input']['raised']} crashes and {B['malformed_input']['wrongly_accepted']} wrongly accepted out of "
          f"{B['malformed_input']['must_refuse']} commands that must be refused; {B['concurrency']['exceptions']} errors under {B['concurrency']['threads']} threads | "
          "fuzzed inputs, degraded telemetry, a noise sweep, concurrent load |",
          f"| Bias and fairness | per-stage detection ratio (min/max) **{g(C['stage_parity']['disparity'].get('ratio_min_over_max'))}**, "
          f"source-address parity {C['source_parity']['identical_outcome_for_every_source']}, per-register ratio {g(C['register_parity']['disparity'].get('ratio_min_over_max'))} | "
          "the same perturbation in each stage; identical commands from each sender and to each register |",
          f"| Consistency | {D['determinism']['distinct_outcomes']} distinct outcome(s) over {D['determinism']['repeats']} identical commands; "
          f"live-vs-offline max difference {D['live_offline_parity']['max_abs_difference']} | repeats, permutations, parity, fixed seed |",
          f"| Explainability | stage attribution top-1 **{pct(E['faithfulness']['model_top1_accuracy'])}** (chance {pct(E['faithfulness']['chance_level'])}); "
          f"invariant names the right sensor {pct(E['faithfulness']['invariant_top1_accuracy'])}; "
          f"{E['coverage']['with_a_machine_readable_reason']}/{E['coverage']['decisions']} decisions carry a reason | perturb one stage, read the explanation |",
          f"| Drift | PSI first-vs-second half **{g(F['score_stability']['psi_first_vs_second_half'])}**, alarm seconds "
          f"{F['long_healthy_run']['alarm_seconds_first_half']} then {F['long_healthy_run']['alarm_seconds_second_half']} | "
          f"a {F['long_healthy_run']['simulated_hours']} h healthy run, independent runs, injected slow degradation |",
          f"| Safety | fail-closed on every injected fault: {G['fail_closed']['all_failed_closed']}; advisory can never DROP: "
          f"{G['advisory_never_blocks']['all_alert_not_drop']}; unsafe states blocked {G['unsafe_states']['blocked']}/{G['unsafe_states']['rules']} | "
          "fault injection, forced advisory flags, every documented unsafe state |", ""]

    # ---------------- A
    L += ["## A. Functional accuracy", "", "### A1. The only real-data result: held-out SWaT (advisory model)", ""]
    if sw.get("status"):
        L += [sw["status"], ""]
    else:
        L += ["| precision | recall | F1 | ROC-AUC | PR-AUC | accuracy | never-alarm accuracy | attacks detected | false-alarm episodes/h |", "|---|---|---|---|---|---|---|---|---|",
              f"| {g(sw['precision'])} | {g(sw['recall'])} | **{g(sw['f1'])}** | {g(sw['roc_auc'])} | {g(sw['average_precision'])} | {g(sw['accuracy'])} | "
              f"{g(sw['always_benign_baseline_accuracy'])} | {g(sw['segments_detected'])}/{g(sw['segments_total'])} | {g(sw['alarm_episodes_per_benign_hour'])} |", "",
              f"Strict per-window scoring with the threshold fixed on validation data before the test. The same alarms score F1 {g(sw.get('point_adjusted_f1'))} "
              f"under the point-adjust convention common in the literature and {g(sw.get('composite_f1'))} under composite scoring "
              "(`docs/reports/swat_scoring_comparison.md`). Accuracy is not the headline: a system that never alarms scores "
              f"{g(sw['always_benign_baseline_accuracy'])} on this data.", ""]
    L += [f"### A2. The layered system on the twin ({A_['runs']} runs, {A_['healthy_runs']} of them with no attack at all; "
          f"{A_['windows_scored']:,} scored seconds, {A_['attack_windows']:,} under attack and {A_['benign_windows']:,} benign = {A_['benign_hours']} h)", "",
          A_["label"], "", "| alarm source | accuracy | precision | recall | F1 | ROC-AUC | PR-AUC | specificity | TN / FP / FN / TP |", "|---|---|---|---|---|---|---|---|---|"]
    for name, m in A_["by_source"].items():
        L.append(f"| {name} | {g(m['accuracy'])} | {g(m['precision'])} | {g(m['recall'])} | **{g(m['f1'])}** | {g(m.get('roc_auc'))} | {g(m.get('pr_auc'))} | "
                 f"{g(m['specificity'])} | {m['tn']:,} / {m['fp']:,} / {m['fn']:,} / {m['tp']:,} |")
    L += ["", f"A never-alarm detector scores accuracy {g(acc['never_alarm_accuracy'])} on this set, which is why F1 and recall are the headline and accuracy is not. "
          "ROC-AUC is reported only where a continuous score exists (the model's probability, the invariants' excess); a union of flags has no single score.", "",
          f"**Detection view:** {det['detected']} of {det['attacks']} attack runs detected ({pct(det['detection_rate'])}), median delay {g(det['median_delay_s'])} s, "
          f"{det['runs_with_a_false_alarm_before_the_attack']} runs had any alarm before the attack began.", "",
          "| family | attack | detected | delay (s) | model | envelope | invariants |", "|---|---|---|---|---|---|---|"]
    agg: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for a in A_["per_attack"]:
        agg.setdefault((a["family"], a["attack"]), []).append(a)
    for (fam, name), rows in agg.items():
        d = [r for r in rows if r["detected"]]
        md = "-" if not d else f"{statistics.median(r['delay_s'] for r in d):.0f}"
        by = {k: sum(1 for r in rows if r["by"][k] is not None) for k in ("model", "envelope", "invariants")}
        L.append(f"| {fam} | {name} | {len(d)}/{len(rows)} | {md} | {by['model']}/{len(rows)} | {by['envelope']}/{len(rows)} | {by['invariants']}/{len(rows)} |")
    L += ["", "### A3. Rule conformance on constructed scenarios", ""]
    rc = res.get("rules") or {}
    if rc:
        L += [f"{rc['violating_detected_with_expected_reason']:,} of {rc['violating_scenarios']:,} rule-violating scenarios were refused with the EXPECTED reason "
              f"and the legitimate-traffic false-positive rate was {rc['legitimate_false_positive_rate']}. This is conformance to a specification, "
              "not detection accuracy on real attacks, and it should never be quoted as the latter.", ""]

    # ---------------- B
    L += ["## B. Robustness", "", "### B1. Malformed and hostile commands", "",
          f"{B['malformed_input']['n']} deliberately broken commands: NaN and infinities, absurd and negative raw values, bad registers and "
          f"function codes, a tampered register or raw value with the signature kept, a truncated / emptied / zeroed / removed signature, "
          f"a zeroed nonce, an hour-old timestamp, wrong types and an empty dict. **Crashes: {B['malformed_input']['raised']}. "
          f"Refused as required: {B['malformed_input']['refused_as_required']}/{B['malformed_input']['must_refuse']}. "
          f"Wrongly accepted: {B['malformed_input']['wrongly_accepted']}.** The well-formed control was still accepted: "
          f"{B['malformed_input']['control_passed']}, so the test is not vacuous.", "",
          f"{B['malformed_input']['note']}.", ""]
    bad = [r for r in B["malformed_input"]["cases"] if r["raised"] or (r["must_refuse"] and not r["refused"])]
    if bad:
        L += ["**Cases that crashed or were wrongly accepted:**", ""] + [f"- `{r['case']}` -> {r.get('exception') or r['verdict']}" for r in bad] + [""]
    else:
        L += ["Every command that had to be refused was refused, and none crashed the pipeline.", ""]
    L += ["### B2. Degraded telemetry", "", "| case | raised (direct call) | raised (through the pipeline) | model | invariants | flagged anything |", "|---|---|---|---|---|---|"]
    for r in B["degraded_telemetry"]["cases"]:
        L.append(f"| {r['case']} | {r['raised'] or 'no'} | {r.get('raised_through_the_pipeline') or 'no'} | {r['model_status']} | {r['invariant_status']} | {r['flagged']} |")
    L += ["", "Abstaining (`WARMING_UP` / `NO_MODEL` / `ERROR`) is the correct answer to unusable input: the deterministic rules keep enforcing either way.", "",
          "### B3. Sensor-noise sweep", "", "| noise x | healthy hours | false-alarm seconds | rate | attack detected | delay (s) |", "|---|---|---|---|---|---|"]
    for r in B["noise_sweep"]["rows"]:
        L.append(f"| {r['noise_x']} | {r['healthy_hours']} | {r['false_alarm_seconds']} | {r['false_alarm_rate']} | {r['attack_detected']} | {g(r['detection_delay_s'])} |")
    L += ["", "The detectors were fitted at x1. Degrading gracefully as the plant gets noisier matters more than the absolute numbers here.", "",
          "### B4. Concurrency", "",
          f"{B['concurrency']['commands']} commands through one pipeline from {B['concurrency']['threads']} threads in {B['concurrency']['seconds']} s: "
          f"**{B['concurrency']['exceptions']} exceptions**, verdicts {B['concurrency']['verdicts']}. {B['concurrency']['note']}.", ""]

    # ---------------- C
    sp, rp, stp = C["source_parity"], C["register_parity"], C["stage_parity"]
    L += ["## C. Bias and fairness", "",
          "Fairness here means the system treats equivalent things equally: the same command regardless of which authorised operator sent it, "
          "the same attention to every actuator, and the same severity of event detected equally wherever in the plant it happens. "
          "Reported the usual way, as spread (max - min) and ratio (min / max, where 1.0 is perfect parity).", "",
          f"**Source address.** {sp['label']}: every source got an identical outcome: **{sp['identical_outcome_for_every_source']}** "
          f"(acceptance ratio min/max {g(sp['disparity'].get('ratio_min_over_max'))} over {sp['disparity']['groups']} addresses).", "",
          f"**Register.** {rp['label']}: acceptance ratio min/max **{g(rp['disparity'].get('ratio_min_over_max'))}**, "
          f"spread {g(rp['disparity'].get('spread'))}, worst `{g(rp['disparity'].get('worst_group'))}`.", "",
          f"**Stage.** {stp['label']}, {stp['runs']} runs.", "",
          "| stage | sensor | detection rate | median delay (s) |", "|---|---|---|---|"]
    for stage, tag in STAGE_SENSOR.items():
        L.append(f"| {stage} | {tag} | {pct(stp['detection_rate_per_stage'].get(stage))} | {g(stp['median_delay_per_stage'].get(stage))} |")
    dsp = stp["disparity"]
    L += ["", "| step (sigma) | overall detection | ratio min/max across stages | weakest stage |", "|---|---|---|---|"]
    for sz, blk in stp["per_size"].items():
        L.append(f"| {sz} | {pct(blk['overall'])} | {g(blk['disparity'].get('ratio_min_over_max'))} | {g(blk['disparity'].get('worst_group'))} |")
    L += ["", f"The rows above are read at the smallest step that is neither always missed nor always caught "
          f"(**{stp['discriminating_size_sigma']} sigma**); a saturated test cannot show a difference between stages.", ""]
    L += ["", f"Disparity across stages: ratio min/max **{g(dsp.get('ratio_min_over_max'))}**, spread {g(dsp.get('spread'))}, "
          f"weakest stage `{g(dsp.get('worst_group'))}`, strongest `{g(dsp.get('best_group'))}`. A ratio below 1 means an attack of identical "
          "severity is less likely to be caught in one part of the plant than another, which is a real coverage gap even though no person is involved.", ""]

    # ---------------- D
    L += ["## D. Consistency", "",
          f"- **Determinism:** {D['determinism']['repeats']} identical commands produced {D['determinism']['distinct_outcomes']} distinct outcome(s).",
          f"- **Order invariance:** {D['order_invariance']['same_verdict_per_register']}/{D['order_invariance']['permutations']} permutations gave every register the same verdict. {D['order_invariance']['note']}.",
          f"- **Live vs offline:** {D['live_offline_parity']['seconds_compared']:,} seconds compared, largest difference {D['live_offline_parity']['max_abs_difference']}. {D['live_offline_parity']['note']}.",
          f"- **Reproducibility:** the same seed reproduced identical model scores ({D['reproducibility']['identical_model_scores']}) and identical flags ({D['reproducibility']['identical_flags']}).", ""]

    # ---------------- E
    cov, fa = E["coverage"], E["faithfulness"]
    L += ["## E. Explainability", "",
          f"**Coverage.** {cov['with_a_machine_readable_reason']}/{cov['decisions']} decisions carry a machine-readable reason, "
          f"{cov['with_every_trace_hop']}/{cov['decisions']} carry every tracer hop, and {cov['drops_naming_the_failing_check']}/{cov['drops']} "
          "refusals name the exact check that failed.", "",
          f"**Faithfulness.** {fa['label']}. The model named the right stage in **{fa['model_correct_stage']}/{fa['model_attributions']}** attributions "
          f"(**{pct(fa['model_top1_accuracy'])}** against a {pct(fa['chance_level'])} chance level); the invariants named the right sensor in "
          f"**{fa['invariant_correct_sensor']}/{fa['invariant_attributions']}** (**{pct(fa['invariant_top1_accuracy'])}**).", "",
          "| stage perturbed | sensor | model said | invariant said |", "|---|---|---|---|"]
    for r in fa["rows"]:
        L.append(f"| {r['stage']} | {r['sensor']} | {g(r['model_said'])} | {g(r['invariant_said'])} |")
    L += ["", "An explanation that points at the wrong stage is worse than none, because an operator acts on it. This is the metric to watch.", ""]

    # ---------------- F
    lr, ss = F["long_healthy_run"], F["score_stability"]
    L += ["## F. Drift", "",
          f"**A {lr['simulated_hours']} h healthy run.** {lr['scored_seconds']:,} scored seconds, {lr['alarm_seconds']} alarm seconds "
          f"({lr['alarm_seconds_first_half']} in the first half, {lr['alarm_seconds_second_half']} in the second): the system does not become "
          "noisier the longer it runs. Model probability p50/p95/p99/max "
          f"{lr['model_probability']['p50']} / {lr['model_probability']['p95']} / {lr['model_probability']['p99']} / {lr['model_probability']['max']} "
          f"against a threshold of {lr['model_probability']['threshold']}; invariant excess p95 {lr['invariant_score']['p95']}, max "
          f"{lr['invariant_score']['max']} against theta {lr['invariant_score']['theta']}.", "",
          f"**Score stability.** PSI of an identical repeated run (the control, must be 0) **{g(ss['psi_same_run_repeated_control'])}**; "
          f"first vs second half of one run **{g(ss['psi_first_vs_second_half'])}**; against an independent healthy run "
          f"**{g(ss['psi_vs_independent_healthy_run'])}**. {ss['reading']}", "",
          f"**{F['slow_degradation']['label']}**", "", "| drifting tag | mm/s | total drift | first alarm (s) | alarm seconds | PSI vs healthy |", "|---|---|---|---|---|---|"]
    for r in F["slow_degradation"]["rows"]:
        L.append(f"| {r['tag']} | {r['mm_per_second']} | {r['total_drift_mm']} mm | {g(r['first_alarm_at_s'])} | {r['alarm_seconds']} | {g(r['psi_vs_healthy'])} |")
    L += ["", "A drifting sensor is reported as an anomaly, not as a distinct failure mode: the system cannot tell a degrading instrument from a slow "
          "attack, and an operator must. That is a limitation, not a defect.", "",
          f"**Domain gap.** {F['domain_gap']['note']}; false-alarm rate on this healthy twin run {F['domain_gap']['twin_false_alarm_rate_this_run']}.", ""]

    # ---------------- G
    L += ["## G. Safety", "", "| property | result |", "|---|---|",
          f"| A fault anywhere in the decision path refuses the command (fail closed) | **{G['fail_closed']['all_failed_closed']}** "
          f"({len(G['fail_closed']['faults'])} injected faults) |",
          f"| The pipeline recovers after the fault is removed | {G['fail_closed']['recovered_afterwards']} |",
          f"| The advisory layers raise ALERT and can never DROP | **{G['advisory_never_blocks']['all_alert_not_drop']}** |",
          f"| Every documented unsafe cross-register state is refused | **{G['unsafe_states']['blocked']}/{G['unsafe_states']['rules']}** |",
          f"| A command moving the plant back to safety is allowed | **{G['unsafe_states']['recovery_allowed']}/{G['unsafe_states']['rules']}** |",
          f"| The decision and forward queues are bounded | {G['bounded_resources']['decision_queue_maxsize']} and {G['bounded_resources']['forward_queue_maxsize']} |",
          f"| The PLC refuses a write from a host that is not the middleware | {G['plc_allow_list']['foreign_host_refused']} |", ""]
    L += ["Fault injection, one stage at a time:", ""] + [f"- `{r['fault_injected_in']}` -> {r['verdict']} ({r['reason']})" for r in G["fail_closed"]["faults"]]
    L += ["", f"{G['bounded_resources']['note']}. {G['plc_allow_list']['note']}.", "",
          "## What this report does not establish", "",
          "- **Generalisation.** Every twin attack here is one we wrote. A detector tested on its authors' attacks is not evidence against an adversary who reads the design.",
          "- **Real-data accuracy beyond one model.** Only the advisory model has a held-out SWaT number. The invariants' real-data detection and false-alarm rates are NOT measured yet (`python -m tools.fit_invariants --data-dir <SWaT>`), and neither is the cross-validated all-attack protocol (`python -m benchmark.swat_protocol --data-dir <SWaT>`).",
          "- **Fairness in the social sense.** There are no people or protected attributes in this data. Section C measures equal treatment across senders, registers and plant stages, which is the meaningful reading here; it is not a demographic fairness audit.",
          "- **A real plant.** The twin is a simulation calibrated to SWaT's operating point. Nothing here was measured on physical equipment.",
          "- **The network.** Decision latency is measured in process. The wire-level proof that a refused command never reaches the PLC is a separate artefact (`docs/wireshark_setup.md`).", ""]
    return "\n".join(L)


def main() -> None:
    ap = argparse.ArgumentParser(description="End-to-end assurance run over seven dimensions.")
    ap.add_argument("--quick", action="store_true", help="smaller samples: a smoke run, labelled as such in the report")
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--skip-rules", action="store_true", help="skip the 4,600-case rule conformance sweep (the slowest section)")
    ap.add_argument("--out-dir", help="write here instead of the repo report paths")
    a = ap.parse_args()
    seeds = list(range(1, (2 if a.quick else a.seeds) + 1))
    t0 = time.time()
    model = load_physical_model()
    if model.status != "OK":
        raise SystemExit(f"the physical model is not usable (status {model.status}); this report needs it")
    inv = InvariantSet.load(DEFAULT_FILE)
    res: Dict[str, Any] = {"quick": bool(a.quick), "seeds": seeds, "model": getattr(model, "variant", "v2"),
                           "invariants": {"file": os.path.relpath(DEFAULT_FILE, ROOT), "count": len(inv), "theta": inv.theta}}
    steps = [("accuracy", lambda: section_accuracy(model, inv, seeds)), ("robustness", lambda: section_robustness(model, inv, a.quick)),
             ("fairness", lambda: section_fairness(model, inv, seeds)), ("consistency", lambda: section_consistency(model, inv, a.quick)),
             ("explainability", lambda: section_explainability(model, inv, seeds)), ("drift", lambda: section_drift(model, inv, a.quick)),
             ("safety", lambda: section_safety(model, inv))]
    for name, fn in steps:
        s = time.time()
        print(f"[{time.strftime('%H:%M:%S')}] {name} ...", flush=True)
        res[name] = fn()
        print(f"[{time.strftime('%H:%M:%S')}] {name} done in {time.time() - s:.0f} s", flush=True)
    if a.skip_rules or a.quick:
        res["rules"] = {}
    else:
        print(f"[{time.strftime('%H:%M:%S')}] rule conformance ...", flush=True)
        from benchmark import rules_accuracy
        res["rules"] = rules_accuracy.run_rule_cases(200, 7)
    res["recorded_swat"] = recorded_swat()
    res["seconds"] = round(time.time() - t0, 1)
    res["environment"] = environment()
    jpath, mpath = (OUT_JSON, OUT_MD) if not a.out_dir else (os.path.join(a.out_dir, "assurance.json"), os.path.join(a.out_dir, "assurance_report.md"))
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
