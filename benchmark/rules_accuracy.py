"""
benchmark/rules_accuracy.py - RULE-BASED checks on CONSTRUCTED scenarios. NOT SWaT data, NOT a learned model.

    python -m benchmark.rules_accuracy [--per-case 200] [--seed 7]

Every cyber and physical rule is exercised with randomised violating commands, and with randomised legitimate commands to measure
false positives. A scenario "detects" when the REAL pipeline (rule agents + orchestrator, physical ML model cold) returns DROP with
the EXPECTED reason. The rules are deterministic, so these numbers are expected to be 100 %: they are a regression check that each
rule fires on what it was written for, not evidence of detection performance against an unknown attacker. Scenarios are built on a
virtual clock (benchmark/workload.py), so they are exactly reproducible.

Part 2 replays the randomised attacker plans (attacker/scenarios.py) through the same agents. Here the honest finding is that the
stealthy SWaT-derived behaviours (freeze, ramp) are mostly in-bounds and slow, so the RULES do not stop them: that is what the
advisory physical model is for (measured separately, see the twin section).
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from typing import Any, Callable, Dict, List, Tuple

import numpy as np

from attacker import scenarios as atk
from benchmark import workload as W
from benchmark.env import environment
from docs import hmac_auth
from docs.interfaces import (CROSS_REGISTER_RULES, LIT101, MACHINE_BY_REGISTER, MV101, PIT501, P501, to_raw)
from middleware import cyber_agent, orchestrator
from pipeline.multi_model_pipeline import MultiModelPipeline

Case = Tuple[str, str, str]          # (layer, case name, expected reason prefix or "PASS")


def _rule_cases(rng: np.random.Generator) -> List[Tuple[Case, Callable[[int], Tuple[List[Dict[str, Any]], Dict[str, Any]]]]]:
    """Each builder returns (commands in order, state); the LAST command is the one whose verdict is judged."""
    acts, sens = W.actuators(), W.sensors()
    regs = W.nominal_registers()
    T = W.T0 + 1000.0

    def act():
        return int(rng.choice(acts))

    def state_for(r=None):
        return W.make_state(r or regs, T - 10.0)

    def legit(i):
        reg = act()
        lo, hi = W.bounds(reg)
        v = float(np.clip(regs[reg] + rng.uniform(-3, 3), lo, hi))
        return [W.signed(reg, v, T, tx=f"c{i}")], state_for()

    def untrusted(i):
        reg = act()
        return [W.signed(reg, regs[reg], T, ip=f"{W.UNTRUSTED_PREFIX}{int(rng.integers(1, 250))}.{int(rng.integers(1, 250))}", tx=f"c{i}")], state_for()

    def bad_fc(i):
        reg = act()
        return [W.signed(reg, regs[reg], T, fc=int(rng.choice([1, 2, 4, 5, 15, 23, 43])), tx=f"c{i}")], state_for()

    def bad_register(i):
        fr = hmac_auth.build_frame(int(rng.integers(20, 2000)), 50.0, timestamp_ms=int(T * 1000))
        return [W.signed(0, 0, T, frame=fr, tx=f"c{i}")], state_for()

    def rate(i):
        reg = act()
        k = int(rng.integers(6, 25))
        return [W.signed(reg, regs[reg], T + j * (0.8 / k), tx=f"c{i}-{j}") for j in range(k)], state_for()

    def hmac_missing(i):
        reg = act()
        return [W.unsigned(reg, regs[reg], T, tx=f"c{i}")], state_for()

    def hmac_tamper(i):
        reg = act()
        lo, hi = W.bounds(reg)
        fr = hmac_auth.build_frame(reg, regs[reg], timestamp_ms=int(T * 1000))
        fr[2] = to_raw(float(rng.uniform(lo, hi)) + 0.1)
        if fr[2] == to_raw(regs[reg]):                 # a "tamper" must actually change the signed value
            fr[2] = to_raw(regs[reg]) + 1
        return [W.signed(reg, 0, T, frame=fr, tx=f"c{i}")], state_for()

    def hmac_wrong_key(i):
        reg = act()
        return [W.signed(reg, regs[reg], T, key=bytes(rng.integers(0, 256, 32, dtype=np.uint8)), tx=f"c{i}")], state_for()

    def hmac_expired(i):
        reg = act()
        age = float(rng.choice([-1, 1])) * float(rng.uniform(45, 3600))
        fr = hmac_auth.build_frame(reg, regs[reg], timestamp_ms=int((T - age) * 1000))
        return [W.signed(reg, 0, T, frame=fr, tx=f"c{i}")], state_for()

    def replay(i):
        reg = act()
        fr = hmac_auth.build_frame(reg, regs[reg], timestamp_ms=int(T * 1000))
        gap = float(rng.uniform(0.05, 10.0))
        return [W.signed(reg, 0, T, frame=fr, tx=f"c{i}a"), W.signed(reg, 0, T + gap, frame=fr, tx=f"c{i}b")], state_for()

    def sensor_write(i):
        reg = int(rng.choice(sens))
        lo, hi = W.bounds(reg)
        return [W.signed(reg, float(rng.uniform(lo, hi)), T, tx=f"c{i}")], state_for()

    def oob(i):
        reg = act()
        return [W.signed(reg, float(W.bounds(reg)[1] * rng.uniform(1.2, 60)), T, tx=f"c{i}")], state_for()

    def rate_of_change(i):
        reg = act()
        m = MACHINE_BY_REGISTER[reg]
        dt = float(rng.uniform(0.5, 5.0))
        lo, hi = W.bounds(reg)
        need = m["rate_per_sec"] * 1.1 * dt * float(rng.uniform(1.5, 4.0))
        cur = regs[reg]
        target = cur + need if cur + need <= hi else cur - need
        if not (lo <= target <= hi):
            reg, target, dt = acts[0], 100.0, 0.5            # MV101 0.5 s: jump of 45 vs max 5.5
        st = dict(regs)
        return [W.signed(reg, float(np.clip(target, lo, hi)), T, tx=f"c{i}")], W.make_state(st, T - dt)

    def cross(rule):
        (r1, op1, th1), (r2, op2, th2) = rule["conditions"][0], rule["conditions"][1]

        def build(i):
            st = dict(regs)
            st[r2] = min(W.bounds(r2)[1], th2 + 4) if op2 == ">=" else max(0.0, th2 - 4)
            st[r1] = th1 - 3 if op1 == ">=" else th1 + 3
            goal = th1 + float(rng.uniform(0.5, 4)) if op1 == ">=" else max(0.0, th1 - float(rng.uniform(0.5, 4)))
            return [W.signed(r1, float(np.clip(goal, *W.bounds(r1))), T, tx=f"c{i}")], W.make_state(st, T - 10.0)
        return build

    def valve_low_level(i):
        st = dict(regs)
        st[LIT101], st[MV101] = float(rng.uniform(10, 200)), 60.0
        return [W.signed(MV101, float(rng.uniform(5, 30)), T, tx=f"c{i}")], W.make_state(st, T - 10.0)

    def ro_overload(i):
        st = dict(regs)
        st[PIT501] = float(rng.uniform(320, 345))
        return [W.signed(P501, float(rng.uniform(92, 100)), T, tx=f"c{i}")], W.make_state(st, T - 10.0)

    cases = [
        (("legitimate", "operator command, in bounds, slow", "PASS"), legit),
        (("cyber", "untrusted source", "UNTRUSTED_SOURCE"), untrusted),
        (("cyber", "invalid function code", "INVALID_FUNCTION_CODE"), bad_fc),
        (("cyber", "unknown register", "INVALID_REGISTER"), bad_register),
        (("cyber", "rate-limit burst", "RATE_LIMIT_EXCEEDED"), rate),
        (("cyber", "HMAC missing (unsigned)", "HMAC_MISSING"), hmac_missing),
        (("cyber", "HMAC invalid: value tampered", "HMAC_INVALID"), hmac_tamper),
        (("cyber", "HMAC invalid: wrong key", "HMAC_INVALID"), hmac_wrong_key),
        (("cyber", "HMAC expired / future-dated", "HMAC_EXPIRED"), hmac_expired),
        (("cyber", "replayed frame", "REPLAY_DETECTED"), replay),
        (("physical", "write to a sensor register", "WRITE_TO_SENSOR_REGISTER"), sensor_write),
        (("physical", "out-of-bounds value", "OUT_OF_BOUNDS"), oob),
        (("physical", "rate of change too fast", "RATE_OF_CHANGE_EXCEEDED"), rate_of_change),
        (("physical", "stage rule VALVE_CLOSING_LOW_LEVEL", "CROSS_REGISTER_VIOLATION:VALVE_CLOSING_LOW_LEVEL"), valve_low_level),
        (("physical", "stage rule RO_PRESSURE_OVERLOAD", "CROSS_REGISTER_VIOLATION:RO_PRESSURE_OVERLOAD"), ro_overload),
    ]
    for rule in CROSS_REGISTER_RULES:
        cases.append((("physical", f"cross-register {rule['id']}", f"CROSS_REGISTER_VIOLATION:{rule['id']}"), cross(rule)))
    return cases


def metrics(tp: int, fp: int, fn: int, tn: int) -> Dict[str, Any]:
    n = tp + fp + fn + tn
    prec = tp / (tp + fp) if tp + fp else None
    rec = tp / (tp + fn) if tp + fn else None
    spec = tn / (tn + fp) if tn + fp else None
    f1 = 2 * prec * rec / (prec + rec) if prec and rec else (0.0 if prec is not None and rec is not None else None)
    r = lambda v: None if v is None else round(float(v), 4)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "n": n, "accuracy": r((tp + tn) / n if n else None), "precision": r(prec), "recall": r(rec),
            "specificity": r(spec), "f1": r(f1), "false_positive_rate": r(1 - spec if spec is not None else None),
            "balanced_accuracy": r((rec + spec) / 2 if rec is not None and spec is not None else None)}


def command_confusion(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """COMMAND-level confusion of the RULE layers on the constructed scenarios. Positive = a violating command; flagged = DROP or ALERT.
    Also the 3-class matrix (truth PASS/DROP x predicted PASS/ALERT/DROP) and per-layer binary scores (that layer's violations vs the legitimate commands)."""
    leg = next(r for r in rows if r["layer"] == "legitimate")
    flagged = lambda r: r["predicted"]["DROP"] + r["predicted"]["ALERT"]
    viol = [r for r in rows if r["layer"] != "legitimate"]
    overall = metrics(sum(flagged(r) for r in viol), flagged(leg), sum(r["predicted"]["PASS"] for r in viol), leg["predicted"]["PASS"])
    three = {"truth_PASS (legitimate)": leg["predicted"], "truth_DROP (violating)": {c: sum(r["predicted"][c] for r in viol) for c in ("PASS", "ALERT", "DROP")}}
    layers = {}
    for layer in ("cyber", "physical"):
        v = [r for r in viol if r["layer"] == layer]
        layers[layer] = metrics(sum(r["as_expected"] for r in v), leg["n"] - leg["as_expected"], sum(r["n"] - r["as_expected"] for r in v), leg["as_expected"])
    return {"overall": overall, "three_class": three, "per_layer": layers}


def judge(decision: Dict[str, Any], expected: str) -> Tuple[bool, str]:
    if expected == "PASS":
        return decision["verdict"] in ("PASS", "ALERT"), decision["reason"].split(":")[0]
    return decision["verdict"] == "DROP" and decision["reason"].startswith(expected), decision["reason"].split(":")[0] if decision["verdict"] == "DROP" else decision["verdict"]


def run_rule_cases(per_case: int = 200, seed: int = 7) -> Dict[str, Any]:
    orchestrator._forward_decision_to_dashboard = lambda payload: None
    rng = np.random.default_rng(seed)
    pipe = MultiModelPipeline()
    rows = []
    for (layer, name, expected), build in _rule_cases(rng):
        ok, any_drop, seen, pred_classes = 0, 0, Counter(), Counter()
        for i in range(per_case):
            cmds, state = build(i)
            cyber_agent.reset_state()
            dec = None
            for c in cmds:
                dec = pipe.process_command(c, state)["decision"]
            good, got = judge(dec, expected)
            ok += good
            any_drop += dec["verdict"] == "DROP"
            pred_classes[dec["verdict"]] += 1
            if not good:
                seen[got] += 1
        rows.append({"layer": layer, "case": name, "expected": expected, "n": per_case, "as_expected": ok,
                     "rate": round(ok / per_case, 4), "dropped_any_reason": any_drop, "unexpected_outcomes": dict(seen),
                     "predicted": {c: pred_classes.get(c, 0) for c in ("PASS", "ALERT", "DROP")}})
    pipe.shutdown()
    leg = next(r for r in rows if r["layer"] == "legitimate")
    viol = [r for r in rows if r["layer"] != "legitimate"]
    conf = command_confusion(rows)
    return {"label": "RULE-BASED checks on CONSTRUCTED scenarios (deterministic rules; NOT SWaT, NOT a learned model)",
            "per_case": per_case, "seed": seed, "cases": rows,
            "legitimate_false_positive_rate": round(1 - leg["rate"], 4), "confusion": conf,
            "violating_scenarios": sum(r["n"] for r in viol), "violating_detected_with_expected_reason": sum(r["as_expected"] for r in viol)}


def _benign_run(rng: np.random.Generator) -> Dict[str, Any]:
    """A legitimate operator session: a few small, slow, in-bounds set-point changes on random actuators, spaced 2 to 10 s apart."""
    acts = W.actuators()
    steps, t = [], 0.0
    for _ in range(int(rng.integers(2, 6))):
        reg = int(rng.choice(acts))
        lo, hi = W.bounds(reg)
        nominal = W.nominal_registers()[reg]
        steps.append({"t": round(t, 3), "kind": "signed", "register": reg, "tag": str(reg), "value": float(np.clip(nominal + rng.uniform(-3, 3), lo, hi))})
        t += float(rng.uniform(2.0, 10.0))
    return {"steps": steps}


def run_attack_plans(per_type: int = 100, seed: int = 11) -> Dict[str, Any]:
    """Randomised attacker plans through the real rule agents on a virtual clock (state follows the commands that were let through)."""
    orchestrator._forward_decision_to_dashboard = lambda payload: None
    pipe = MultiModelPipeline()
    out = {}
    for typ, origin in atk.TYPES.items():
        dropped_runs, first_drop, reasons, frames, frames_dropped = 0, [], Counter(), 0, 0
        for s in range(per_type):
            plan = atk.make_plan(typ, seed + s)
            cyber_agent.reset_state()
            regs, changed = W.nominal_registers(), {}
            t0 = W.T0 + 5000.0 + s * 100.0
            first = None
            for k, st in enumerate(plan["steps"]):
                t = t0 + st["t"]
                state = W.make_state(regs, changed.get(st["register"], t - 10.0))
                if st["kind"] == "replay_of":
                    src = plan["steps"][st["ref"]]
                    fr = hmac_auth.build_frame(src["register"], src["value"], timestamp_ms=int((t0 + src["t"]) * 1000))
                    cmd = W.signed(0, 0, t, frame=fr, tx=f"p{s}-{k}")
                else:
                    fr = hmac_auth.build_frame(st["register"], st["value"], timestamp_ms=int(t * 1000))
                    cmd = W.signed(0, 0, t, frame=fr, tx=f"p{s}-{k}")
                dec = pipe.process_command(cmd, state)["decision"]
                frames += 1
                if dec["verdict"] == "DROP":
                    frames_dropped += 1
                    reasons[dec["reason"].split(":")[0]] += 1
                    first = k if first is None else first
                else:
                    regs[st["register"]] = st["value"]
                    changed[st["register"]] = t
            dropped_runs += first is not None
            if first is not None:
                first_drop.append(first + 1)
        out[typ] = {"origin": origin, "runs": per_type, "runs_with_a_drop": dropped_runs, "run_drop_rate": round(dropped_runs / per_type, 4),
                    "frames": frames, "frames_dropped": frames_dropped,
                    "median_frame_of_first_drop": float(np.median(first_drop)) if first_drop else None, "drop_reasons": dict(reasons.most_common())}
    benign_flagged, benign_runs = 0, per_type
    rng = np.random.default_rng(seed + 999)
    for s in range(benign_runs):
        plan = _benign_run(rng)
        cyber_agent.reset_state()
        regs, changed = W.nominal_registers(), {}
        t0 = W.T0 + 90000.0 + s * 100.0
        flagged = False
        for k, st in enumerate(plan["steps"]):
            t = t0 + st["t"]
            fr = hmac_auth.build_frame(st["register"], st["value"], timestamp_ms=int(t * 1000))
            dec = pipe.process_command(W.signed(0, 0, t, frame=fr, tx=f"b{s}-{k}"), W.make_state(regs, changed.get(st["register"], t - 10.0)))["decision"]
            if dec["verdict"] in ("DROP", "ALERT"):
                flagged = True
            else:
                regs[st["register"]], changed[st["register"]] = st["value"], t
        benign_flagged += flagged
    attack_runs = sum(v["runs"] for v in out.values())
    attack_detected = sum(v["runs_with_a_drop"] for v in out.values())
    run_conf = metrics(attack_detected, benign_flagged, attack_runs - attack_detected, benign_runs - benign_flagged)
    pipe.shutdown()
    return {"run_level_confusion": run_conf, "benign_runs": benign_runs,
            "label": "Randomised ATTACKER PLANS through the RULE agents (constructed; swat-derived types follow SWaT behaviours, "
                     "synthetic-extension types are network-layer constructions; physical ML model cold)",
            "runs_per_type": per_type, "seed": seed, "types": out}


def run(per_case: int = 200, per_type: int = 100, seed: int = 7) -> Dict[str, Any]:
    return {"rules": run_rule_cases(per_case, seed), "attacker_plans": run_attack_plans(per_type, seed + 4)}


def main() -> None:
    ap = argparse.ArgumentParser(description="Rule-based accuracy on constructed scenarios.")
    ap.add_argument("--per-case", type=int, default=200)
    ap.add_argument("--per-type", type=int, default=100)
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    res = run(a.per_case, a.per_type, a.seed)
    r = res["rules"]
    print(r["label"])
    for c in r["cases"]:
        print(f"  {c['layer']:<10} {c['case']:<44} {c['as_expected']:>4}/{c['n']}  {c['unexpected_outcomes'] or ''}")
    print(f"\nlegitimate false-positive rate {r['legitimate_false_positive_rate']:.2%}; "
          f"violating scenarios detected with the expected reason {r['violating_detected_with_expected_reason']}/{r['violating_scenarios']}")
    print("\n" + res["attacker_plans"]["label"])
    for t, v in res["attacker_plans"]["types"].items():
        print(f"  {t:<19} [{v['origin']}] runs with a drop {v['runs_with_a_drop']}/{v['runs']}  reasons {v['drop_reasons']}")


if __name__ == "__main__":
    main()
