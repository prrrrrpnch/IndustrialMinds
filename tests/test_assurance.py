"""
tests/test_assurance.py - the assurance harness (benchmark/assurance.py): its statistics on hand-made inputs, the attack injectors,
and one small real run of each of the seven sections.

    python -m tests.test_assurance

These checks prove the harness measures what it claims. The numbers IT produces are twin measurements; see docs/reports/assurance_report.md.
"""

from __future__ import annotations

import os
import tempfile

os.environ.setdefault("IM_LOG_DIR", tempfile.mkdtemp(prefix="im-asr-test-"))

import numpy as np  # noqa: E402

from benchmark import assurance as A  # noqa: E402
from models.invariant_monitor import DEFAULT_FILE  # noqa: E402
from models.physical_model_v2 import load_physical_model  # noqa: E402
from swat.invariants import InvariantSet  # noqa: E402
from swat.physical_features import SENSORS  # noqa: E402

fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global fails
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    fails += 0 if cond else 1


print("THE METRICS, ON NUMBERS THAT CAN BE CHECKED BY HAND")
y = np.array([1, 1, 1, 1, 0, 0, 0, 0, 0, 0], bool)
f = np.array([1, 1, 0, 0, 1, 0, 0, 0, 0, 0], bool)
m = A.classification(y, f)
check("the four counts", (m["tp"], m["fp"], m["fn"], m["tn"]) == (2, 1, 2, 5), str((m["tp"], m["fp"], m["fn"], m["tn"])))
check("precision 2/3, recall 2/4, F1 0.5714, accuracy 0.7", (m["precision"], m["recall"], m["f1"], m["accuracy"]) == (0.6667, 0.5, 0.5714, 0.7))
check("specificity 5/6 and the false-positive rate are consistent", m["specificity"] == 0.8333 and abs(m["false_positive_rate"] - 0.1667) < 1e-9)
check("the never-alarm baseline is reported next to accuracy", m["never_alarm_accuracy"] == 0.6)
check("balanced accuracy is the mean of recall and specificity", abs(m["balanced_accuracy"] - (0.5 + 0.8333) / 2) < 1e-3)
perfect = A.classification(y, y, np.where(y, 0.9, 0.1))
check("a perfect detector scores 1.0 everywhere, ROC-AUC included", perfect["f1"] == 1.0 and perfect["roc_auc"] == 1.0 and perfect["pr_auc"] == 1.0)
rng = np.random.default_rng(0)
yy = rng.random(4000) < 0.3
chance = A.classification(yy, rng.random(4000) < 0.3, rng.random(4000))
check("a chance detector scores ROC-AUC about 0.5", 0.45 < chance["roc_auc"] < 0.55, str(chance["roc_auc"]))
none = A.classification(y, np.zeros(10, bool))
check("a detector that never alarms has undefined precision, recall 0 and no crash", none["precision"] is None and none["recall"] == 0.0)
check("scores that are all NaN produce no ROC-AUC rather than a wrong one", "roc_auc" not in A.classification(y, f, np.full(10, np.nan)))

print("\nFAIRNESS STATISTICS")
d = A.disparity({"S1": 1.0, "S2": 0.5, "S3": 0.75})
check("spread is max - min and the ratio is min / max", d["spread"] == 0.5 and d["ratio_min_over_max"] == 0.5 and d["groups"] == 3)
check("the weakest and strongest groups are named", d["worst_group"] == "S2" and d["best_group"] == "S1")
eq = A.disparity({"a": 0.8, "b": 0.8})
check("perfect parity is ratio 1.0 and spread 0", eq["ratio_min_over_max"] == 1.0 and eq["spread"] == 0.0)
check("groups with no value are skipped, not counted as zero", A.disparity({"a": 1.0, "b": None})["groups"] == 1)
check("no groups at all does not crash", A.disparity({})["groups"] == 0)

print("\nDRIFT STATISTIC (PSI)")
base = np.random.default_rng(1).normal(0, 1, 5000)
check("the same distribution gives PSI about 0", abs(A.psi(base, np.random.default_rng(2).normal(0, 1, 5000))) < 0.05, str(A.psi(base, np.random.default_rng(2).normal(0, 1, 5000))))
shifted = A.psi(base, np.random.default_rng(3).normal(1.5, 1, 5000))
check("a shifted distribution gives a large PSI", shifted > 0.25, str(shifted))
check("PSI grows with the size of the shift", A.psi(base, np.random.default_rng(4).normal(3, 1, 5000)) > shifted)
check("too few samples give None rather than a meaningless number", A.psi(base, base[:10]) is None)

print("\nTHE ATTACK INJECTORS DO WHAT THEY SAY")
model = load_physical_model()
inv = InvariantSet.load(DEFAULT_FILE)
check("the live physical model and the twin invariant file both load", model.status == "OK" and len(inv) > 0, f"{model.status}, {len(inv)} invariants")
reg = {m_["register"]: 100.0 for m_ in __import__("core.interfaces", fromlist=["MACHINES"]).MACHINES}
lit = A.MACHINE_BY_NAME["LIT101"]["register"]
for kind, expect in [("freeze", "holds the first value"), ("dead", "reads zero"), ("bias", "adds a fixed offset"), ("ramp", "grows with time")]:
    t = A.Tamper(kind, "LIT101", 4.0, model.norm)
    r0, r1 = dict(reg), dict(reg)
    t.apply(r0, 0)
    r1[lit] = 500.0
    t.apply(r1, 300)
    if kind == "freeze":
        ok = r0[lit] == 100.0 and r1[lit] == 100.0            # the held value, not the new reading
    elif kind == "dead":
        ok = r0[lit] == 0.0 and r1[lit] == 0.0
    elif kind == "bias":
        ok = abs(r0[lit] - 100.0 - 4.0 * t.sd) < 1e-6 and abs(r1[lit] - 500.0 - 4.0 * t.sd) < 1e-6
    else:
        ok = r0[lit] == 100.0 and r1[lit] > 500.0             # nothing at t=0, full size later
    check(f"tamper '{kind}' {expect}", ok, f"{r0[lit]:.2f} then {r1[lit]:.2f}")
check("the perturbation size is in sigma of that sensor's measured spread", abs(A.Tamper("bias", "LIT101", 1.0, model.norm).sd - float(model.norm.sd[SENSORS.index("LIT101")])) < 1e-9)
check("the wire rounds to the Modbus 0.1 resolution", A.wire(1.2345) == 1.2 and A.wire(1.26) == 1.3)
check("first_after measures from the injection and ignores anything before it",
      A.first_after(np.array([1, 0, 0, 0, 1, 1], bool), 3) == 1 and A.first_after(np.array([1, 0, 0], bool), 1) is None)

print("\nONE SMALL REAL RUN OF EACH SECTION")
A.SETTLE_S, A.ATTACK_S = 200, 120
A.ACTUATOR_ATTACKS = {k: v for k, v in A.ACTUATOR_ATTACKS.items() if k.startswith("ro_deadhead")}
A.SENSOR_ATTACKS = [("step", "LIT401", 8.0)]
A.STAGE_SENSOR = {"S1": "LIT101", "S4": "LIT401"}
seeds = [1]

acc = A.section_accuracy(model, inv, seeds)
check("accuracy: healthy runs are pooled in, so the benign side is real operation", acc["healthy_runs"] == 1 and acc["benign_windows"] > acc["attack_windows"])
for name, mm in acc["by_source"].items():
    assert mm["n"] > 0, name
check("accuracy: every alarm source gets the full metric set", all({"precision", "recall", "f1", "accuracy"} <= set(v) for v in acc["by_source"].values()))
check("accuracy: the model's ROC-AUC is computed from its probability", "roc_auc" in acc["by_source"]["advisory model (v2)"])
check("accuracy: the layered system is never worse than its parts at catching attacks",
      acc["by_source"]["model OR envelope OR invariants (current)"]["tp"] >= max(acc["by_source"]["advisory model (v2)"]["tp"], acc["by_source"]["physical invariants"]["tp"]))
check("accuracy: healthy runs are excluded from the per-attack table", all(r["family"] != "healthy" for r in acc["per_attack"]))

rob = A.section_robustness(model, inv, quick=True)
mi = rob["malformed_input"]
check("robustness: no malformed command crashed the pipeline", mi["raised"] == 0, f"{mi['raised']} of {mi['n']}")
check("robustness: every command that must be refused was refused", mi["wrongly_accepted"] == 0, f"{mi['wrongly_accepted']} of {mi['must_refuse']}")
check("robustness: a tampered signature, register or raw value is always rejected",
      all(r["refused"] for r in mi["cases"] if "mac" in r["case"] or "tampered" in r["case"] or "nonce" in r["case"]),
      str([r["case"] for r in mi["cases"] if ("mac" in r["case"] or "tampered" in r["case"]) and not r["refused"]]))
check("robustness: the fuzzer attacks the fields the signature actually covers",
      any("mac zeroed" == r["case"] for r in mi["cases"]) and any("raw_value tampered (signature kept)" == r["case"] for r in mi["cases"]))
check("robustness: the well-formed control was still accepted (the test is not vacuous)", mi["control_passed"])
check("robustness: unusable telemetry makes the detectors abstain rather than flag",
      rob["degraded_telemetry"]["raised"] == 0 and rob["degraded_telemetry"]["flagged_on_garbage"] == 0,
      str([c["case"] for c in rob["degraded_telemetry"]["cases"] if c["raised"]]))
check("robustness: the real telemetry entry point never raises either", rob["degraded_telemetry"]["raised_through_the_pipeline"] == 0)
check("robustness: concurrent load raised no exception", rob["concurrency"]["exceptions"] == 0, str(rob["concurrency"]["examples"]))
check("robustness: the noise sweep reports a false-alarm rate and a detection result per level", all({"false_alarm_rate", "attack_detected"} <= set(r) for r in rob["noise_sweep"]["rows"]))

fair = A.section_fairness(model, inv, seeds)
check("fairness: every trusted source address got the identical outcome", fair["source_parity"]["identical_outcome_for_every_source"])
check("fairness: no register is treated differently for a legitimate command", fair["register_parity"]["disparity"]["ratio_min_over_max"] == 1.0)
check("fairness: the stage test sweeps the perturbation size instead of saturating", len(fair["stage_parity"]["per_size"]) >= 2 and "discriminating_size_sigma" in fair["stage_parity"])
check("fairness: a disparity figure is reported for the stages", "ratio_min_over_max" in fair["stage_parity"]["disparity"])

con = A.section_consistency(model, inv, quick=True)
check("consistency: an identical command always gives the identical verdict", con["determinism"]["distinct_outcomes"] == 1, str(con["determinism"]["outcomes"]))
check("consistency: order-independent rules do not depend on order",
      con["order_invariance"]["same_verdict_per_register"] == con["order_invariance"]["permutations"])
check("consistency: the live monitor matches the offline engine exactly", con["live_offline_parity"]["max_abs_difference"] < 1e-9, str(con["live_offline_parity"]["max_abs_difference"]))
check("consistency: the same seed reproduces the same run", con["reproducibility"]["identical_model_scores"] and con["reproducibility"]["identical_flags"])

exp = A.section_explainability(model, inv, seeds)
cov = exp["coverage"]
check("explainability: every decision carries a machine-readable reason", cov["with_a_machine_readable_reason"] == cov["decisions"])
check("explainability: every decision carries a complete tracer record", cov["with_every_trace_hop"] == cov["decisions"], f"{cov['with_every_trace_hop']}/{cov['decisions']}")
check("explainability: every refusal names the check that failed", cov["drops"] > 0 and cov["drops_naming_the_failing_check"] == cov["drops"])
fa = exp["faithfulness"]
check("explainability: the attribution is scored against a stated chance level", fa["chance_level"] == round(1 / len(A.STAGE_SENSOR), 4))
check("explainability: at least one explanation was produced to score", (fa["model_attributions"] + fa["invariant_attributions"]) > 0)
check("explainability: the invariant attribution now names an invariant (it used to be empty)",
      fa["invariant_attributions"] == 0 or any(r["invariant_said"] for r in fa["rows"]), str([r["invariant_said"] for r in fa["rows"]]))

dr = A.section_drift(model, inv, quick=True)
check("drift: repeating the identical run gives PSI 0 (the control that makes the others readable)",
      dr["score_stability"]["psi_same_run_repeated_control"] == 0.0, str(dr["score_stability"]["psi_same_run_repeated_control"]))
check("drift: the long healthy run is split into halves so alarm creep would show",
      {"alarm_seconds_first_half", "alarm_seconds_second_half"} <= set(dr["long_healthy_run"]))
check("drift: the model's probability quantiles are reported against its threshold", dr["long_healthy_run"]["model_probability"]["threshold"] > 0)
check("drift: a slow degradation is measured at each rate", len(dr["slow_degradation"]["rows"]) >= 1)

saf = A.section_safety(model, inv)
check("safety: a fault in any stage of the decision path refuses the command", saf["fail_closed"]["all_failed_closed"], str(saf["fail_closed"]["faults"]))
check("safety: the pipeline works again once the fault is removed", saf["fail_closed"]["recovered_afterwards"])
check("safety: an advisory flag alone produces ALERT, never DROP", saf["advisory_never_blocks"]["all_alert_not_drop"])
u = saf["unsafe_states"]
check("safety: every documented unsafe cross-register state is refused by its own rule", u["blocked"] == u["rules"], f"{u['blocked']}/{u['rules']}")
check("safety: the way back out of every unsafe state is allowed", u["recovery_allowed"] == u["rules"], f"{u['recovery_allowed']}/{u['rules']}")
check("safety: both queues are bounded", saf["bounded_resources"]["decision_queue_maxsize"] > 0 and saf["bounded_resources"]["forward_queue_maxsize"] > 0)
check("safety: the PLC refuses a writer that is not the middleware", saf["plc_allow_list"]["foreign_host_refused"] and saf["plc_allow_list"]["middleware_allowed"])

print("\nTHE REPORT")
res = {"quick": True, "seeds": seeds, "accuracy": acc, "robustness": rob, "fairness": fair, "consistency": con,
       "explainability": exp, "drift": dr, "safety": saf, "rules": {}, "recorded_swat": A.recorded_swat(),
       "seconds": 1.0, "environment": A.environment()}
md = A.render(res)
check("the report has all seven sections and the limits", all(h in md for h in ("## A. Functional accuracy", "## B. Robustness", "## C. Bias and fairness",
      "## D. Consistency", "## E. Explainability", "## F. Drift", "## G. Safety", "## What this report does not establish")))
check("the report states the twin scope and marks a smoke run as one", "DIGITAL TWIN" in md and "SMOKE RUN" in md)
check("the report names the still-unmeasured real-data gaps", "NOT measured yet" in md and "swat_protocol" in md)
check("the report carries the real-data SWaT row", "held-out SWaT" in md)
check("the report does not present fairness as a demographic audit", "not a demographic fairness audit" in md)
import json  # noqa: E402
json.dumps(res, default=float)
check("the whole result serialises to JSON", True)

print("\nALL PASS" if fails == 0 else f"\n{fails} CHECK(S) FAILED")
raise SystemExit(1 if fails else 0)
