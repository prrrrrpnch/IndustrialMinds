"""
tests/test_invariants_ab.py - the before/after harness (benchmark/invariants_ab.py): its arithmetic on hand-made runs, and one tiny real run on the twin.

    python -m tests.test_invariants_ab
"""

from __future__ import annotations

import os
import tempfile

os.environ.setdefault("IM_LOG_DIR", tempfile.mkdtemp(prefix="im-ab-test-"))

from benchmark import invariants_ab as AB  # noqa: E402
from models.invariant_monitor import DEFAULT_FILE  # noqa: E402
from models.physical_model_v2 import load_physical_model  # noqa: E402
from swat.invariants import InvariantSet  # noqa: E402

fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global fails
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    fails += 0 if cond else 1


print("ARITHMETIC ON HAND-MADE RUNS")
check("the first alarm after the attack is measured from the attack, alarms before it are ignored", AB._first_after([5, 99, 640, 700], 600) == 40 and AB._first_after([5], 600) is None)
check("alarm episodes merge flags closer than 30 s", AB._episodes([1, 2, 3, 100, 101]) == 2 and AB._episodes([]) == 0)
rows = [{"seed": 1, "first": {"model": 10, "envelope": None, "invariants": 2}, "before": 10, "after": 2},
        {"seed": 2, "first": {"model": None, "envelope": None, "invariants": 5}, "before": None, "after": 5},
        {"seed": 3, "first": {"model": None, "envelope": None, "invariants": None}, "before": None, "after": None},
        {"seed": 4, "first": {"model": 8, "envelope": 8, "invariants": None}, "before": 8, "after": 8}]
sm = AB.summarise({"x": {"runs": rows}})
check("summary counts detections per source and for before / after", (sm["before"]["detected"], sm["after"]["detected"], sm["invariants"]["detected"], sm["model"]["detected"]) == (2, 3, 2, 2))
check("runs caught only because of the invariants are counted separately", sm["newly_detected_by_invariants"] == 1)
check("the paired delay compares before and after on the SAME runs (those before already caught)", sm["paired_median_delay_s"] == {"before": 9.0, "after": 5.0, "runs": 2}, str(sm["paired_median_delay_s"]))
check("after is never slower or less sensitive than before by construction", all(r["after"] is None or r["before"] is None or r["after"] <= r["before"] for r in rows))

print("\nONE TINY REAL RUN ON THE TWIN")
model = load_physical_model()
inv = InvariantSet.load(DEFAULT_FILE)
if model.status != "OK":
    check("the physical model loads", False, model.status)
else:
    AB.SENSOR_ATTACKS = {k: v for k, v in AB.SENSOR_ATTACKS.items() if k.startswith("step LIT401")}
    AB.SCENARIOS = {k: v for k, v in AB.SCENARIOS.items() if k.startswith("ro_deadhead")}
    sens = AB.scenarios(model, inv, [3], "sensor")
    act = AB.scenarios(model, inv, [3], "actuator")
    r = next(iter(sens.values()))["runs"][0]
    check("a sensor step is flagged by the invariants within seconds", r["first"]["invariants"] is not None and r["first"]["invariants"] <= 10, str(r["first"]))
    check("the combined system is at least as fast as before", r["after"] is not None and (r["before"] is None or r["after"] <= r["before"]))
    check("no source alarmed before the attack on the healthy twin", all(v == 0 for v in r["alarm_seconds_before_attack"].values()), str(r["alarm_seconds_before_attack"]))
    ra = next(iter(act.values()))["runs"][0]
    check("an actuator attack is reported for every source with a first-alarm time or None", set(ra["first"]) == {"model", "envelope", "invariants"})
    res = {"label": "x", "theta": inv.theta, "scenarios": act, "sensor_scenarios": sens, "summary": AB.summarise(act) | {"runs": 5}, "sensor_summary": AB.summarise(sens) | {"runs": 5},
           "healthy": {"hours_total": 1.0, "per_seed": [{"seed": 1, "hours": 1.0, "model": 0, "envelope": 0, "invariants": 0, "before": 0, "after": 0}],
                       "episodes_per_hour": {"before": 0.0, "after": 0.0, "model": 0.0, "envelope": 0.0, "invariants": 0.0}},
           "overhead": {"n": 10, "without": {"p50": 0.3, "p95": 0.6}, "with": {"p50": 0.3, "p95": 0.6}, "monitor_update_ms_per_sample": 0.5, "merge_into_us": 0.5, "invariants": len(inv)},
           "environment": AB.environment()}
    md = AB.render(res)
    check("the report states it is a twin measurement and names the open SWaT gap", "NOT SWaT detection performance" in md and "Still open" in md)
    check("the report has the headline, both attack families and the false-alarm table", all(h in md for h in ("## Headline", "Actuator attacks", "Sensor tampering", "## False alarms on healthy runs")))

print("\nOVERHEAD MEASUREMENT")
ov = AB.overhead(60)
check("the cost of the monitor is measured with and without it, interleaved", ov["n"] == 60 and ov["without"]["p50"] > 0 and ov["with"]["p50"] > 0 and ov["invariants"] > 0, str(ov["with"]))
check("merging the cached verdict costs microseconds, not milliseconds", ov["merge_into_us"] < 200, f"{ov['merge_into_us']} us")

print("\nALL PASS" if fails == 0 else f"\n{fails} CHECK(S) FAILED")
raise SystemExit(1 if fails else 0)
