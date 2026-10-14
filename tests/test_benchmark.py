"""
tests/test_benchmark.py - Phase 11: the benchmarks run, are reproducible, and every number quoted in README/report comes from the JSON.

    python -m tests.test_benchmark
"""

from __future__ import annotations

import json
import os
import tempfile

os.environ.setdefault("IM_LOG_DIR", tempfile.mkdtemp(prefix="im-bench-"))

from benchmark import latency, render, rules_accuracy, swat_accuracy  # noqa: E402
from benchmark.env import ROOT  # noqa: E402

fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global fails
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    fails += 0 if cond else 1


print("LATENCY")
a, b = latency.build_commands(200, 5), latency.build_commands(200, 5)
sig = lambda items: [(x["kind"], x["cmd"]["register"], x["cmd"]["value"], x["cmd"]["timestamp"], x["cmd"]["source_ip"]) for x in items]
check("the workload is deterministic for a seed (same kinds, registers, values, times, sources; only the random nonces differ)", sig(a) == sig(b))
check("a different seed gives a different workload", sig(a) != sig(latency.build_commands(200, 6)))
check("the workload mixes legitimate and attack commands", {x["kind"] for x in a} >= {"legit", "tamper", "unsigned", "oob", "untrusted", "cross"})
r = latency.run_once(150, 30, 5)
check("every hop is timed", all(r["hops"][h]["n"] > 0 for h in latency.HOPS), str({h: r["hops"][h]["n"] for h in latency.HOPS}))
check("percentiles are ordered (p50 <= p95 <= p99 <= max) for every hop",
      all(s["p50_ms"] <= s["p95_ms"] <= s["p99_ms"] <= s["max_ms"] for s in r["hops"].values()))
check("the total is at least the concurrent branch wall time and at least each rule hop on average",
      r["hops"]["total"]["mean_ms"] >= r["hops"]["branches"]["mean_ms"] * 0.95
      and r["hops"]["total"]["mean_ms"] >= max(r["hops"][h]["mean_ms"] for h in ("cyber_rules", "physical_rules", "orchestrator")) * 0.5)
check("timers are removed after the run (agents are the original functions)",
      latency.cyber_agent.check.__name__ == "check" and latency.orchestrator.decide.__name__ == "decide")
check("verdict classes include both forwarded and dropped commands", {"DROP"} <= set(r["verdict_counts"]) and bool({"PASS", "ALERT"} & set(r["verdict_counts"])))

print("\nRULE-BASED ACCURACY (constructed scenarios)")
rr = rules_accuracy.run_rule_cases(per_case=6, seed=3)
check("every rule case is exercised", len(rr["cases"]) == 23, str(len(rr["cases"])))
check("every violating scenario is dropped with the expected reason", rr["violating_detected_with_expected_reason"] == rr["violating_scenarios"],
      str([c["case"] for c in rr["cases"] if c["as_expected"] != c["n"]]))
check("no legitimate command is dropped", rr["legitimate_false_positive_rate"] == 0.0)
check("negative control: the judge rejects a wrong outcome",
      rules_accuracy.judge({"verdict": "PASS", "reason": "OK"}, "HMAC_INVALID")[0] is False
      and rules_accuracy.judge({"verdict": "DROP", "reason": "OUT_OF_BOUNDS:x"}, "HMAC_INVALID")[0] is False
      and rules_accuracy.judge({"verdict": "DROP", "reason": "OUT_OF_BOUNDS:x"}, "PASS")[0] is False)
ap = rules_accuracy.run_attack_plans(per_type=8, seed=2)
check("attacker plans: network-layer attacks are always caught, stealthy ones are not claimed to be",
      all(ap["types"][t]["run_drop_rate"] == 1.0 for t in ("impossible-command", "flood", "replay", "cross-register"))
      and ap["types"]["ramp"]["run_drop_rate"] < 1.0)

print("\nSWAT SECTION (synthetic fixture: code path only)")
from tests.swat_fixture import make_swat_archive  # noqa: E402
d = tempfile.mkdtemp(prefix="bench-fix-")
make_swat_archive(d, seed=0)
sw = swat_accuracy.run(d, fixture=True)
c = sw["advisory_model_flag"]
check("confusion counts add up to the number of windows", c["tp"] + c["fp"] + c["fn"] + c["tn"] == sw["windows"])
check("segment table is consistent", sw["segments"]["total"] == len(sw["segments"]["per_segment"])
      and sw["segments"]["detected"] == sum(s["detected"] for s in sw["segments"]["per_segment"]))
check("the fixture result is labelled as meaningless", sw["fixture_not_real_results"] is True and "SYNTHETIC" in sw["label"])
check("evaluation uses only the test block", sw["block"].startswith("test"))

print("\nQUOTED NUMBERS COME FROM THE JSON")
latest = os.path.join(ROOT, "benchmarks", "latest.json")
check("benchmarks/latest.json exists (run python -m benchmark.run_all)", os.path.exists(latest))
if os.path.exists(latest):
    res = json.load(open(latest))
    readme = open(os.path.join(ROOT, "README.md")).read()
    report = open(os.path.join(ROOT, "docs", "reports", "benchmark_report.md")).read()
    check("README benchmark block equals the rendering of latest.json", render.render_readme_block(res) in readme)
    check("benchmark_report.md equals the rendering of latest.json", report == render.render_markdown(res))
    nr = dict(res, swat={"status": "NOT RUN: test"})
    check("a missing SWaT section is rendered as NOT RUN and quotes no SWaT number",
          "NOT RUN" in render.render_markdown(nr) and "ROC-AUC (attack probability)" not in render.render_markdown(nr))

print("\nALL PASS" if fails == 0 else f"\n{fails} CHECK(S) FAILED")
raise SystemExit(1 if fails else 0)
