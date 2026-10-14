"""
tests/test_test_runner.py - the test runner's parsing/summary logic and the new accuracy fields (offline).

    python -m tests.test_test_runner
"""

from __future__ import annotations

from benchmark.swat_accuracy import add_derived, derived
from tests import run_all

fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global fails
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    fails += 0 if cond else 1


p = run_all.parse_output("  [PASS] a\n  [PASS] b\n  [FAIL] c\n\nALL PASS\n")
check("counts [PASS]/[FAIL] lines and takes the last non-empty line", (p["checks_passed"], p["checks_failed"], p["last_line"]) == (2, 1, "ALL PASS"))
check("scripts without check lines report None, not 0", run_all.parse_output("All 24 checks passed")["checks_passed"] is None)
names = run_all.discover()
check("discovery finds the test scripts and excludes the runner and the fixture helper",
      "test_trace" in names and "test_benchmark" in names and "run_all" not in names and "swat_fixture" not in names, f"{len(names)} scripts")
r = run_all.run_one("test_environment")
check("running a script records status, exit code, duration and check counts", r["status"] == "PASS" and r["exit_code"] == 0 and r["checks_passed"] == 4 and r["seconds"] >= 0, str(r["checks_passed"]))
check("services-needing scripts are SKIPPED with a reason unless asked for",
      all(n in run_all.NEEDS_SERVICES for n in ("pipeline_test", "test_middleware_efficiency")))

d = derived({"tp": 279, "fp": 483, "fn": 781, "tn": 26532})
check("accuracy / balanced accuracy / always-benign baseline are computed from the counts",
      d == {"accuracy": 0.955, "balanced_accuracy": 0.6227, "always_benign_baseline_accuracy": 0.9622}, str(d))
check("a rule that never flags has accuracy = the baseline and balanced accuracy 0.5",
      derived({"tp": 0, "fp": 0, "fn": 40, "tn": 960}) == {"accuracy": 0.96, "balanced_accuracy": 0.5, "always_benign_baseline_accuracy": 0.96})
res = {"advisory_model_flag": {"tp": 1, "fp": 1, "fn": 1, "tn": 1}}
check("add_derived is idempotent", add_derived(add_derived(res)) == add_derived(res))

print("\nALL PASS" if fails == 0 else f"\n{fails} CHECK(S) FAILED")
raise SystemExit(1 if fails else 0)
