"""
tests/run_all.py - run every test script and SAVE a dated record of the outcome.

    python -m tests.run_all                  # all test scripts that need no running services
    python -m tests.run_all --with-stress    # also the middleware stress test (slow, can flake on a host stall)
    python -m tests.run_all --only test_trace,test_orchestrator

Writes benchmarks/test_results.json (per script: status, exit code, seconds, number of [PASS]/[FAIL] check lines, last output line;
plus the environment and a summary) and prints a table. Exit code 0 only if nothing failed. SKIPPED scripts say why; `pipeline_test`
needs a running PLC and is only run with --with-plc.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from typing import Any, Dict, List

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "benchmarks", "test_results.json")
NEEDS_SERVICES = {"pipeline_test": "needs a running PLC (python -m plc.plc); use --with-plc",
                  "test_middleware_efficiency": "slow stress test that can flake on a single host stall; use --with-stress"}
SELF = {"run_all", "swat_fixture"}            # not test scripts


def parse_output(text: str) -> Dict[str, Any]:
    """Counts of [PASS]/[FAIL] check lines (None when the script does not print them) and its last non-empty line."""
    passed = len(re.findall(r"^\s*\[PASS\]", text, re.M))        # only lines that START with the marker are check results
    failed = len(re.findall(r"^\s*\[FAIL\]", text, re.M))
    lines = [l for l in text.strip().splitlines() if l.strip()]
    return {"checks_passed": passed if passed + failed else None, "checks_failed": failed if passed + failed else None,
            "last_line": lines[-1].strip()[:160] if lines else ""}


def discover() -> List[str]:
    names = [f[:-3] for f in sorted(os.listdir(os.path.join(ROOT, "tests"))) if f.endswith(".py") and not f.startswith("__")]
    return [n for n in names if n not in SELF]


def run_one(name: str, timeout: int = 900) -> Dict[str, Any]:
    t0 = time.time()
    try:
        p = subprocess.run([sys.executable, "-m", f"tests.{name}"], cwd=ROOT, capture_output=True, text=True, timeout=timeout)
        out, err = p.stdout or "", p.stderr or ""           # results are parsed from stdout only; stderr (log lines) is kept for failures
        rec = {"status": "PASS" if p.returncode == 0 else "FAIL", "exit_code": p.returncode}
    except subprocess.TimeoutExpired as e:
        out = ((e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or ""))
        err = ""
        rec = {"status": "FAIL", "exit_code": None, "error": f"timeout after {timeout}s"}
    rec.update({"script": name, "seconds": round(time.time() - t0, 1), **parse_output(out)})
    if rec["status"] == "FAIL":
        rec["output_tail"] = "\n".join((out.strip().splitlines()[-15:]) + (["--- stderr ---"] + err.strip().splitlines()[-8:] if err.strip() else []))
    return rec


def run(only: List[str] | None, with_stress: bool, with_plc: bool) -> Dict[str, Any]:
    started = time.time()
    results = []
    for name in discover():
        if only and name not in only:
            continue
        why = NEEDS_SERVICES.get(name)
        if why and not ((name == "test_middleware_efficiency" and with_stress) or (name == "pipeline_test" and with_plc)):
            results.append({"script": name, "status": "SKIPPED", "reason": why})
            continue
        results.append(run_one(name))
    from benchmark.env import environment
    summ = {s: sum(r["status"] == s for r in results) for s in ("PASS", "FAIL", "SKIPPED")}
    summ["check_lines_passed"] = sum(r.get("checks_passed") or 0 for r in results)
    summ["check_lines_failed"] = sum(r.get("checks_failed") or 0 for r in results)
    return {"started_utc": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(started)), "total_seconds": round(time.time() - started, 1),
            "environment": environment(), "summary": summ, "results": results}


def main() -> None:
    ap = argparse.ArgumentParser(description="Run every test script and save the outcome.")
    ap.add_argument("--only", default="")
    ap.add_argument("--with-stress", action="store_true")
    ap.add_argument("--with-plc", action="store_true")
    ap.add_argument("--no-save", action="store_true")
    a = ap.parse_args()
    res = run([x for x in a.only.split(",") if x] or None, a.with_stress, a.with_plc)
    print(f"{'script':<34}{'status':<9}{'checks':>8}{'sec':>7}  last line")
    for r in res["results"]:
        chk = "-" if r.get("checks_passed") is None else f"{r['checks_passed']}/{r['checks_passed'] + r['checks_failed']}"
        print(f"{r['script']:<34}{r['status']:<9}{chk:>8}{r.get('seconds', 0):>7}  {r.get('last_line', r.get('reason', ''))[:60]}")
    s = res["summary"]
    print(f"\n{s['PASS']} passed, {s['FAIL']} failed, {s['SKIPPED']} skipped; {s['check_lines_passed']} individual checks passed, {s['check_lines_failed']} failed "
          f"({res['total_seconds']} s, commit {res['environment']['git_commit']})")
    if not a.no_save and not a.only:
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        with open(OUT, "w") as fh:
            json.dump(res, fh, indent=2)
        print(f"Saved {os.path.relpath(OUT, ROOT)}")
    sys.exit(1 if s["FAIL"] else 0)


if __name__ == "__main__":
    main()
