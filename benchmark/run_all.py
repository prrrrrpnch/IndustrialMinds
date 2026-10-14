"""
benchmark/run_all.py - ONE command: regenerate every benchmark and the documents that quote them.

    python -m benchmark.run_all                              # latency + rules + twin here; SWaT section reused from benchmarks/swat_accuracy.json if present
    python -m benchmark.run_all --data-dir "<SWaT archive>"  # ALSO re-measures the held-out SWaT section (needs the archive on this machine)
    python -m benchmark.run_all --quick                      # small sizes: a smoke run, results are NOT written unless --write

Writes benchmarks/latest.json, docs/reports/benchmark_report.md and the BENCHMARK block of README.md, all from the same data.
"""

from __future__ import annotations

import argparse
import json
import os

from benchmark import latency, render, rules_accuracy, swat_accuracy
from benchmark.env import ROOT, environment

OUT = os.path.join(ROOT, "benchmarks")
SWAT_JSON = os.path.join(OUT, "swat_accuracy.json")
REPORT = os.path.join(ROOT, "docs", "reports", "benchmark_report.md")
README = os.path.join(ROOT, "README.md")
WEIGHTS = os.path.join(ROOT, "models", "weights", "physical_model.joblib")


def twin_section(hours: float, seed: int) -> dict:
    from tools import twin_domain_gap
    return twin_domain_gap.run(WEIGHTS, hours, seed)


def collect(n: int, warmup: int, repeats: int, per_case: int, per_type: int, twin_hours: float, seed: int,
            data_dir: str | None, live: bool) -> dict:
    res = {"latency": latency.run(n, warmup, repeats, seed, live, out=OUT)}
    res.update(rules_accuracy.run(per_case, per_type, seed))
    res["twin"] = twin_section(twin_hours, seed)
    if data_dir:
        swat = swat_accuracy.run(data_dir)
        os.makedirs(OUT, exist_ok=True)
        with open(SWAT_JSON, "w") as fh:
            json.dump(swat, fh, indent=2)
        swat["provenance"] = "measured by this run"
    elif os.path.exists(SWAT_JSON):
        with open(SWAT_JSON) as fh:
            swat = json.load(fh)
        swat["provenance"] = "reused from benchmarks/swat_accuracy.json (measured earlier on the machine that holds the archive)"
    else:
        swat = {"status": "NOT RUN: no --data-dir given and no benchmarks/swat_accuracy.json"}
    res["swat"] = swat
    res["environment"] = environment()
    return res


def main() -> None:
    ap = argparse.ArgumentParser(description="Regenerate all benchmarks and the documents that quote them.")
    ap.add_argument("--data-dir", help="SWaT archive folder (re-measures the held-out SWaT section)")
    ap.add_argument("--n", type=int, default=3000)
    ap.add_argument("--warmup", type=int, default=300)
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--per-case", type=int, default=200)
    ap.add_argument("--per-type", type=int, default=100)
    ap.add_argument("--twin-hours", type=float, default=4.0)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--live", action="store_true", help="also time the Modbus round trip against a running middleware")
    ap.add_argument("--render-only", action="store_true", help="re-render README block and report from the existing benchmarks/latest.json")
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--write", action="store_true", help="with --quick: still write the files")
    a = ap.parse_args()
    if a.quick:
        a.n, a.warmup, a.repeats, a.per_case, a.per_type, a.twin_hours = 300, 60, 2, 20, 10, 0.5
    if a.render_only:
        with open(os.path.join(OUT, "latest.json")) as fh:
            res = json.load(fh)
        with open(REPORT, "w") as fh:
            fh.write(render.render_markdown(res))
        with open(README) as fh:
            text = fh.read()
        with open(README, "w") as fh:
            fh.write(render.update_readme(text, render.render_readme_block(res)))
        print("Re-rendered README block and report from benchmarks/latest.json")
        return
    res = collect(a.n, a.warmup, a.repeats, a.per_case, a.per_type, a.twin_hours, a.seed, a.data_dir, a.live)
    if a.quick and not a.write:
        print(render.render_readme_block(res))
        print("\n(--quick: nothing written)")
        return
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "latest.json"), "w") as fh:
        json.dump(res, fh, indent=2)
    with open(REPORT, "w") as fh:
        fh.write(render.render_markdown(res))
    with open(README) as fh:
        text = fh.read()
    with open(README, "w") as fh:
        fh.write(render.update_readme(text, render.render_readme_block(res)))
    print(render.render_readme_block(res))
    print(f"\nWrote benchmarks/latest.json, {os.path.relpath(REPORT, ROOT)} and the BENCHMARK block of README.md")


if __name__ == "__main__":
    main()
