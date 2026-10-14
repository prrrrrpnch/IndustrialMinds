"""
benchmark/plots.py - charts and confusion-matrix images drawn from benchmarks/latest.json (nothing typed by hand).

Written to docs/reports/figures/ by `python -m benchmark.run_all` (and `--render-only`). Each figure states what its data is
(real SWaT vs constructed vs synthetic twin) in its own title, so a chart can never be quoted without its label.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

FIG_DIR_REL = os.path.join("docs", "reports", "figures")
NAMES = {"confusion": "swat_confusion_matrix.png", "latency": "latency_per_hop.png", "rules": "rule_checks.png",
         "plans": "attacker_plans.png", "twin": "twin_detection_latency.png", "segments": "swat_segments.png"}


def _save(fig, out_dir: str, name: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, name), dpi=130)
    plt.close(fig)
    return name


def _cm_axis(ax, c: Dict[str, Any], title: str) -> None:
    m = np.array([[c["tn"], c["fp"]], [c["fn"], c["tp"]]], dtype=float)
    pct = m / np.maximum(m.sum(axis=1, keepdims=True), 1)
    ax.imshow(pct, cmap="Blues", vmin=0, vmax=1)
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{int(m[i, j]):,}\n{100 * pct[i, j]:.1f}% of row", ha="center", va="center",
                    color="white" if pct[i, j] > 0.55 else "black", fontsize=9)
    ax.set_xticks([0, 1], ["no flag", "flag"])
    ax.set_yticks([0, 1], ["benign", "attack"])
    ax.set_xlabel("predicted")
    ax.set_ylabel("true window label")
    f = c.get("f1")
    ax.set_title(f"{title}\nprecision {c['precision']}, recall {c['recall']}, F1 {f}", fontsize=9)


def confusion(res: Dict[str, Any], out_dir: str) -> str | None:
    s = res["swat"]
    if s.get("status") != "OK":
        return None
    fig, axes = plt.subplots(1, 2, figsize=(9, 4.2))
    _cm_axis(axes[0], s["advisory_model_flag"], "Advisory model flag (drives ALERT)")
    _cm_axis(axes[1], s["envelope_rule_alone (alert-only)"], "Envelope rule alone (alert-only)")
    fig.suptitle(f"HELD-OUT SWaT test block (real data), {s['windows']:,} windows ({s['attack_windows']:,} attack)", fontsize=10)
    return _save(fig, out_dir, NAMES["confusion"])


def latency(res: Dict[str, Any], out_dir: str) -> str:
    hops = res["latency"]["hops"]
    names = list(hops)
    y = np.arange(len(names))
    fig, ax = plt.subplots(figsize=(8, 4.5))
    for k, (key, label) in enumerate((("mean_ms", "mean"), ("p95_ms", "p95"), ("p99_ms", "p99"))):
        ax.barh(y + (k - 1) * 0.26, [hops[n][key] for n in names], 0.26, label=label)
    ax.set_yticks(y, names)
    ax.invert_yaxis()
    ax.set_xscale("log")
    ax.set_xlabel("milliseconds (log scale)")
    ax.legend()
    e = res["environment"]
    ax.set_title(f"Per-hop decision latency, in-process, constructed workload\n{e['platform']}, Python {e['python']}", fontsize=9)
    return _save(fig, out_dir, NAMES["latency"])


def rules(res: Dict[str, Any], out_dir: str) -> str:
    cs = res["rules"]["cases"]
    fig, ax = plt.subplots(figsize=(8, 6.5))
    y = np.arange(len(cs))
    ax.barh(y, [100 * c["rate"] for c in cs], color=["tab:green" if c["layer"] == "legitimate" else "tab:blue" for c in cs])
    ax.set_yticks(y, [f"{c['layer']}: {c['case']}" for c in cs], fontsize=7)
    ax.invert_yaxis()
    ax.set_xlim(0, 105)
    ax.set_xlabel("% of scenarios with the expected outcome")
    ax.set_title("Rule-based checks on CONSTRUCTED scenarios (not SWaT, not a learned model)\n"
                 f"{res['rules']['per_case']} randomised scenarios per case; legitimate case (green) must PASS", fontsize=9)
    return _save(fig, out_dir, NAMES["rules"])


def plans(res: Dict[str, Any], out_dir: str) -> str:
    t = res["attacker_plans"]["types"]
    names = list(t)
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar(names, [100 * t[n]["run_drop_rate"] for n in names],
           color=["tab:orange" if t[n]["origin"] == "synthetic-extension" else "tab:purple" for n in names])
    ax.set_ylabel("% of runs with at least one DROP")
    ax.set_ylim(0, 105)
    plt.setp(ax.get_xticklabels(), rotation=20, ha="right")
    ax.set_title("Randomised attacker plans through the RULE agents (constructed)\n"
                 "purple = SWaT-derived behaviour, orange = synthetic extension (network layer)", fontsize=9)
    return _save(fig, out_dir, NAMES["plans"])


def twin(res: Dict[str, Any], out_dir: str) -> str:
    sc = res["twin"]["scenarios"]
    names = list(sc)
    y = np.arange(len(names))
    fig, ax = plt.subplots(figsize=(8, 3.8))
    for k, (key, label) in enumerate((("first_model_flag_after_s", "learned model"), ("first_envelope_violation_after_s", "envelope rule"))):
        ax.barh(y + (k - 0.5) * 0.35, [sc[n][key] if sc[n][key] is not None else 0 for n in names], 0.35, label=label)
    ax.set_yticks(y, [n.split(" (")[0] for n in names])
    ax.invert_yaxis()
    ax.set_xlabel("seconds from the attack to the first alarm (0 = no alarm in the window)")
    ax.legend()
    ax.set_title("Digital TWIN measurement (synthetic plant, NOT SWaT performance)", fontsize=9)
    return _save(fig, out_dir, NAMES["twin"])


def segments(res: Dict[str, Any], out_dir: str) -> str | None:
    s = res["swat"]
    segs = (s.get("segments") or {}).get("per_segment") or []
    if s.get("status") != "OK" or not segs:
        return None
    fig, ax = plt.subplots(figsize=(8, 4))
    ids = [str(g["segment"]) for g in segs]
    frac = [g["flagged_windows"] / max(g["attack_windows"], 1) * 100 for g in segs]
    ax.bar(ids, frac, color=["tab:green" if g["detected"] else "tab:red" for g in segs])
    ax.set_xlabel("attack segment")
    ax.set_ylabel("% of its attack windows flagged")
    ax.set_title("HELD-OUT SWaT test block (real data): per-segment detection (green = detected)", fontsize=9)
    return _save(fig, out_dir, NAMES["segments"])


def figure_names(res: Dict[str, Any]) -> List[str]:
    """Which figures make_all() draws for this result (pure: used by the renderers so documents never depend on the filesystem)."""
    s = res["swat"]
    out = []
    if s.get("status") == "OK":
        out.append(NAMES["confusion"])
    out += [NAMES["latency"], NAMES["rules"], NAMES["plans"], NAMES["twin"]]
    if s.get("status") == "OK" and (s.get("segments") or {}).get("per_segment"):
        out.append(NAMES["segments"])
    return out


def make_all(res: Dict[str, Any], root: str) -> List[str]:
    out = os.path.join(root, FIG_DIR_REL)
    made = [confusion(res, out), latency(res, out), rules(res, out), plans(res, out), twin(res, out), segments(res, out)]
    return [m for m in made if m]
