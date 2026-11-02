"""
models/operating_points.py - named operating points for the live physical model, DERIVED FROM THE MEASURED REPORT.

`IM_PHYSICAL_THRESHOLD` already lets you move the model's threshold, but a bare number says nothing about what it costs. A preset is
the same move expressed in the terms an operator cares about, and every preset here is a row that was actually measured on the
held-out SWaT test block (docs/reports/physical_training_report_v2_swat.json) - none is invented. If the report is missing, there are
no presets and the shipped threshold stands.

    IM_PHYSICAL_SENSITIVITY=sensitive     # or balanced / cautious, or a measured false-alarm budget such as 1.0

Aliases are assigned relative to the budget the live weights shipped at: a measured budget below it is `cautious`, the shipped one is
`balanced`, above it is `sensitive`. A tier with no measured budget simply does not exist, so the list is never padded with guesses.
`IM_PHYSICAL_THRESHOLD` still wins if both are set.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

log = logging.getLogger("industrialmind.models.operating_points")

ROOT = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
REPORT = os.path.join(ROOT, "docs", "reports", "physical_training_report_v2_swat.json")
RULE = "selected_without_persistence"          # the live model flags per window, with no persistence
SHIPPED_BUDGET = 0.5
KEEP = ("precision", "recall", "f1", "alarm_episodes_per_benign_hour", "segments_detected", "segments_total", "median_latency_s")


def _report_path() -> str:
    return os.environ.get("IM_PHYSICAL_REPORT", "").strip() or REPORT


def measured(shipped_budget: float = SHIPPED_BUDGET) -> List[Dict[str, Any]]:
    """Every operating point the held-out report actually measured, quietest first."""
    path = _report_path()
    try:
        with open(path) as fh:
            rep = json.load(fh)
        rules, test = rep["alarm_rules"], rep.get("test", {})
    except Exception:
        log.debug("no measured operating points at %s - only the shipped threshold is available", path)
        return []
    points = []
    for budget, by_rule in sorted(rules.items(), key=lambda kv: float(kv[0])):
        thr = (by_rule.get(RULE) or {}).get("threshold")
        if thr is None:
            continue
        m = (test.get(budget, {}) or {}).get(RULE, {}) or {}
        points.append({"budget": float(budget), "threshold": float(thr), "measured": {k: m.get(k) for k in KEEP if m.get(k) is not None}})
    below = [p for p in points if p["budget"] < shipped_budget]
    above = [p for p in points if p["budget"] > shipped_budget]
    for p in points:
        p["name"] = None
    if below:
        below[0]["name"] = "cautious"
    for p in points:
        if p["budget"] == shipped_budget:
            p["name"] = "balanced"
    if above:
        above[-1]["name"] = "sensitive"
    return points


def presets(shipped_budget: float = SHIPPED_BUDGET) -> Dict[str, Dict[str, Any]]:
    """{'balanced': {...}, 'sensitive': {...}} - only the tiers that were measured."""
    return {p["name"]: p for p in measured(shipped_budget) if p["name"]}


def resolve(choice: str, shipped_budget: float = SHIPPED_BUDGET) -> Optional[Dict[str, Any]]:
    """A preset name ('sensitive') or a measured budget ('1.0') -> that operating point, or None if it was never measured."""
    choice = str(choice).strip().lower()
    points = measured(shipped_budget)
    for p in points:
        if p["name"] == choice:
            return p
    try:
        want = float(choice)
    except ValueError:
        return None
    return next((p for p in points if p["budget"] == want), None)


def describe(point: Dict[str, Any]) -> str:
    """One line for a log or the dashboard."""
    m = point.get("measured") or {}
    bits = [f"threshold {point['threshold']:.4f}", f"budget {point['budget']:g}/h"]
    if m.get("alarm_episodes_per_benign_hour") is not None:
        bits.append(f"measured {m['alarm_episodes_per_benign_hour']:g} alerts/h")
    if m.get("segments_detected") is not None:
        bits.append(f"{m['segments_detected']}/{m.get('segments_total', '?')} attack segments")
    if m.get("f1") is not None:
        bits.append(f"F1 {m['f1']}")
    return f"{point.get('name') or 'budget ' + format(point['budget'], 'g')}: " + ", ".join(bits)


def apply_preset(default: float, meta: Dict[str, Any], name: str) -> "tuple[float, Dict[str, Any]]":
    """IM_PHYSICAL_SENSITIVITY -> (threshold, metadata). Unknown or unmeasured choices are ignored, keeping the shipped point."""
    choice = os.environ.get("IM_PHYSICAL_SENSITIVITY", "").strip()
    if not choice:
        return default, meta
    shipped = float(meta.get("false_alarm_budget_per_hour", SHIPPED_BUDGET))
    point = resolve(choice, shipped)
    if point is None:
        avail = ", ".join(sorted(presets(shipped))) or "none (measured report not found)"
        log.warning("IM_PHYSICAL_SENSITIVITY=%s was never measured for this model - ignored. Available: %s", choice, avail)
        return default, meta
    log.info("%s operating point: %s (shipped threshold %.4f)", name, describe(point), default)
    return point["threshold"], {**meta, "operating_point": point, "shipped_threshold": float(default)}
