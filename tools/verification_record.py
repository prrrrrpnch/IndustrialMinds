#!/usr/bin/env python3
"""
tools/verification_record.py - GENERATE CHECKLIST_VERIFICATION.txt from the artefacts, so its numbers cannot drift from the repository.

    python -m tools.verification_record            # rewrite CHECKLIST_VERIFICATION.txt
    python -m tools.verification_record --check    # exit non-zero if the file on disk is not what the artefacts say (used by the tests)

The old checklist was hand-written, went stale (it described ten machines, RUL and synthetic-trained models that no longer exist) and had to
carry a "STALE" banner for months - PART 0 item 13. A hand-maintained claims document always ends there. This reads every generated JSON in
`benchmarks/` and `docs/reports/` and emits the claim table from them, so the only way a number here can be wrong is for the artefact to be
wrong, and re-running the measurement fixes both at once.

Every claim is printed with the EVIDENCE CLASS it belongs to, because the classes are not interchangeable:
    REAL-DATA     measured on the SWaT archive (iTrust, SUTD) - the only external data this project uses
    CONSTRUCTED   our own scenarios exercising a specification (conformance, not detection skill)
    TWIN          the digital twin, a simulation calibrated to SWaT's operating point, with attacks we wrote
    CODE          a property of the implementation, demonstrated by a test
    NOT MEASURED  stated so plainly, with the command that would measure it
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

OUT = os.path.join(ROOT, "CHECKLIST_VERIFICATION.txt")
W = 118


def load(*parts: str) -> Dict[str, Any]:
    try:
        with open(os.path.join(ROOT, *parts)) as fh:
            return json.load(fh)
    except Exception:
        return {}


def g(d: Dict[str, Any], *path: Any, default: Any = None) -> Any:
    cur: Any = d
    for p in path:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        elif isinstance(cur, list) and isinstance(p, int) and -len(cur) <= p < len(cur):
            cur = cur[p]
        else:
            return default
    return cur


def fmt(v: Any) -> str:
    if v is None:
        return "n/a"
    if isinstance(v, float):
        return f"{v:g}"
    return str(v)


# Short tags keep the claim rows narrow; the legend under the table gives the exact path of every one.
TAG = {
    "docs/reports/physical_training_report_v2_swat.json": "v2",
    "benchmarks/swat_scoring_comparison.json": "scoring",
    "cyber_training_report_swat.json": "cyber",
    "fusion_training_report_swat.md": "fusion",
    "benchmarks/latest.json (benchmark.run_all)": "bench",
    "benchmarks/latest.json": "bench",
    "benchmarks/evidence_pack.json": "evidence",
    "benchmarks/assurance.json": "assurance",
    "benchmarks/invariants_ab.json": "ab",
    "benchmarks/twin_invariants.json": "twin-inv",
    "benchmarks/test_results.json (python -m tests.run_all)": "tests",
    "benchmarks/swat_protocol.json": "protocol",
    "benchmarks/swat_invariants.json": "swat-inv",
    "python -m benchmark.swat_protocol --data-dir <SWaT>": "TODO",
    "python -m tools.fit_invariants --data-dir <SWaT>": "TODO",
    "see the limitations below": "below",
    "python -m benchmark.run_all --live": "TODO",
}
PATH = {
    "v2": "docs/reports/physical_training_report_v2_swat.json", "scoring": "benchmarks/swat_scoring_comparison.json",
    "cyber": "docs/reports/cyber_training_report_swat.json", "fusion": "docs/reports/fusion_training_report_swat.md",
    "bench": "benchmarks/latest.json", "evidence": "benchmarks/evidence_pack.json", "assurance": "benchmarks/assurance.json",
    "ab": "benchmarks/invariants_ab.json", "twin-inv": "benchmarks/twin_invariants.json", "tests": "benchmarks/test_results.json",
    "protocol": "benchmarks/swat_protocol.json", "swat-inv": "benchmarks/swat_invariants.json",
    "TODO": "not generated yet - see the command in the row", "below": "stated in the limitations section of this file",
}


def rule(ch: str = "-") -> str:
    return ch * W


def wrap(text: str, indent: int = 6) -> List[str]:
    words, line, out = text.split(), "", []
    pad = " " * indent
    for w in words:
        if len(line) + len(w) + 1 > W - indent:
            out.append(pad + line)
            line = w
        else:
            line = f"{line} {w}".strip()
    if line:
        out.append(pad + line)
    return out


class Claims:
    """Rows of (class, claim, value, evidence). Nothing is typed by hand except the wording of the claim itself."""

    def __init__(self) -> None:
        self.rows: List[Dict[str, str]] = []
        self.sources: set = set()
        self.last = ""

    def add(self, cls: str, claim: str, value: Any, evidence: str) -> None:
        if evidence != "same":
            self.last = evidence
        self.rows.append({"class": cls, "claim": claim, "value": fmt(value), "evidence": self.last})
        self.sources.add(self.last)

    def render(self) -> List[str]:
        out = []
        for cls in ("REAL-DATA", "CONSTRUCTED", "TWIN", "CODE", "NOT MEASURED"):
            rows = [r for r in self.rows if r["class"] == cls]
            if not rows:
                continue
            out += ["", f"  {cls}", "  " + rule("-")[2:]]
            for r in rows:
                out.append(f"  {r['claim']:<70.70} {r['value']:<32.32} [{TAG.get(r['evidence'], '?')}]")
        return out


def build() -> str:
    latest, swat_cmp = load("benchmarks", "latest.json"), load("benchmarks", "swat_scoring_comparison.json")
    ev, asr = load("benchmarks", "evidence_pack.json"), load("benchmarks", "assurance.json")
    ab, tests = load("benchmarks", "invariants_ab.json"), load("benchmarks", "test_results.json")
    twin_inv, v2 = load("benchmarks", "twin_invariants.json"), load("docs", "reports", "physical_training_report_v2_swat.json")
    protocol, swat_inv = load("benchmarks", "swat_protocol.json"), load("benchmarks", "swat_invariants.json")

    env = asr.get("environment") or latest.get("environment") or {}
    c = Claims()

    # ---------------------------------------------------------------- real data (SWaT)
    t = g(v2, "test", "0.5", "selected_without_persistence", default={})
    if t:
        c.add("REAL-DATA", "Physical model v2 on held-out SWaT: F1 (strict, per window)", t.get("f1"), "docs/reports/physical_training_report_v2_swat.json")
        c.add("REAL-DATA", "  ... precision / recall", f"{fmt(t.get('precision'))} / {fmt(t.get('recall'))}", "same")
        c.add("REAL-DATA", "  ... ROC-AUC / average precision", f"{fmt(t.get('roc_auc'))} / {fmt(t.get('average_precision'))}", "same")
        c.add("REAL-DATA", "  ... accuracy (a never-alarm detector scores)", f"{fmt(t.get('accuracy'))} ({fmt(t.get('always_benign_baseline_accuracy'))})", "same")
        c.add("REAL-DATA", "  ... attack segments detected", f"{fmt(t.get('segments_detected'))}/{fmt(t.get('segments_total'))}", "same")
        c.add("REAL-DATA", "  ... false-alarm episodes per benign hour", t.get("alarm_episodes_per_benign_hour"), "same")
        c.add("REAL-DATA", "  ... median detection delay (s)", t.get("median_latency_s"), "same")
    sc = g(swat_cmp, "budgets", "0.5", "selected_without_persistence", "metrics", default={})
    if sc:
        c.add("REAL-DATA", "Same alarms re-scored: composite F1", sc.get("composite_f1"), "benchmarks/swat_scoring_comparison.json")
        c.add("REAL-DATA", "Same alarms re-scored: PA%K (K=50) F1", sc.get("pak50_f1"), "same")
        c.add("REAL-DATA", "Same alarms re-scored: point-adjust F1 (literature only)", sc.get("pa_f1"), "same")
    cyb = g(load("docs", "reports", "cyber_training_report_swat.json"), "results", "test", "classifier", default={})
    if cyb:
        c.add("REAL-DATA", "Cyber ML on SWaT: ROC-AUC / F1  (NEGATIVE RESULT, not promoted)",
              f"{fmt(round(cyb['roc_auc'], 4))} / {fmt(round(cyb['f1'], 4))}", "cyber_training_report_swat.json")
    fus = load("docs", "reports", "fusion_training_report_swat.json")
    if fus:
        c.add("REAL-DATA", "Learned fusion on SWaT (NEGATIVE RESULT, not promoted)",
              "test AUC below physical alone", "fusion_training_report_swat.md")

    # ---------------------------------------------------------------- constructed scenarios
    r = latest.get("rules") or {}
    if r:
        c.add("CONSTRUCTED", "Rule-violating scenarios refused with the EXPECTED reason",
              f"{r.get('violating_detected_with_expected_reason')}/{r.get('violating_scenarios')}", "benchmarks/latest.json (benchmark.run_all)")
        c.add("CONSTRUCTED", "Legitimate-traffic false-positive rate", r.get("legitimate_false_positive_rate"), "same")
    lv = ev.get("live") or {}
    cc, cv = lv.get("command_confusion") or {}, lv.get("campaign_view") or {}
    if cc:
        c.add("CONSTRUCTED", "Live campaign, per command: precision / recall / F1",
              f"{fmt(cc.get('precision'))} / {fmt(cc.get('recall'))} / {fmt(cc.get('f1'))}", "benchmarks/evidence_pack.json")
    if cv:
        c.add("CONSTRUCTED", "Live campaign, per campaign: detected through the middleware",
              f"{cv.get('detected')}/{cv.get('campaigns_through_middleware')}", "same")
        c.add("CONSTRUCTED", "  ... attack commands that passed AFTER detection began", cv.get("commands_passed_after_first_flag"), "same")
        c.add("CONSTRUCTED", "  ... legitimate commands wrongly flagged",
              f"{cv.get('benign_commands_flagged')}/{cv.get('benign_commands')}", "same")
    lat = g(latest, "latency", "hops", "total", default={})
    if lat:
        c.add("CONSTRUCTED", "Decision latency p50/mean/p95/p99 (ms, in process)",
              " / ".join(fmt(lat.get(k)) for k in ("p50_ms", "mean_ms", "p95_ms", "p99_ms")), "benchmarks/latest.json")

    # ---------------------------------------------------------------- twin
    acc = g(asr, "accuracy", "by_source", "model OR envelope OR invariants (current)", default={})
    if acc:
        c.add("TWIN", "Layered detection on the twin: F1 / precision / recall",
              f"{fmt(acc.get('f1'))} / {fmt(acc.get('precision'))} / {fmt(acc.get('recall'))}", "benchmarks/assurance.json")
        c.add("TWIN", "  ... accuracy (a never-alarm detector scores)",
              f"{fmt(acc.get('accuracy'))} ({fmt(acc.get('never_alarm_accuracy'))})", "same")
    m_only = g(asr, "accuracy", "by_source", "advisory model (v2)", default={})
    if m_only:
        c.add("TWIN", "Advisory model alone on the twin: ROC-AUC / PR-AUC",
              f"{fmt(m_only.get('roc_auc'))} / {fmt(m_only.get('pr_auc'))}", "same")
    det = g(asr, "accuracy", "detection_view", default={})
    if det:
        c.add("TWIN", "Attack runs detected / median delay (s)",
              f"{det.get('detected')}/{det.get('attacks')} / {fmt(det.get('median_delay_s'))}", "same")
    ss, sa = g(ab, "summary", default={}), g(ab, "sensor_summary", default={})
    if sa:
        c.add("TWIN", "Invariants: sensor tampering detected, before -> after",
              f"{g(sa, 'before', 'detected')}/{sa.get('runs')} -> {g(sa, 'after', 'detected')}/{sa.get('runs')}", "benchmarks/invariants_ab.json")
    if ss:
        c.add("TWIN", "Invariants: actuator attacks detected, before -> after",
              f"{g(ss, 'before', 'detected')}/{ss.get('runs')} -> {g(ss, 'after', 'detected')}/{ss.get('runs')}", "same")
    if ab:
        c.add("TWIN", "Invariants: false-alarm episodes/h, before -> after",
              f"{g(ab, 'healthy', 'episodes_per_hour', 'before')} -> {g(ab, 'healthy', 'episodes_per_hour', 'after')}"
              f" over {g(ab, 'healthy', 'hours_total')} h", "same")
    fair = g(asr, "fairness", "stage_parity", default={})
    if fair:
        c.add("TWIN", f"Equal treatment across plant stages at {fmt(fair.get('discriminating_size_sigma'))} sigma (min/max ratio)",
              g(fair, "disparity", "ratio_min_over_max"), "benchmarks/assurance.json")
    drift = g(asr, "drift", "long_healthy_run", default={})
    if drift:
        c.add("TWIN", f"Alarm seconds over a {fmt(drift.get('simulated_hours'))} h healthy run, 1st half -> 2nd half",
              f"{drift.get('alarm_seconds_first_half')} -> {drift.get('alarm_seconds_second_half')}", "same")
    tw = g(twin_inv, "nominal", default={})
    if tw:
        c.add("TWIN", "Twin invariants: violating seconds, fresh healthy run",
              g(tw, "per_theta", str(tw.get("calibrated_theta")), "violating_seconds"), "benchmarks/twin_invariants.json")

    # ---------------------------------------------------------------- code properties
    rob, saf = asr.get("robustness") or {}, asr.get("safety") or {}
    con, exp = asr.get("consistency") or {}, asr.get("explainability") or {}
    mi = rob.get("malformed_input") or {}
    if mi:
        c.add("CODE", "Malformed commands that must be refused, and were",
              f"{mi.get('refused_as_required')}/{mi.get('must_refuse')}", "benchmarks/assurance.json")
        c.add("CODE", "Malformed commands that crashed the pipeline", mi.get("raised"), "same")
    if rob.get("concurrency"):
        c.add("CODE", f"Exceptions under {g(rob, 'concurrency', 'threads')} concurrent threads", g(rob, "concurrency", "exceptions"), "same")
    if saf.get("fail_closed"):
        c.add("CODE", "Fails CLOSED on a fault injected into each decision stage", g(saf, "fail_closed", "all_failed_closed"), "same")
    if saf.get("advisory_never_blocks"):
        c.add("CODE", "An advisory flag alone yields ALERT and can never DROP", g(saf, "advisory_never_blocks", "all_alert_not_drop"), "same")
    us = saf.get("unsafe_states") or {}
    if us:
        c.add("CODE", "Unsafe cross-register states refused by their own rule",
              f"{us.get('blocked')}/{us.get('rules')}", "same")
        c.add("CODE", "  ... and the recovery command out of each is allowed", f"{us.get('recovery_allowed')}/{us.get('rules')}", "same")
    if con.get("determinism"):
        c.add("CODE", f"Distinct outcomes over {g(con, 'determinism', 'repeats')} identical commands", g(con, "determinism", "distinct_outcomes"), "same")
    if con.get("live_offline_parity"):
        c.add("CODE", "Live detector vs offline engine, largest difference", g(con, "live_offline_parity", "max_abs_difference"), "same")
    cov = exp.get("coverage") or {}
    if cov:
        c.add("CODE", "Decisions carrying a machine-readable reason", f"{cov.get('with_a_machine_readable_reason')}/{cov.get('decisions')}", "same")
        c.add("CODE", "Refusals naming the exact check that failed", f"{cov.get('drops_naming_the_failing_check')}/{cov.get('drops')}", "same")
    fa = exp.get("faithfulness") or {}
    if fa:
        c.add("CODE", f"Stage attribution top-1 accuracy (chance {fmt(fa.get('chance_level'))})", fa.get("model_top1_accuracy"), "same")
    summ = tests.get("summary") or {}
    if summ:
        c.add("CODE", "Test scripts passed / failed / skipped",
              f"{summ.get('PASS')} / {summ.get('FAIL')} / {summ.get('SKIPPED')}", "benchmarks/test_results.json (python -m tests.run_all)")
        c.add("CODE", "Individual checks passed / failed",
              f"{summ.get('check_lines_passed')} / {summ.get('check_lines_failed')}", "same")

    # ---------------------------------------------------------------- not measured
    if not protocol:
        c.add("NOT MEASURED", "Cross-validated result over ALL 35 SWaT attacks, with CIs", "needs the archive",
              "python -m benchmark.swat_protocol --data-dir <SWaT>")
    else:
        pv = g(protocol, "pooled", "v2", str(g(protocol, "protocol", "primary_budget")), default={})
        c.add("REAL-DATA", "Cross-validated over all SWaT attacks: F1 / attacks detected",
              f"{fmt(pv.get('f1'))} / {fmt(pv.get('segments_detected'))}/{fmt(pv.get('segments_total'))}", "benchmarks/swat_protocol.json")
    if not swat_inv:
        c.add("NOT MEASURED", "Physical invariants on REAL SWaT (detection + false alarms)", "needs the archive",
              "python -m tools.fit_invariants --data-dir <SWaT>")
    else:
        pt = g(swat_inv, "evaluation", "per_theta", "1.0", default={})
        c.add("REAL-DATA", "Invariants on SWaT at theta 1: attacks detected / false-alarm episodes per h",
              f"{fmt(pt.get('segments_detected'))}/{fmt(pt.get('segments_total'))} / {fmt(pt.get('false_alarm_episodes_per_hour'))}",
              "benchmarks/swat_invariants.json")
    c.add("NOT MEASURED", "Generalisation to attacks we did not design", "by construction", "see the limitations below")
    c.add("NOT MEASURED", "Any result on physical plant equipment", "twin only", "see the limitations below")
    c.add("NOT MEASURED", "Network round-trip latency since the module split", "not re-run", "python -m benchmark.run_all --live")

    # ---------------------------------------------------------------- document
    L = [rule("="),
         "  INDUSTRIALMIND - VERIFICATION RECORD".ljust(W - 2),
         f"  GENERATED by `python -m tools.verification_record` - do not edit by hand.".ljust(W - 2),
         rule("="), ""]
    L += wrap(f"Generated {env.get('generated_utc', 'n/a')} UTC from commit {env.get('git_commit', 'n/a')}"
              f"{' (dirty tree)' if env.get('git_dirty') else ''}, Python {env.get('python', 'n/a')}, "
              f"scikit-learn {env.get('scikit_learn', 'n/a')}. Every number below is read from a generated artefact, so this file cannot "
              "drift from the repository: if a number is wrong, the measurement is wrong, and re-running it fixes both.", 2)
    L += ["", "  HOW TO READ THE EVIDENCE CLASSES", "  " + rule()[2:]]
    for label, text in [("REAL-DATA", "measured on the SWaT archive (iTrust, SUTD) - the only external dataset this project uses."),
                        ("CONSTRUCTED", "our own scenarios exercising a specification. Conformance, NOT detection skill on real attacks."),
                        ("TWIN", "the digital twin, calibrated to SWaT's operating point, attacked with scenarios we wrote."),
                        ("CODE", "a property of the implementation, demonstrated by a test."),
                        ("NOT MEASURED", "stated plainly, with the command that would measure it.")]:
        L.append(f"    {label:<14} {text}")
    L += ["", "  A number from one class must never be quoted as if it belonged to another. The twin F1 is not a SWaT F1; the rule",
          "  conformance rate is not a detection rate.", ""]
    L += [rule("="), "  CLAIMS AND THEIR EVIDENCE", rule("=")]
    L += c.render()
    L += ["", "  SOURCES", "  " + rule()[2:]]
    for tag in sorted({TAG.get(x, "?") for x in c.sources}):
        L.append(f"    [{tag:<8}] {PATH.get(tag, '?')}")
    L += ["", rule("="), "  WHAT THIS RECORD DOES NOT ESTABLISH", rule("="), ""]
    for text in [
        "Generalisation. Every twin and constructed attack is one we designed. A detector evaluated on its authors' attacks is "
        "evidence that it does what it was built to do, not that it withstands an adversary who has read the design.",
        "A real plant. The twin is a simulation; its physics constants are derived from SWaT's measured operating point, but no "
        "result here was obtained on physical equipment.",
        "The cyber branch on real data. SWaT carries no network fields, so no cyber detector can be trained or evaluated on it. "
        "The SWaT-trained cyber ML candidate was weak and was NOT promoted; the cyber branch is deterministic rules by design, and "
        "its evidence is conformance to a specification.",
        "Fairness in the social sense. There are no people or protected attributes in this data. The fairness measurements are "
        "equal treatment across source addresses, registers and plant stages, which is the meaningful reading for a plant.",
        "Unattended operation. Alarm counts rise over a long healthy twin run and stage coverage is uneven at small perturbations; "
        "both bound what the advisory layer can be trusted to do without a human.",
    ]:
        L += wrap("* " + text, 2) + [""]
    L += [rule("="), "  REGENERATING EVERYTHING IN THIS FILE", rule("="), "",
          "    python -m tests.run_all                                  tests and check counts",
          "    python -m benchmark.run_all                              latency, rule conformance, twin",
          "    python -m benchmark.assurance                            the seven assurance dimensions",
          "    python -m benchmark.invariants_ab                        before/after of the invariant rules",
          "    python -m benchmark.evidence_pack                        the live campaign",
          "    python -m tools.fit_invariants --twin                    refit the twin invariant file",
          "    python -m tools.verification_record                      rewrite this file from all of the above",
          "",
          "  Needing the SWaT archive (not in this repository, licensed from iTrust/SUTD):", "",
          "    python -m benchmark.swat_protocol --data-dir <archive>   all 35 attacks, cross-validated, with intervals",
          "    python -m tools.fit_invariants   --data-dir <archive>    the invariants on real data",
          "    python -m benchmark.run_all      --data-dir <archive>    re-measure the held-out SWaT section",
          ""]
    return "\n".join(L) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate CHECKLIST_VERIFICATION.txt from the generated artefacts.")
    ap.add_argument("--check", action="store_true", help="do not write; exit 1 if the file on disk differs from what the artefacts say")
    ap.add_argument("--out", default=OUT)
    a = ap.parse_args()
    text = build()
    if a.check:
        try:
            with open(a.out) as fh:
                current = fh.read()
        except FileNotFoundError:
            print(f"{os.path.relpath(a.out, ROOT)} does not exist; run `python -m tools.verification_record`")
            raise SystemExit(1)
        if current != text:
            print(f"{os.path.relpath(a.out, ROOT)} is out of date with the artefacts; run `python -m tools.verification_record`")
            raise SystemExit(1)
        print(f"{os.path.relpath(a.out, ROOT)} matches the artefacts")
        return
    with open(a.out, "w") as fh:
        fh.write(text)
    print(f"Wrote {os.path.relpath(a.out, ROOT)} ({len(text.splitlines())} lines) from the generated artefacts.")


if __name__ == "__main__":
    main()
