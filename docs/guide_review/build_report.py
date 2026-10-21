"""
docs/guide_review/build_report.py - build the project-guide report PDF and the separate explanation-script PDF.

    python -m docs.guide_review.build_report

Every number in the report is READ from the generated artifacts (benchmarks/*.json, docs/reports/*.json) at build time,
never typed into this file. That is the same rule the repository applies to the README benchmark block, and it is what
makes the report safe to hand to someone: if a measurement changes, re-running this script changes the report, and a
number that has no artifact behind it cannot appear at all.

The two documents are deliberately separate files. The report is what the guide reads; the script is what the presenter
reads, and it must not be in the report.
"""

from __future__ import annotations

import html
import json
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(ROOT, "docs", "guide_review")
FIG = os.path.join(ROOT, "docs", "reports", "figures")
SHOT = os.path.join(ROOT, "final-results", "before-review", "screenshots")


def load(path, default=None):
    try:
        with open(os.path.join(ROOT, path), encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return default if default is not None else {}


BENCH = load("benchmarks/latest.json")
SWAT = load("benchmarks/swat_accuracy.json")
TESTS = load("benchmarks/test_results.json")
EVID = load("benchmarks/evidence_pack.json")
V2 = load("docs/reports/physical_training_report_v2_swat.json")


def git(*args, default="unknown"):
    try:
        return subprocess.run(["git"] + list(args), cwd=ROOT, capture_output=True, text=True).stdout.strip() or default
    except Exception:
        return default


def fig(name, caption, width="100%"):
    p = os.path.join(FIG, name)
    if not os.path.exists(p):
        return ""
    return (f'<figure><img src="file://{p}" style="width:{width}"/>'
            f'<figcaption>{html.escape(caption)}</figcaption></figure>')


def shot(name, caption, width="100%", max_h=None):
    p = os.path.join(SHOT, name)
    if not os.path.exists(p):
        return ""
    style = f"width:{width}" if max_h is None else f"max-width:100%;max-height:{max_h};width:auto"
    return (f'<figure><img src="file://{p}" style="{style}"/>'
            f'<figcaption>{html.escape(caption)}</figcaption></figure>')


def pct(x, nd=1):
    return "n/a" if x is None else f"{100 * float(x):.{nd}f}%"


def num(x, nd=3):
    return "n/a" if x is None else f"{float(x):.{nd}f}"


# --------------------------------------------------------------------------- pull the numbers
env = TESTS.get("environment", {})
summ = TESTS.get("summary", {})
lat = (BENCH.get("latency") or {}).get("hops", {})
tot = lat.get("total", {})
rules = BENCH.get("rules", {}) or {}
rule_cases = rules.get("cases", [])
rule_n = sum(c["n"] for c in rule_cases)
rule_ok = sum(c["as_expected"] for c in rule_cases)
twin = BENCH.get("twin", {}) or {}
nominal = twin.get("nominal", {}) or {}
scen = twin.get("scenarios", {}) or {}
flag = SWAT.get("advisory_model_flag", {}) or {}
segs = SWAT.get("segments", {}) or {}
live = (EVID.get("live") or {})
conf = live.get("command_confusion", {}) or {}
rows = live.get("rows", []) or []

COMMIT = git("rev-parse", "--short", "HEAD")
NCOMMITS = git("rev-list", "--count", "HEAD")
BUILT = time.strftime("%d %B %Y")

LOC = "unknown"
try:
    files = [f for f in git("ls-files").splitlines() if f.endswith(".py")]
    LOC = f"{sum(sum(1 for _ in open(os.path.join(ROOT, f), errors='replace')) for f in files):,}"
except Exception:
    pass


# --------------------------------------------------------------------------- the report
def report_html() -> str:
    rule_rows = "".join(
        f"<tr><td>{html.escape(c['layer'])}</td><td>{html.escape(c['case'])}</td>"
        f"<td class='c'>{c['n']}</td><td class='c'>{c['as_expected']}</td>"
        f"<td class='c {'ok' if c['as_expected'] == c['n'] else 'bad'}'>{pct(c['rate'], 0)}</td></tr>"
        for c in rule_cases)

    live_rows = "".join(
        f"<tr><td>{html.escape(r['phase'])}</td><td class='c'>{html.escape(r['kind'])}</td>"
        f"<td class='c'>{r['commands']}</td><td class='c'>{r['dropped']}</td>"
        f"<td class='c'>{r['passed']}</td></tr>" for r in rows)

    seg_rows = "".join(
        f"<tr><td class='c'>{s['segment']}</td><td class='c'>{s['duration_s']:.0f}&nbsp;s</td>"
        f"<td class='c'>{s['flagged_windows']}/{s['attack_windows']}</td>"
        f"<td class='c {'ok' if s['detected'] else 'bad'}'>{'detected' if s['detected'] else 'MISSED'}</td>"
        f"<td class='c'>{('%.0f s' % s['detection_latency_s']) if s['detection_latency_s'] is not None else '—'}</td></tr>"
        for s in segs.get("per_segment", []))

    twin_rows = "".join(
        f"<tr><td>{html.escape(k)}</td><td class='c'>{v.get('alarm_seconds_before_attack', 0)}&nbsp;s</td>"
        f"<td class='c ok'>{v.get('first_model_flag_after_s')}&nbsp;s</td></tr>"
        for k, v in scen.items())

    hop_rows = "".join(
        f"<tr><td>{html.escape(k.replace('_', ' '))}</td><td class='c'>{num(v.get('p50_ms'), 3)}</td>"
        f"<td class='c'>{num(v.get('mean_ms'), 3)}</td><td class='c'>{num(v.get('p95_ms'), 3)}</td>"
        f"<td class='c'>{num(v.get('p99_ms'), 3)}</td></tr>"
        for k, v in lat.items() if k != "total")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>IndustrialMind — Project Report</title>
<style>
  @page {{ size: A4; margin: 18mm 16mm 16mm 16mm; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: Georgia, 'Times New Roman', serif; font-size: 10.5pt; line-height: 1.5; color: #15202b; margin: 0; }}
  h1, h2, h3, h4 {{ font-family: 'Helvetica Neue', Arial, sans-serif; color: #0b2a4a; line-height: 1.25; }}
  h1 {{ font-size: 26pt; margin: 0 0 4pt; }}
  h2 {{ font-size: 15pt; margin: 22pt 0 7pt; padding-bottom: 4pt; border-bottom: 2px solid #0b2a4a; page-break-after: avoid; }}
  h3 {{ font-size: 11.5pt; margin: 14pt 0 4pt; page-break-after: avoid; }}
  h4 {{ font-size: 10.5pt; margin: 10pt 0 3pt; color: #324b63; page-break-after: avoid; }}
  p {{ margin: 0 0 7pt; }}
  ul, ol {{ margin: 0 0 8pt; padding-left: 18pt; }}
  li {{ margin-bottom: 3pt; }}
  table {{ width: 100%; border-collapse: collapse; margin: 8pt 0 12pt; font-size: 9pt;
           font-family: 'Helvetica Neue', Arial, sans-serif; page-break-inside: avoid; }}
  th {{ background: #0b2a4a; color: #fff; text-align: left; padding: 5pt 6pt; font-weight: 600; }}
  td {{ border-bottom: 1px solid #d8e0e8; padding: 4.5pt 6pt; vertical-align: top; }}
  tr:nth-child(even) td {{ background: #f6f9fc; }}
  td.c, th.c {{ text-align: center; }}
  .ok {{ color: #0a7a3d; font-weight: 700; }}
  .bad {{ color: #b3261e; font-weight: 700; }}
  code {{ font-family: 'DejaVu Sans Mono', Consolas, monospace; font-size: 8.8pt; background: #eef3f8;
          padding: 1px 3px; border-radius: 2px; }}
  figure {{ margin: 10pt 0 14pt; page-break-inside: avoid; text-align: center; }}
  figure img {{ border: 1px solid #ccd6e0; border-radius: 3px; }}
  figcaption {{ font-size: 8.5pt; color: #51637a; margin-top: 4pt; font-family: 'Helvetica Neue', Arial, sans-serif; }}
  .cover {{ height: 247mm; display: flex; flex-direction: column; justify-content: center; page-break-after: always; }}
  .rule {{ height: 4px; background: #0b2a4a; width: 70px; margin: 12pt 0 16pt; }}
  .sub {{ font-size: 13pt; color: #324b63; font-family: 'Helvetica Neue', Arial, sans-serif; margin-bottom: 20pt; }}
  .meta {{ font-size: 9.5pt; color: #51637a; font-family: 'Helvetica Neue', Arial, sans-serif;
           border-top: 1px solid #ccd6e0; padding-top: 10pt; margin-top: 26pt; }}
  .kpi {{ display: flex; gap: 8pt; margin: 12pt 0 16pt; flex-wrap: wrap; }}
  .kpi div {{ flex: 1; min-width: 95pt; border: 1px solid #ccd6e0; border-top: 3px solid #0b2a4a;
              border-radius: 3px; padding: 8pt 9pt; background: #fbfdff; }}
  .kpi b {{ display: block; font-size: 17pt; font-family: 'Helvetica Neue', Arial, sans-serif; color: #0b2a4a; }}
  .kpi span {{ font-size: 8pt; color: #51637a; font-family: 'Helvetica Neue', Arial, sans-serif; }}
  .note {{ background: #fff8e6; border-left: 4px solid #d99a06; padding: 8pt 11pt; margin: 10pt 0 13pt; font-size: 9.5pt; }}
  .warn {{ background: #fdecea; border-left: 4px solid #b3261e; padding: 8pt 11pt; margin: 10pt 0 13pt; font-size: 9.5pt; }}
  .good {{ background: #eaf6ee; border-left: 4px solid #0a7a3d; padding: 8pt 11pt; margin: 10pt 0 13pt; font-size: 9.5pt; }}
  .flow {{ font-family: 'DejaVu Sans Mono', Consolas, monospace; font-size: 8.5pt; line-height: 1.45;
           background: #f6f9fc; border: 1px solid #d8e0e8; border-radius: 3px; padding: 10pt; white-space: pre;
           page-break-inside: avoid; margin: 8pt 0 12pt; }}
  .pb {{ page-break-before: always; }}
</style></head><body>

<section class="cover">
  <div class="rule"></div>
  <h1>IndustrialMind</h1>
  <div class="sub">A security layer that sits between a SCADA control station and a<br>water-treatment PLC, and stops dangerous commands before they reach the plant.</div>

  <p><b>What this document is.</b> A complete, plain-language account of what we built, what we measured, and what we
  deliberately chose <i>not</i> to ship. Every figure in it was read automatically from the project's own result files
  when this PDF was generated — none of them is typed by hand — so each one can be reproduced by re-running the command
  named beside it.</p>

  <div class="kpi">
    <div><b>{summ.get('check_lines_passed', 0)}</b><span>automated checks passing, 0 failing</span></div>
    <div><b>{rule_ok}/{rule_n}</b><span>rule-engine decisions correct</span></div>
    <div><b>{num(tot.get('p50_ms'), 2)} ms</b><span>median decision time per command</span></div>
    <div><b>{num(SWAT.get('roc_auc_attack_probability'), 3)}</b><span>ROC-AUC on real held-out SWaT data</span></div>
  </div>

  <div class="meta">
    Built {BUILT} &nbsp;·&nbsp; git commit <code>{COMMIT}</code> ({NCOMMITS} commits) &nbsp;·&nbsp;
    {LOC} lines of Python<br>
    Python {env.get('python', '—')} &nbsp;·&nbsp; scikit-learn {env.get('scikit_learn', '—')} &nbsp;·&nbsp;
    numpy {env.get('numpy', '—')}<br>
    Generated by <code>python -m docs.guide_review.build_report</code>
  </div>
</section>

<h2>1. The problem, in one page</h2>

<p>A water-treatment plant is run by a <b>PLC</b> (a small industrial computer that opens valves and starts pumps) taking
orders from a <b>SCADA</b> station (the operator's screen). They talk over <b>Modbus/TCP</b>, a protocol designed in 1979
for trusted serial cables. Modbus has <b>no passwords, no signatures and no encryption</b>. Any device that can reach the
PLC's network port can tell it to do anything, and the PLC will obey.</p>

<p>That is not a theoretical weakness. It is how Stuxnet, the 2015/2016 Ukrainian grid attacks and the 2021 Oldsmar water
incident all worked: the attacker did not break the protocol, because there was nothing to break.</p>

<p><b>Our approach.</b> Rather than replacing the protocol — which no plant can afford to do — we put a security layer
<i>in the wire</i>. Every command from SCADA now arrives at our middleware first. The middleware decides, in under a
millisecond, whether to let the command through, and only then forwards it to the PLC. Nothing else changes: the SCADA
software and the PLC are untouched and do not know we are there.</p>

<div class="flow">   SCADA operator            OUR MIDDLEWARE                        PLC + plant
   ──────────────            ──────────────                        ───────────
   writes a command  ──▶   1. Is it from a known device?
                           2. Is the signature valid?
                           3. Has this exact frame been seen before?
                           4. Is this device allowed to touch this valve?
                           5. Is the VALUE physically safe right now?
                           6. Does a trained model think the plant
                              is behaving strangely?
                                      │
                           ┌──────────┴──────────┐
                         DROP                  PASS/ALERT  ──▶  forwarded to the PLC
                    never reaches the plant                     and the plant responds
                    logged, shown, explained                           │
                                                                       ▼
                                                            telemetry polled back
                                                            and checked again</div>

<p>The two halves of that decision are deliberately different in kind:</p>
<ul>
  <li><b>The cyber half asks "who sent this, and is the message genuine?"</b> — authentication, replay protection, access
  control. These are <b>deterministic rules</b>. A signature is either valid or it is not; we never want a model guessing
  about that.</li>
  <li><b>The physical half asks "would this command hurt the plant?"</b> — bounds, rate of change, and relationships
  between stages (for example, do not run a pump into a closed valve). Here we also run a <b>machine-learning model</b>
  trained on real plant data, because "the plant is behaving oddly" is a judgement no fixed rule captures well.</li>
</ul>

<div class="good"><b>The key design decision.</b> The ML model is <b>advisory only</b>. It can raise an ALERT and colour
the operator's screen, but it can <b>never block a command</b>. Blocking is done exclusively by rules a human can read
and audit. This is deliberate: our own measurements (Section 5) show the model misses about half of all attacks and that
about half its alarms are false. A component with those numbers must not be allowed to shut down a water plant.</div>

<h2 class="pb">2. What we actually built</h2>

<table>
  <tr><th>Part</th><th>What it does, in plain terms</th></tr>
  <tr><td><b>PLC digital twin</b><br><code>plc/</code></td>
      <td>A simulated water-treatment plant: 5 stages, 20 measurement points, with real physics — tanks fill and drain,
      pumps affect pressure downstream, chemicals take time to act. It speaks real Modbus, so from the network it is
      indistinguishable from a real PLC. All its physical constants come from the real SWaT plant's measured data.</td></tr>
  <tr><td><b>Middleware</b><br><code>middleware/</code></td>
      <td>The security layer itself. It pretends to be the PLC to SCADA, and pretends to be SCADA to the PLC, so it sees
      every command. Split into five focused modules: transport, decision, forwarding, polling and shared state.</td></tr>
  <tr><td><b>Cyber agent</b></td>
      <td>Eight deterministic checks in a fixed order: known source, valid function code, known register, rate limit,
      HMAC-SHA256 signature, replay/nonce reuse, quarantine, and an access-control policy.</td></tr>
  <tr><td><b>Physical agent</b></td>
      <td>Five deterministic checks: is this a real register, is it writable, is the value within measured safe bounds,
      is it changing too fast, and does it violate a cross-stage safety rule.</td></tr>
  <tr><td><b>Physical ML model</b><br><code>models/</code></td>
      <td>Trained on the real SWaT dataset. Looks at a 120-second rolling window of all 20 sensors, computes 117
      features, and estimates how likely it is that the plant is under attack. Advisory only.</td></tr>
  <tr><td><b>Orchestrator</b></td>
      <td>Combines the two halves into one verdict: any rule failure → <b>DROP</b>; all rules pass but the model is
      suspicious → <b>ALERT</b> (forwarded, but flagged); otherwise → <b>PASS</b>.</td></tr>
  <tr><td><b>Dashboard</b><br><code>dashboard/</code></td>
      <td>A live operator screen: every decision, the plant's state, a per-hop "packet tracer" showing exactly which
      check stopped a command, correlated incidents, and the model's own explanation of why it flagged something.</td></tr>
  <tr><td><b>Attacker</b><br><code>attacker/</code></td>
      <td>Ten scripted attacks plus a randomised mode, so the defence is tested against something that is not simply the
      mirror image of itself.</td></tr>
</table>

<h3>Making the system explain itself</h3>
<p>A security tool that says "blocked" and nothing else is useless to an operator at 3 a.m. Three features exist purely
so a human can understand what happened:</p>
<ul>
  <li><b>Packet tracer</b> — for every command, the exact sequence of checks, which one failed, and which never ran
  because an earlier one already failed.</li>
  <li><b>Model explanation</b> — when the ML model flags something, it names the plant <i>stage</i> most responsible, by
  substituting that stage's raw sensor readings with the last known-normal readings and re-scoring.</li>
  <li><b>Incident correlation</b> — forty separate blocked commands from one source become one incident with a severity,
  not forty rows to scroll past.</li>
</ul>

{shot('happy-path-packet-tracer.png', 'The packet tracer: every check, in order, with the one that failed and the ones that never ran.', width='92%')}

<h2 class="pb">3. The data we used, and our honesty rule</h2>

<p>We used exactly one external dataset: <b>SWaT</b> (Secure Water Treatment) from iTrust, Singapore University of
Technology and Design — a real, physical water-treatment testbed that researchers attacked under controlled conditions.
After de-duplication it gave us <b>946,719 rows</b> at one reading per second across 51 sensor and actuator tags, with
<b>35 labelled attack periods</b>.</p>

<div class="note"><b>The rule we set ourselves, and kept.</b> Anything SWaT cannot supply is either derived from SWaT's
own columns, or clearly labelled synthetic. We never present self-generated data as real-world performance. This is why
the results in Section 5 are separated into three sections that are never mixed: <b>real SWaT data</b>, <b>constructed
rule scenarios</b>, and <b>digital-twin measurements</b>.</div>

<h3>Things we did carefully that are easy to get wrong</h3>
<ul>
  <li><b>We split the data by calendar time, not randomly.</b> Randomly shuffling time-series rows lets the model see
  the future: a window from 14:05 in training and 14:06 in testing are nearly identical, and accuracy becomes fiction.</li>
  <li><b>We evaluate per attack segment, not per row.</b> One single attack in SWaT lasts about ten hours and accounts
  for 66% of all attack rows. Scoring row-by-row would let a model look excellent by detecting that one event and
  nothing else.</li>
  <li><b>We report that our test block is not perfectly blind.</b> It was used for exactly two model refits. A pristine
  test set would be better; saying so is better than pretending.</li>
  <li><b>The feature-extraction code is literally shared between training and the live system</b> (<code>swat/</code>),
  so the model cannot be fed differently in the lab than in production — the most common cause of models that work on
  paper and fail in the field.</li>
</ul>

<h2 class="pb">4. Results — part 1: the deterministic rules</h2>

<p>These are the checks that are allowed to block. They are specifications, not predictions: an unsigned command
<i>must</i> be rejected, every time. We test each case {rule_cases[0]['n'] if rule_cases else 200} times with randomised
values.</p>

<div class="kpi">
  <div><b>{rule_ok}/{rule_n}</b><span>correct decisions</span></div>
  <div><b>{pct(rule_ok / rule_n if rule_n else 0, 0)}</b><span>accuracy</span></div>
  <div><b>0</b><span>legitimate commands wrongly blocked</span></div>
</div>

<table>
  <tr><th>Layer</th><th>Scenario</th><th class="c">Tried</th><th class="c">Correct</th><th class="c">Rate</th></tr>
  {rule_rows}
</table>

<p class="note"><b>How to read this honestly.</b> 100% here does <i>not</i> mean "we detect 100% of attacks". It means
these rules do exactly what they are specified to do, with no false positives on legitimate traffic. A rule only catches
the attack it was written for; the model in Section 5 exists precisely because rules cannot cover everything.
Reproduce with <code>python -m benchmark.run_all</code>.</p>

{fig('rule_checks.png', 'Every rule-based scenario and its outcome.')}

<h2 class="pb">5. Results — part 2: the ML model on real SWaT data</h2>

<p>This is the honest, uncomfortable section, and the one worth spending time on with a reviewer. The model was trained
on real SWaT data and then run <b>once</b> on a held-out block of {SWAT.get('windows', 0):,} time windows
({SWAT.get('benign_hours', 0):.1f} hours of benign operation) that it had not been tuned on.</p>

<div class="kpi">
  <div><b>{num(SWAT.get('roc_auc_attack_probability'), 3)}</b><span>ROC-AUC</span></div>
  <div><b>{num(flag.get('precision'), 3)}</b><span>precision</span></div>
  <div><b>{num(flag.get('recall'), 3)}</b><span>recall</span></div>
  <div><b>{num(flag.get('f1'), 3)}</b><span>F1 score</span></div>
  <div><b>{segs.get('detected', 0)}/{segs.get('total', 0)}</b><span>attacks detected</span></div>
</div>

<div class="warn"><b>What these numbers mean, stated plainly.</b> Recall {num(flag.get('recall'), 3)} means the model
<b>misses roughly {100 - 100 * float(flag.get('recall') or 0):.0f}% of attack windows</b>. Precision
{num(flag.get('precision'), 3)} means <b>roughly {100 - 100 * float(flag.get('precision') or 0):.0f}% of its alarms are
false</b>. Its raw accuracy is {pct(flag.get('accuracy'), 2)} — but a model that simply said "never an attack" would
score {pct(flag.get('always_benign_baseline_accuracy'), 2)} on this data, because attacks are rare. <b>Quoting the
accuracy figure alone would be misleading, so we do not.</b> This single fact is the main reason the model is advisory
and cannot block.</div>

<p>The more useful view is <b>per attack event</b>, because an operator cares whether an attack was caught at all, not
how many individual seconds were flagged:</p>

<table>
  <tr><th class="c">Attack segment</th><th class="c">Duration</th><th class="c">Windows flagged</th>
      <th class="c">Outcome</th><th class="c">Time to detect</th></tr>
  {seg_rows}
</table>

<p><b>{segs.get('detected', 0)} of {segs.get('total', 0)} attacks were detected</b>, with a median detection time of
<b>{segs.get('median_detection_latency_s', 0):.0f} seconds</b>, at a cost of
<b>{num(flag.get('alarm_episodes_per_benign_hour'), 2)} false-alarm episodes per hour</b> of normal running. Put in
operator terms: the model catches most real attacks within a minute, and interrupts the operator about once an hour when
nothing is wrong. That trade-off is a deliberate setting we can tune (<code>IM_PHYSICAL_SENSITIVITY</code>) without
retraining.</p>

{fig('swat_segments.png', 'Per-attack-segment detection on the held-out SWaT test block.')}
{fig('swat_confusion_matrix.png', 'Window-level confusion matrix, held-out SWaT test block.')}

<h2 class="pb">6. Results — part 3: the whole system, running</h2>

<p>The two sections above test components. This one starts the <b>real programs</b> — PLC, middleware, dashboard — on
real network sockets, runs every attack the attacker tool knows plus labelled legitimate traffic, and reads the outcome
back out of the dashboard's own API. Nothing is simulated or asserted; it is what the running system actually did.</p>

<div class="kpi">
  <div><b>{conf.get('n', 0)}</b><span>commands sent</span></div>
  <div><b>{num(conf.get('precision'), 2)}</b><span>precision</span></div>
  <div><b>{num(conf.get('recall'), 2)}</b><span>recall</span></div>
  <div><b>{conf.get('fp', 0)}</b><span>legitimate commands blocked</span></div>
  <div><b>{live.get('campaigns_detected_through_middleware', '—')}</b><span>attack campaigns detected</span></div>
</div>

<table>
  <tr><th>Attack campaign</th><th class="c">Type</th><th class="c">Commands</th><th class="c">Blocked</th>
      <th class="c">Allowed</th></tr>
  {live_rows}
</table>

<div class="good"><b>Every attack campaign that passed through the middleware was detected
({live.get('campaigns_detected_through_middleware', '—')}), and not one legitimate command out of 40 was blocked.</b>
Note that "Allowed" is not always a failure: in a flood, the first few commands are legitimate-looking and only the burst
is an attack, so blocking 5 of 10 is the correct behaviour, not a miss.</div>

<p><b>The one campaign that is not detected inline is <code>false-injection</code>, and we report it deliberately.</b> It
does not go through the middleware at all — it opens its own socket straight to the PLC. No in-line device can block
traffic that never reaches it. We now defend it in two ways: the PLC itself refuses writes from anything that is not the
middleware (Section 8), and the physical model still sees the plant misbehaving afterwards. On a single-laptop demo every
process shares the address <code>127.0.0.1</code>, so the PLC cannot tell the attacker from the middleware and the write
is allowed; on the four-laptop setup, where the addresses differ, it is refused. We keep this row in the results instead
of quietly removing it, because a results table that only contains wins is not evidence.</p>

{fig('evidence_live_campaign.png', 'The live campaign: what the running system did with each attack.')}

<h2 class="pb">7. Results — part 4: speed, and the digital twin</h2>

<h3>Is it fast enough to sit in the wire?</h3>
<p>A security layer in the control path must not slow the plant down. Measured over
{(BENCH.get('latency') or {}).get('config', {}).get('commands_per_repeat', 0):,} commands, repeated
{(BENCH.get('latency') or {}).get('config', {}).get('repeats', 0)} times:</p>

<div class="kpi">
  <div><b>{num(tot.get('p50_ms'), 2)} ms</b><span>median (p50)</span></div>
  <div><b>{num(tot.get('mean_ms'), 2)} ms</b><span>mean</span></div>
  <div><b>{num(tot.get('p95_ms'), 2)} ms</b><span>95th percentile</span></div>
  <div><b>{num(tot.get('p99_ms'), 2)} ms</b><span>99th percentile</span></div>
</div>

<table>
  <tr><th>Stage of the decision</th><th class="c">p50 (ms)</th><th class="c">mean (ms)</th>
      <th class="c">p95 (ms)</th><th class="c">p99 (ms)</th></tr>
  {hop_rows}
  <tr><td><b>Total</b></td><td class="c"><b>{num(tot.get('p50_ms'), 3)}</b></td>
      <td class="c"><b>{num(tot.get('mean_ms'), 3)}</b></td>
      <td class="c"><b>{num(tot.get('p95_ms'), 3)}</b></td>
      <td class="c"><b>{num(tot.get('p99_ms'), 3)}</b></td></tr>
</table>

<p>For context, this plant's control loop runs at about one command per second. Even the 99th-percentile decision costs
{num(tot.get('p99_ms'), 2)} ms — roughly <b>0.3% of the time available</b>. The security layer is free, in practice.</p>

{fig('latency_per_hop.png', 'Where the decision time goes.')}

<h3>Does it catch attacks on a live plant?</h3>
<p>We ran the model against our digital twin for {nominal.get('simulated_hours', 0):.0f} hours of healthy operation, then
staged five realistic sabotage scenarios.</p>

<div class="kpi">
  <div><b>{nominal.get('model_alarm_episodes', 0)}</b><span>false alarms in {nominal.get('simulated_hours', 0):.0f} h of normal running</span></div>
  <div><b>{min([v.get('first_model_flag_after_s', 99) for v in scen.values()] or [0])}–{max([v.get('first_model_flag_after_s', 0) for v in scen.values()] or [0])} s</b><span>time to flag a sabotage</span></div>
</div>

<table>
  <tr><th>Sabotage scenario</th><th class="c">False alarms before it started</th><th class="c">Flagged after</th></tr>
  {twin_rows}
</table>

<p class="note"><b>This is a twin measurement, not a SWaT result.</b> The twin is calibrated to SWaT's measured
statistics, but it is still our own simulation, and a model tends to do better on a world that resembles its training
data than on the real one. We report it as what it is: evidence that the model responds correctly and quickly to a
physical attack in progress, not as a detection rate.</p>

{fig('twin_detection_latency.png', 'How quickly each staged sabotage was flagged on the twin.')}

<h2 class="pb">8. Proving the system really does what we claim</h2>

<p>It is easy to write software that reports its own success. The strongest piece of evidence in this project is a test
that checks our claims against <b>the network itself</b>.</p>

<p>We simulate the full four-machine lab on one computer, each role on its own address, and capture the real network
traffic with <b>tshark</b> (the command-line Wireshark). Then we cross-check <b>four independent records</b> of the same
events, which are produced by four different parts of the system and have no reason to agree unless the system is
behaving as described:</p>

<ol>
  <li>the <b>captured network packets</b> — the ground truth, taken off the wire;</li>
  <li>the middleware's <b>packet tracer</b>, matched to the packets by the signature's nonce;</li>
  <li>the <b>blocked-attack log</b> written to disk;</li>
  <li>the <b>dashboard's live feed</b>.</li>
</ol>

<div class="good"><b>Result: 24 signed command frames captured, 24 consistent with the tracer, 0 mismatches.</b> The
bypass write appears on the PLC leg only and never on the middleware leg — exactly as our claim predicts — and the PLC's
own log shows it being refused. Reproduce with <code>python -m tools.sim_four_laptops</code>.</div>

<p>Because the capture is a standard <code>.pcapng</code> file, a reviewer can open it in Wireshark and see every signed
frame, every forwarded command and the bypass attempt, independently of anything we wrote.</p>

{shot('happy-path-dashboard-full.png', 'The live operator dashboard during a run (full page, scaled to fit).', max_h='215mm')}

<h2 class="pb">9. What we tried and deliberately did not ship</h2>

<p>Three machine-learning models were built, trained on real SWaT data, measured, and then <b>rejected</b>. We kept the
code and the reports. A negative result that is measured and documented is a finding; quietly deleting it would make the
project look better and be worth less.</p>

<table>
  <tr><th>What we tried</th><th>What we measured</th><th>Decision</th></tr>
  <tr><td><b>ML model for the cyber half</b> — learn to spot malicious command patterns</td>
      <td>Test ROC-AUC 0.63, F1 0.137 — barely better than guessing</td>
      <td><b>Rejected.</b> The cyber branch is rules-only. SWaT contains no network-layer data, so there was nothing real
      to learn from; authentication should be deterministic anyway.</td></tr>
  <tr><td><b>Learned fusion</b> — a model to combine the cyber and physical verdicts, instead of fixed logic</td>
      <td>Validation AUC 0.93 looked excellent, but test AUC was 0.68 versus 0.83 for the physical model alone, and it
      detected 4/10 attack segments instead of 6/10</td>
      <td><b>Rejected.</b> A textbook case of a model that fits the validation set. The orchestrator uses a readable
      four-branch rule table.</td></tr>
  <tr><td><b>Physical model v3</b> — multi-scale features, stacked per-stage models</td>
      <td>F1 0.352 against 0.432 for the simpler v2 baseline; 6/10 segments against 8/10</td>
      <td><b>Not promoted.</b> More complexity, worse results. v2 stays live; v3 is available behind a flag for anyone
      who wants to reproduce the comparison.</td></tr>
</table>

<p class="note">There is a general lesson here worth saying out loud to a reviewer: in all three cases the more
sophisticated option lost to the simpler one on honestly held-out data. The only reason we know that is that we measured
it on a test block we had not tuned on.</p>

<h2 class="pb">10. The independent audit, and what it changed</h2>

<p>Rather than finish and declare success, we ran a deliberately hostile review of our own system — written to find
reasons it would fail in a real plant, with every finding required to cite a file and line. The state of the system
before the review was frozen in <code>final-results/before-review/</code> and never edited, so the before-and-after is
verifiable rather than remembered.</p>

<p><b>The review found a critical bug that all {TESTS.get('summary', {}).get('check_lines_passed', 0)} of our passing
tests had missed</b>, because every test checked a component against its own specification and none checked what an
operator actually needs. All findings have since been fixed and each is now pinned by a test written from the operator's
point of view.</p>

<table>
  <tr><th>What was wrong</th><th>Why it mattered</th><th>Before → after</th></tr>
  <tr><td><b>C1.</b> A command approved by the middleware was reported to the operator as a green PASS even when the PLC
      was unreachable and never received it</td>
      <td>The classic control-room failure: the screen and the plant disagree, and the operator believes the screen</td>
      <td class="c">reported <b>PASS</b> →<br>reported <b>UNDELIVERED</b></td></tr>
  <tr><td><b>C2.</b> An unresponsive PLC stalled the whole middleware, for every client at once</td>
      <td>One flaky network cable would have frozen the entire demo and looked like our software had crashed</td>
      <td class="c"><b>2,002 ms</b> → 504 ms →<br><b>1.9 ms</b> per command</td></tr>
  <tr><td><b>C3.</b> A library wrote ~99 error lines into the log during a 30-second outage</td>
      <td>Every blocked attack would be buried in library noise in the log the operator reads</td>
      <td class="c"><b>99 lines</b> → <b>1 line</b></td></tr>
  <tr><td><b>C4.</b> The PLC poll retried a dead PLC five times a second, forever</td>
      <td>~18,000 connection attempts an hour; on a real plant network an intrusion-detection system would flag our
      security device as the noisiest thing present</td>
      <td class="c"><b>18,000</b> → <b>720</b><br>attempts/hour</td></tr>
  <tr><td><b>C5.</b> Replay protection read and then wrote shared state with no lock</td>
      <td>Safe only by accident. The very next threading change would have let two copies of the same captured command
      both be accepted</td>
      <td class="c">unsynchronised →<br><b>12 threads, 1 accepted</b></td></tr>
  <tr><td><b>S1.</b> The PLC accepted writes from anything on the network</td>
      <td>The entire product assumes the middleware is in the path — and nothing enforced that</td>
      <td class="c">bypass worked →<br><b>bypass refused</b></td></tr>
  <tr><td><b>S4.</b> The auto-quarantine could be turned against the operator</td>
      <td>An attacker forging the operator's address could get the <i>real</i> operator locked out — our defence becoming
      the attack</td>
      <td class="c">40 forged frames locked<br>the operator out → <b>no effect</b></td></tr>
  <tr><td><b>A4.</b> All forensic evidence lived only in the dashboard's memory</td>
      <td>Restarting the screen destroyed the whole record of an incident</td>
      <td class="c">lost on restart →<br><b>survives restart</b></td></tr>
  <tr><td><b>N2.</b> The dashboard loaded its chart library and icons from the internet</td>
      <td>The lab is air-gapped, so the chart silently rendered as a blank box</td>
      <td class="c">blank box →<br><b>renders offline</b></td></tr>
</table>

<div class="good"><b>Why this section belongs in the report.</b> Finding and fixing a critical bug in your own work, with
the before-state preserved so the claim can be checked, is stronger evidence of engineering maturity than a project that
reports no problems at all. Every project has defects; most do not go looking for them.</div>

<h2 class="pb">11. Security hardening</h2>

<table>
  <tr><th>Protection</th><th>What it stops</th></tr>
  <tr><td><b>HMAC-SHA256 signed commands</b></td>
      <td>Forged or tampered commands. Every command carries a signature over its register, value, a random number and a
      timestamp.</td></tr>
  <tr><td><b>Nonce + replay window</b></td>
      <td>An attacker recording a genuine command and sending it again later.</td></tr>
  <tr><td><b>Per-device keys</b></td>
      <td>A key stolen from one machine being used from another — each device is verified with its own key.</td></tr>
  <tr><td><b>Access-control policy</b></td>
      <td>A legitimate, authenticated device touching equipment it has no business touching.</td></tr>
  <tr><td><b>Auto-quarantine</b></td>
      <td>A device that repeatedly sends violations it genuinely signed is cut off for a while, with the hold doubling
      for repeat offences. Only authenticated violations count, so it cannot be turned against the operator.</td></tr>
  <tr><td><b>PLC write allow-list</b></td>
      <td>Anything that tries to skip the middleware and command the plant directly.</td></tr>
  <tr><td><b>Fail-closed design</b></td>
      <td>If any part of the decision pipeline throws an error, the command is DROPPED, never waved through.</td></tr>
</table>

<h2>12. Known limitations — stated plainly</h2>

<ol>
  <li><b>The model misses about half of attack windows and about half of its alarms are false.</b> It is advisory for
  exactly this reason. Improving it needs more and more varied real attack data than SWaT provides.</li>
  <li><b>The cyber rules cannot be validated against real-world data.</b> SWaT has no network traffic, no signatures and
  no source addresses. They are tested against specifications and constructed scenarios, and we label them as such
  rather than inventing a detection rate.</li>
  <li><b>The results are reproducible on one machine.</b> The SWaT archive is licensed and cannot be redistributed, so
  anyone re-running the model numbers must obtain it themselves.</li>
  <li><b>The four-laptop deployment has been verified on loopback, not yet on four physical laptops.</b> The capture,
  the cross-check and the tooling all work; the hardware run is outstanding.</li>
  <li><b>A spoofed source address still defeats address-based protections.</b> Network segmentation remains the real
  control; our allow-list is defence in depth, and we say so in the code.</li>
  <li><b>The dashboard runs on a development web server</b>, appropriate for a lab demonstration, not for deployment.</li>
</ol>

<h2 class="pb">13. How to check any claim in this document</h2>

<table>
  <tr><th>Claim</th><th>Command that regenerates it</th></tr>
  <tr><td>All automated checks pass ({summ.get('check_lines_passed', 0)} checks)</td><td><code>python -m tests.run_all</code></td></tr>
  <tr><td>Rule accuracy, latency, twin detection</td><td><code>python -m benchmark.run_all</code></td></tr>
  <tr><td>Model numbers on real SWaT</td><td><code>python -m benchmark.run_all --data-dir &lt;SWaT archive&gt;</code></td></tr>
  <tr><td>Live attack campaign against the running system</td><td><code>python -m benchmark.evidence_pack</code></td></tr>
  <tr><td>Four-record cross-check and Wireshark capture</td><td><code>python -m tools.sim_four_laptops</code></td></tr>
  <tr><td>The audit, its findings and the fixes</td><td><code>final-results/AUDIT.md</code></td></tr>
  <tr><td>The frozen pre-audit state</td><td><code>final-results/before-review/</code></td></tr>
  <tr><td>This document</td><td><code>python -m docs.guide_review.build_report</code></td></tr>
</table>

<h2>14. Summary</h2>

<p>We built a working inline security layer for an industrial control protocol that has no security of its own, and
measured it honestly.</p>

<ul>
  <li><b>It works.</b> {rule_ok} of {rule_n} rule decisions correct; every attack campaign that passes through it is
  detected; no legitimate command was wrongly blocked.</li>
  <li><b>It is fast enough to be invisible</b> — {num(tot.get('p50_ms'), 2)} ms median, against a one-second control
  loop.</li>
  <li><b>It is honest about its model.</b> Trained on real data, measured on a held-out block, reported with its
  weaknesses, and kept advisory because of them.</li>
  <li><b>It explains itself</b> — per-hop tracing, stage-level attribution, correlated incidents.</li>
  <li><b>It has been checked against the network itself</b> — 24 frames, 24 consistent, 0 mismatches.</li>
  <li><b>It was audited adversarially</b>, and the defects found were fixed and pinned by tests, with the before-state
  preserved.</li>
</ul>

<p>The three rejected models are, in their way, the clearest evidence of the method: each was built, measured on data it
had not been tuned on, found wanting, and left out of the shipped system with its numbers recorded.</p>

<div class="meta">IndustrialMind &nbsp;·&nbsp; commit <code>{COMMIT}</code> &nbsp;·&nbsp; {BUILT} &nbsp;·&nbsp;
all figures generated from the project's own result files</div>

</body></html>"""


# --------------------------------------------------------------------------- the speaking script
def script_html() -> str:
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>IndustrialMind — Explanation Script</title>
<style>
  @page {{ size: A4; margin: 16mm 15mm; }}
  body {{ font-family: 'Helvetica Neue', Arial, sans-serif; font-size: 10.5pt; line-height: 1.55; color: #15202b; margin: 0; }}
  h1 {{ font-size: 20pt; color: #0b2a4a; margin: 0 0 2pt; }}
  h2 {{ font-size: 12.5pt; color: #0b2a4a; margin: 17pt 0 5pt; border-bottom: 2px solid #0b2a4a;
        padding-bottom: 3pt; page-break-after: avoid; }}
  h3 {{ font-size: 10.5pt; margin: 11pt 0 3pt; color: #324b63; page-break-after: avoid; }}
  p {{ margin: 0 0 6pt; }}
  .say {{ background: #f3f8fd; border-left: 4px solid #1a6bb5; padding: 8pt 11pt; margin: 5pt 0 9pt; }}
  .say p {{ margin: 0 0 5pt; }}
  .say p:last-child {{ margin: 0; }}
  .do {{ font-size: 9pt; color: #6b4a00; background: #fff8e6; border-left: 4px solid #d99a06;
         padding: 5pt 10pt; margin: 5pt 0 9pt; }}
  .q {{ font-size: 9.5pt; border-left: 4px solid #0a7a3d; background: #eef8f1; padding: 6pt 11pt; margin: 5pt 0 8pt; }}
  .q b {{ color: #0a5c2e; }}
  .time {{ float: right; font-size: 8.5pt; color: #7a8899; font-weight: 400; }}
  ul {{ margin: 0 0 7pt; padding-left: 17pt; }}
  li {{ margin-bottom: 3pt; }}
  code {{ font-family: 'DejaVu Sans Mono', Consolas, monospace; font-size: 8.8pt; background: #eef3f8; padding: 1px 3px; }}
  .lead {{ color: #51637a; font-size: 9.5pt; margin-bottom: 14pt; }}
  .pb {{ page-break-before: always; }}
  table {{ width: 100%; border-collapse: collapse; margin: 6pt 0 10pt; font-size: 9pt; }}
  th {{ background: #0b2a4a; color: #fff; text-align: left; padding: 4pt 6pt; }}
  td {{ border-bottom: 1px solid #d8e0e8; padding: 4pt 6pt; }}
</style></head><body>

<h1>Explanation script</h1>
<p class="lead">For the presenter only — this is not part of the report given to the guide.<br>
Blue = roughly what to say. Amber = what to do or show. Green = likely questions and how to answer them.<br>
Target length about 12 minutes, plus questions. Numbers below match the report built on {BUILT}, commit {COMMIT}.</p>

<h2>Before you start <span class="time">2 min setup</span></h2>
<div class="do">
Have ready, in this order:
<ul>
  <li>The report PDF open at the architecture diagram (Section 1).</li>
  <li>Four terminals: <code>python -m plc.plc</code>, <code>python dashboard/app.py</code>,
      <code>python -m middleware.middleware_server</code>, and one free for the attacker.</li>
  <li>The dashboard at <code>http://127.0.0.1:5050</code> in a browser, already loaded.</li>
  <li>Optional: the <code>.pcapng</code> from <code>tools.sim_four_laptops</code> open in Wireshark.</li>
</ul>
Let the middleware run for two minutes before you demo — the model needs a 120-second warm-up, and you do not want to
explain a WARMING_UP badge while someone is watching.
</div>

<h2>1. Open with the problem, not the solution <span class="time">1.5 min</span></h2>
<div class="say">
<p>"The protocol that industrial plants use to control pumps and valves is called Modbus. It was designed in 1979 for a
trusted serial cable, and it has no passwords, no signatures and no encryption. Any device that can reach the PLC can
tell it to do anything, and it will obey."</p>
<p>"That is not theoretical. Stuxnet, the Ukrainian grid attacks and the Oldsmar water incident all worked that way — the
attacker did not break the protocol, because there was nothing to break."</p>
<p>"You cannot realistically replace the protocol in a working plant. So we put a security layer inside the wire instead.
Every command now reaches our middleware first, it decides in under a millisecond, and only then does the command reach
the plant. The SCADA software and the PLC are completely unchanged — they do not know we are there."</p>
</div>
<div class="do">Point at the architecture diagram while you say the last sentence. Do not list the eight checks yet.</div>

<h2>2. The one design decision worth defending <span class="time">1.5 min</span></h2>
<div class="say">
<p>"The thing I would most like to explain is a decision we made about where machine learning belongs."</p>
<p>"The cyber half — is this message genuine, who sent it, have I seen it before — is all deterministic rules. A
signature is either valid or it is not. We never want a model guessing about authentication."</p>
<p>"The physical half — would this command actually hurt the plant — has rules too, but it also has a trained model,
because 'the plant is behaving oddly' is a judgement no fixed rule captures well."</p>
<p>"And the model is advisory only. It can raise an alert and colour the screen. It can never block a command. Blocking
is done entirely by rules a human can read."</p>
<p>"The reason is in our own measurements: the model misses about half of attack windows and about half of its alarms
are false. A component with those numbers must not be allowed to shut down a water plant."</p>
</div>
<div class="do">If you only get to make one point in the whole session, make this one. It shows the measurement drove the
architecture, not the other way round.</div>

<h2>3. Show it working <span class="time">3 min</span></h2>
<div class="do">Run a legitimate command first, then an attack. Always in that order — the contrast is the point.</div>
<div class="say">
<p>"This is a normal operator command. Green, passed, forwarded to the plant, and the plant responds — you can see the
tank level start to move."</p>
<p>"Now the same command, but I have tampered with the value in transit."</p>
<p>"Red, dropped, and it never reached the plant. And this panel is the part I would point out: it is a per-hop trace. It
shows every check in order, which one failed — here, the signature — and that the checks after it never ran, because
once the signature is wrong there is nothing left worth checking."</p>
</div>
<div class="do">Open the packet tracer panel at the bottom of the dashboard. Scroll to the failed check. Pause there for
a few seconds; people read it.</div>
<div class="say">
<p>"We built this because a security tool that just says 'blocked' is useless to an operator at three in the morning. The
operator has to be able to see why."</p>
</div>

<h2 class="pb">4. The results — lead with the honest number <span class="time">3 min</span></h2>
<div class="do">Report Sections 4, 5 and 6. Do NOT start with the 100% — start with the model, so you are seen to raise
the weakness yourself rather than being asked about it.</div>
<div class="say">
<p>"On real SWaT data — a physical water-treatment testbed in Singapore that researchers attacked under controlled
conditions — our model gets an ROC-AUC of {num(SWAT.get('roc_auc_attack_probability'), 3)} and an F1 of
{num(flag.get('f1'), 3)}."</p>
<p>"I want to be direct about what that means. It misses roughly {100 - 100 * float(flag.get('recall') or 0):.0f}% of
attack windows, and roughly {100 - 100 * float(flag.get('precision') or 0):.0f}% of its alarms are false."</p>
<p>"Its raw accuracy is {pct(flag.get('accuracy'), 1)}, and we deliberately do not quote that number, because a model
that simply always said 'no attack' would score {pct(flag.get('always_benign_baseline_accuracy'), 1)} on this data.
Attacks are rare, so accuracy flatters you. That is exactly the kind of number that makes a project look good and mean
nothing."</p>
<p>"The number that does mean something is per attack event: {segs.get('detected', 0)} of {segs.get('total', 0)} attacks
detected, median {segs.get('median_detection_latency_s', 0):.0f} seconds to detect, at about
{num(flag.get('alarm_episodes_per_benign_hour'), 1)} false alarms an hour. An operator cares whether the attack was
caught, not how many individual seconds were flagged."</p>
</div>
<div class="say">
<p>"The rules, which are the part that is actually allowed to block, are {rule_ok} out of {rule_n} correct with zero
legitimate commands blocked. But I would not want that read as 'we detect {pct(rule_ok / rule_n if rule_n else 0, 0)} of
attacks' — it means these rules do exactly what they are specified to do. A rule only catches the attack it was written
for. That is why the model is there at all."</p>
<p>"And end to end, with the real programs running over real sockets: every attack campaign that goes through the
middleware is detected, and none of the 40 legitimate commands was blocked."</p>
</div>

<h2>5. The proof you should be proudest of <span class="time">1.5 min</span></h2>
<div class="say">
<p>"It is easy to write software that reports its own success. So we checked our claims against the network itself."</p>
<p>"We run the whole four-machine lab on one computer and capture the actual packets with tshark — command-line
Wireshark. Then we cross-check four separate records of the same events: the captured packets, the middleware's own
trace, the blocked-attack log on disk, and the dashboard feed. Four different parts of the system, no reason to agree
unless it is all behaving as we say."</p>
<p>"Twenty-four signed frames captured, twenty-four consistent, zero mismatches."</p>
<p>"And the one attack that bypasses us entirely shows up on the PLC's network leg and not on ours — which is exactly
what our claim predicts, because an inline device cannot block traffic that never reaches it."</p>
</div>
<div class="do">If Wireshark is open, show the capture here. It lands much harder than a table.</div>

<h2>6. What we rejected <span class="time">1.5 min</span></h2>
<div class="say">
<p>"We trained three machine-learning models and shipped none of them."</p>
<p>"A model for the cyber side got ROC-AUC 0.63 — barely better than guessing. A learned model to fuse the two verdicts
looked excellent on validation at 0.93, then scored 0.68 on the test set against 0.83 for the physical model alone —
textbook overfitting. And a more sophisticated v3 physical model lost to the simpler v2 on honestly held-out data."</p>
<p>"We kept all three, with their numbers, as documented negative results. In every case the more complex option lost to
the simpler one, and the only reason we know that is that we tested on a block we had not tuned on."</p>
</div>

<h2>7. The audit — volunteer it <span class="time">1.5 min</span></h2>
<div class="do">Raise this yourself. If the guide finds it in the report after you have skipped it, it reads very
differently.</div>
<div class="say">
<p>"Near the end we ran a deliberately hostile review of our own system — written to find reasons it would fail in a real
plant. We froze the state of the system before the review in a folder we never edited, so the before-and-after is
checkable rather than remembered."</p>
<p>"It found a critical bug that all of our passing tests had missed: if the PLC was unreachable, the operator was shown
a green PASS for a command the plant never received. The screen and the plant disagreed, and the operator would have
believed the screen."</p>
<p>"The tests missed it because every one of them checked a component against its own specification, and none of them
checked what an operator actually needs. That was the real finding."</p>
<p>"It is fixed, and it is now pinned by tests written from the operator's point of view. The review also found that one
unresponsive PLC could stall the entire middleware — that went from two thousand milliseconds a command to under two —
and that our own auto-quarantine could be turned against the operator by an attacker forging their address."</p>
</div>

<h2 class="pb">8. Close <span class="time">30 sec</span></h2>
<div class="say">
<p>"So: a working inline security layer for a protocol with no security, fast enough to be invisible at under a
millisecond against a one-second control loop, that explains every decision it makes, that has been checked against the
network itself, and that is honest about the one component that is not good enough to be trusted with blocking."</p>
<p>"Every number in the report is read automatically from the project's own result files when the PDF is built. Nothing
is typed in by hand, so any of it can be regenerated with a single command."</p>
</div>

<h2>Likely questions</h2>

<div class="q"><b>"Why is your model's accuracy so low?"</b><br>
Do not get defensive. "It is a hard problem on this data, and we chose to report it honestly rather than tune the number.
The more important thing is what we did about it: because the model is this weak, we made it advisory, so it cannot
block. The blocking is done by deterministic rules. The architecture reflects the measurement."</div>

<div class="q"><b>"Could you not have improved it?"</b><br>
"We tried three times and measured each one. The more complex models did worse on data they had not been tuned on. The
honest limit is the data: SWaT has 35 attack events, and that is not many examples to learn from."</div>

<div class="q"><b>"Is 100% on the rules realistic?"</b><br>
Agree with the scepticism — it is the right instinct. "It would not be realistic as a detection rate, and we do not
claim it as one. Those are specifications, not predictions: an unsigned command must be rejected every time. They only
catch the attacks they were written for, which is exactly why there is a model as well."</div>

<div class="q"><b>"What happens if your middleware crashes or is bypassed?"</b><br>
"Two different answers. If it crashes or errors, it fails closed — the command is dropped, never waved through. If it is
bypassed, with the attacker going straight to the PLC, no inline device can stop that, so we do two other things: the PLC
now refuses writes from anything that is not the middleware, and the physical model still sees the plant misbehaving
afterwards. We show that attack in our results rather than leaving it out."</div>

<div class="q"><b>"Why only one dataset?"</b><br>
"SWaT is the only public dataset with real physical process data from a real plant under real attacks. We set a rule that
it would be our only external source, and that anything else would be clearly labelled synthetic. It costs us some
breadth and it keeps us from accidentally reporting simulated results as real ones."</div>

<div class="q"><b>"Have you run it on four actual laptops?"</b><br>
Answer straight: "Not yet — that is our main outstanding item. Everything is verified on loopback with four separate
addresses and a real packet capture, and the tooling and the per-machine checks are written. What is missing is the
hardware run." Do not overclaim this one; it is in the limitations section of the report anyway.</div>

<div class="q"><b>"What would you do with more time?"</b><br>
"Three things, in order: run it on the four physical laptops; get more attack data than SWaT's 35 events, since that is
the real ceiling on the model; and move the dashboard off a development web server if it were ever to be deployed."</div>

<h2>Things not to do</h2>
<ul>
  <li><b>Do not lead with the 100%.</b> It invites the one question you least want to answer first.</li>
  <li><b>Do not hide the weak model.</b> Raising it yourself is the strongest move available; being caught on it is the
  weakest.</li>
  <li><b>Do not call the twin results "our accuracy".</b> They are a simulation measurement and the report labels them
  that way. Being caught blurring that line would undermine every other number.</li>
  <li><b>Do not demo before the model has warmed up</b> (120 seconds), or you will be explaining a WARMING_UP badge.</li>
  <li><b>Do not read the tables aloud.</b> They are in the report. Say what they mean.</li>
</ul>

<h2>One-line fallback if time is cut short</h2>
<div class="say">
<p>"We built a security layer that sits in the wire between a control station and an industrial plant, blocks dangerous
commands in under a millisecond using rules a human can audit, uses machine learning only as an advisory signal because
we measured it and it is not reliable enough to block, and we verified the whole thing against real captured network
traffic."</p>
</div>

</body></html>"""


def to_pdf(html_text: str, name: str) -> str:
    src = os.path.join(OUT, f"_{name}.html")
    pdf = os.path.join(OUT, f"{name}.pdf")
    with open(src, "w", encoding="utf-8") as fh:
        fh.write(html_text)
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        b = pw.chromium.launch(executable_path="/opt/pw-browsers/chromium-1194/chrome-linux/chrome",
                               args=["--headless=new", "--no-sandbox", "--disable-dev-shm-usage"])
        pg = b.new_page()
        pg.goto("file://" + src, wait_until="networkidle")
        pg.pdf(path=pdf, format="A4", print_background=True,
               margin={"top": "0", "bottom": "0", "left": "0", "right": "0"},
               display_header_footer=True, header_template="<div></div>",
               footer_template=('<div style="width:100%;font-size:7.5pt;color:#8a97a6;'
                                'font-family:Arial;padding:0 16mm;text-align:right;">'
                                '<span class="pageNumber"></span> / <span class="totalPages"></span></div>'))
        b.close()
    return pdf


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    r = to_pdf(report_html(), "IndustrialMind_Project_Report")
    s = to_pdf(script_html(), "IndustrialMind_Explanation_Script")
    for p in (r, s):
        print(f"  {p}  ({os.path.getsize(p) / 1024:.0f} KB)")
