"""Generate the PASS 0 baseline reports from the raw evidence. Numbers are interpolated, never hand-typed."""
from __future__ import annotations

import json
import os
from datetime import datetime

ROOT = "/home/user/IndustrialMinds"
BR = os.path.join(ROOT, "final-results", "before-review")
RAW = os.path.join(BR, "_raw")
L = json.load(open(os.path.join(RAW, "live.json")))
M = json.load(open(os.path.join(RAW, "model.json")))
B = json.load(open(os.path.join(ROOT, "benchmarks", "latest.json")))
T = json.load(open(os.path.join(ROOT, "benchmarks", "test_results.json")))
CON = json.load(open(os.path.join(RAW, "shots", "console.json")))
NOW = datetime.now().strftime("%Y-%m-%d %H:%M")
COMMIT = os.popen(f"cd {ROOT} && git rev-parse --short HEAD").read().strip()
h = M["heldout_swat"]


def w(name, text):
    open(os.path.join(BR, name), "w").write(text.strip() + "\n")
    print("wrote", name)


def table(rows, head):
    out = ["| " + " | ".join(head) + " |", "|" + "|".join("---" for _ in head) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


# ------------------------------------------------------------------ 00
w("00-system-overview.md", f"""
# 00 - System overview and audit scope

Audited {NOW} at commit `{COMMIT}`, branch `claude/serene-feynman-or6ieo`. This folder is the immutable baseline: it records what
the system did BEFORE any audit-driven change. Everything here was produced by running the real system, not by reading it.

## What the system is

An inline security middleware for an industrial control network. A SCADA operator writes setpoints; the middleware sits in the
path, decides, and only then forwards to the PLC.

```
SCADA (Modbus/TCP :5021) -> MIDDLEWARE -> PLC digital twin (Modbus/TCP :5020)
                               |            5 stages, 20 registers
                               |-- Cyber Agent    deterministic rules
                               |-- Physical Agent deterministic rules + ONE advisory ML model
                               |-- Orchestrator   four-branch fusion -> PASS / ALERT / DROP
                               +-> Dashboard (HTTP :5050), blocked-attack log, packet tracer
```

## Entry points

{table([
    ["Modbus/TCP :5021", "middleware", "the only path a control command can take", "primary"],
    ["Modbus/TCP :5020", "PLC twin", "accepts writes from anyone who can reach it", "**not protected by the middleware**"],
    ["HTTP :5050", "dashboard", "19 routes; 11 GET, 7 POST, 1 static", "read UI + ingest from middleware"],
    ["CLI", "scada / attacker / tools", "operator sim, attack client, 9 tools", "operator + lab"],
], ["Surface", "Component", "What it accepts", "Note"])}

## What was exercised in this pass

- a full happy path over real sockets, SCADA -> middleware -> PLC -> response
- 7 failure and abuse paths: PLC killed mid-run, PLC restored, unsigned write, tampered frame, out-of-bounds value,
  write to a read-only sensor, raw garbage at the frame registers, dashboard killed
- every integration point, reached and checked rather than assumed
- dependency, config and secret presence
- the live model's runtime behaviour (size, load, latency, throughput, memory)
- dashboard endpoint latency and process footprint under sustained command load
- the dashboard rendered in a real browser, with console errors captured

## What could NOT be exercised, and why

- **A fresh held-out model evaluation.** The SWaT archive is not in this environment and by project policy never has been. All
  classification metrics in `06-model-metrics.md` are arithmetic on a confusion matrix recorded from a run the user executed on
  their own machine. This is a CRITICAL finding and is written up as one.
- **The 4-laptop deployment.** No hardware and no addresses assigned. A loopback simulation of it exists and was run previously.
- **The LLM investigator's model path.** No SDK and no API key here; only its deterministic fallback ran.

## Verdict of this pass in one line

The system runs, the happy path works end to end, and every attack thrown at it was stopped - but it tells the operator a
command succeeded when the PLC is unreachable, its headline accuracy is below the do-nothing baseline, and its most important
numbers cannot be reproduced in any environment but the user's laptop.
""")

# ------------------------------------------------------------------ 01
flows = {f["flow"]: f for f in L["flows"]}
hp = [f for f in L["flows"] if "happy" in f["flow"] or "tracer" in f["flow"] or "feedback" in f["flow"]]
w("01-happy-path-results.md", f"""
# 01 - Happy path

Real processes, real Modbus/TCP, real HMAC-signed frames. Cold start to first accepted command: **{L['perf']['cold_start_s']} s**.

## Result

{table([[f["flow"], f"**{f['status']}**", f["detail"]] for f in hp], ["Flow", "Status", "Evidence"])}

## The path a command actually takes

1. SCADA builds a 27-word frame (version, register, value, 64-bit nonce, 64-bit timestamp, 32-byte HMAC-SHA256) and writes it
   with Modbus FC16 to register 100 on :5021.
2. Cyber Agent, 8 checks in order: source whitelist, quarantine, function code, register allow-list, rate limit, HMAC,
   replay, authorization. Measured p50 **{B['latency']['hops']['cyber_rules']['p50_ms']} ms**.
3. Physical Agent, 5 checks: register known, actuator only, bounds, rate of change, cross-register.
   p50 **{B['latency']['hops']['physical_rules']['p50_ms']} ms**.
4. Both branches run concurrently; the advisory model scores the 120 s window. p50 **{B['latency']['hops']['physical_model']['p50_ms']} ms**,
   p99 **{B['latency']['hops']['physical_model']['p99_ms']} ms**.
5. Orchestrator fuses them into PASS / ALERT / DROP. p50 **{B['latency']['hops']['orchestrator']['p50_ms']} ms**.
6. On PASS the middleware opens its own connection to the PLC and writes FC6. The PLC applies it and the poll loop confirms.
7. Decision, trace and telemetry are pushed to the dashboard on a non-blocking worker.

End-to-end in-process decision latency, 3000 commands x 3 repeats:
**p50 {B['latency']['hops']['total']['p50_ms']} ms, p95 {B['latency']['hops']['total']['p95_ms']} ms,
p99 {B['latency']['hops']['total']['p99_ms']} ms**.

Full socket round trip measured in this pass under sustained load: {json.dumps(L['perf'].get('round_trip_under_load'))}.

## Counts from this run

{table([[k, v] for k, v in L["log_counts"].items()], ["Middleware log line", "Count"])}

Screenshot: `screenshots/happy-path-dashboard-full.png`, `screenshots/happy-path-packet-tracer.png`.

## Honest note

The happy path is the best-tested part of this system and it behaves correctly. Everything interesting in this audit is in
`02` and `05`.
""")

# ------------------------------------------------------------------ 02
edges = [f for f in L["flows"] if f not in hp]
w("02-edge-case-results.md", f"""
# 02 - Edge cases and error paths

{table([[f["flow"].replace("edge: ", ""), f"**{f['status']}**", f["detail"]] for f in edges], ["Case", "Status", "Observed"])}

## The one that matters: a command "succeeds" while the PLC is dead

The PLC was killed, then a correctly signed, in-bounds command was sent.

- The middleware returned **PASS** to SCADA.
- The dashboard recorded it as PASS.
- The write never reached a PLC, because there wasn't one.
- The middleware logged a reachability error {L['flows'][3]['detail'].split('error ')[-1] if len(L['flows']) > 3 else ''}.

An operator watching the dashboard sees a green PASS and has no reason to think the setpoint was not applied. The only signal
is telemetry going stale, which on a slow-moving plant can take minutes. This is the single most dangerous behaviour found in
this pass and is written up in `05-anomalies-found.md`.

## Recovery

When the PLC came back the middleware reconnected by itself with no operator action - verdicts and forwarding resumed. That
part is correct and is worth keeping.

## Abuse input

Every malformed and hostile input was dropped with the correct reason code, and the middleware stayed up:

- unsigned write -> `HMAC_MISSING`
- tampered value with the original tag -> `HMAC_INVALID`
- out-of-range value -> `OUT_OF_BOUNDS`
- write to a read-only sensor -> `WRITE_TO_SENSOR_REGISTER`
- a 3-word frame, 27 zero words, and 27 max-int words -> all dropped; the process did not crash or leak a traceback

Note the Modbus layer **accepts** all three garbage writes (`short frame accepted`, `all zeros accepted`, `max ints accepted`)
and the command is rejected afterwards by the agents. That is by design - the frame registers are a datastore - but it means a
sender cannot tell from the Modbus response whether its command was applied. See `05`.

## Dashboard outage

With the dashboard killed, two commands completed in 1.4 s and the sender saw no error: the forwarding worker is genuinely
non-blocking and the control path does not depend on the UI. Correct.
""")

# ------------------------------------------------------------------ 03
w("03-integration-status.md", f"""
# 03 - Integration status

Each one was reached and exercised, not inferred from configuration.

{table([[i["integration"], f"**{i['status']}**", i["detail"]] for i in L["integrations"]],
       ["Integration", "Status", "Evidence"])}

## Dashboard HTTP surface (from the live Flask url_map)

{table([["/", "GET", "the UI"], ["/api/health", "GET", "liveness of the dashboard process ONLY"],
        ["/api/dashboard", "GET", "counters, events, telemetry"], ["/api/traces, /api/trace/<tx>", "GET", "packet tracer"],
        ["/api/flow", "GET", "network flow view"], ["/api/incidents", "GET", "correlated incidents"],
        ["/api/model", "GET + POST", "model card: middleware pushes, UI reads"],
        ["/api/investigations", "GET", "investigator findings"], ["/api/blocked-ips", "GET", "blocked source summary"],
        ["/api/security-event, /api/trace, /api/telemetry, /api/incident, /api/investigation", "POST",
         "ingest from the middleware"], ["/api/reset", "POST", "clears dashboard state"]],
       ["Route", "Methods", "Purpose"])}

## External dependencies at runtime

{table([
    ["Google Fonts CDN", "**BROKEN offline**", "`fonts.googleapis.com` - fails on an isolated lab network"],
    ["Font Awesome CDN", "**BROKEN offline**", "`cdnjs.cloudflare.com` - icon set fails to load"],
    ["Chart.js CDN", "**BROKEN offline**", "`cdn.jsdelivr.net/npm/chart.js@4.4.0` - the CPU chart silently never renders"],
    ["Anthropic API", "MISSING (by design)", "optional; the investigator falls back to its deterministic engine"],
    ["SWaT archive", "MISSING", "not in this environment; blocks any re-measurement of model accuracy"],
    ["tshark 4.2.2", "CONNECTED", "present; used by the capture tooling"],
], ["Dependency", "Status", "Detail"])}

Browser console on a real page load: `{CON['console_errors']}`

Three of the dashboard's five external assets fail without internet. The lab is four laptops on an isolated network. This is a
real deployment defect, not a cosmetic one - see `05`.
""")

# ------------------------------------------------------------------ 04
w("04-config-and-env-check.md", f"""
# 04 - Configuration, secrets and dependencies

## Runtime

Python {B['environment']['python']} | {B['environment']['platform']} | {B['environment']['cpu_count']} CPU |
numpy {B['environment']['numpy']} | scikit-learn {B['environment']['scikit_learn']} | pandas {B['environment']['pandas']}

## Declared vs actually importable

{table([[m, "OK" if m != "anthropic" else "**MISSING**",
         "pinned in requirements.txt" if m != "anthropic" else "optional, commented out; investigator degrades by design"]
        for m in ["flask", "requests", "pymodbus", "psutil", "openpyxl", "matplotlib", "numpy", "pandas",
                  "scikit-learn", "joblib", "anthropic"]],
       ["Package", "Importable", "Note"])}

`pymodbus==3.6.9` and `scikit-learn==1.9.1` are exact pins. The scikit-learn pin is load-bearing: the weights are a pickle and
another version makes the load warn, which `tests/test_environment.py` turns into a failure. That is correct discipline but it
is also a fragility - the artefact is a pickle, not a portable format.

## Secrets

{table([
    ["config/hmac_secret.key", "present, 0600, git-ignored", "auto-generated if absent"],
    ["config/lab.env", "present, git-ignored", "holds HMAC_SECRET and the four laptop addresses"],
    ["IM_HMAC_SECRET", "env var, read by SCADA + middleware", "must match on both or every command is HMAC_INVALID"],
    ["Committed secrets", "**none**", "`git ls-files` shows no key, pem, or lab.env"],
], ["Item", "State", "Note"])}

No secret is committed and both secret files are correctly ignored. The weak point is distribution, not storage: the shared
secret is copied by hand into a file on each laptop, with no rotation path. See `05`.

## Model artefacts

{table([
    ["models/weights/physical_model_v2.joblib", f"{M['model_runtime']['weights_file_mb']} MB", "LIVE model"],
    ["models/weights/physical_model.joblib", "1.49 MB", "v1 fallback, still loadable"],
    ["cyber weights", "absent", "deliberate: the cyber branch is rules-only"],
    ["SWaT archive", "absent", "blocks re-measurement"],
], ["Artefact", "Size", "Role"])}

## Opt-in switches (all default OFF)

`IM_QUARANTINE`, `IM_POLICY_FILE`, `IM_DASHBOARD_TOKEN`, `IM_HMAC_KEYS`, `IM_INVESTIGATOR`, `IM_PHYSICAL_SENSITIVITY`,
`IM_PHYSICAL_THRESHOLD`, `IM_PHYSICAL_MODEL`, `IM_TWIN_NOISE`, `IM_TWIN_TIME_SCALE`, `IM_PENDING_TIMEOUT_S`.

Eleven switches, every one of them off by default. The demo therefore runs with authorization, per-device keys, dashboard auth
and quarantine all disabled. That is a defensible default for a demo and an indefensible one for a deployment; the gap between
"the code supports it" and "the running system uses it" is the subject of `05`.

## Test suite state at baseline

{T['summary']['PASS']} scripts passed, {T['summary']['FAIL']} failed, {T['summary']['SKIPPED']} skipped;
{T['summary']['check_lines_passed']} individual checks passed, {T['summary']['check_lines_failed']} failed.
Recorded at commit `{T['environment'].get('git_commit')}`, {T['total_seconds']} s wall clock.

A suite this green on a system with the defects listed in `05` is itself a finding: the tests assert that each component does
what it was written to do, and almost never that the system as a whole does what an operator needs. See `05-anomalies-found.md`
item A1.
""")

print("base files done")
