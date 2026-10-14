# Industrial Mind

SCADA -> Middleware (Cyber Agent + Physical Agent + Orchestrator) -> PLC security demo.

## Setup

    python -m venv venv && source venv/bin/activate
    pip install -r requirements.txt

HMAC secret (shared by SCADA and middleware). Pick one:

    export IM_HMAC_SECRET="$(python -c 'import secrets;print(secrets.token_hex(32))')"   # in BOTH terminals
    # or leave unset: config/hmac_secret.key is generated on first run (mode 0600, git-ignored)

Hosts and ports (single machine: defaults work; resolved in `docs/netconfig.py`, CLI flags override):

    IM_PLC_HOST / IM_PLC_PORT                 # middleware/attacker -> PLC          (default loopback:5020)
    IM_PLC_LISTEN_HOST / IM_PLC_LISTEN_PORT   # PLC bind                            (default 0.0.0.0:5020)
    IM_MIDDLEWARE_HOST / IM_MIDDLEWARE_PORT   # SCADA/attacker -> middleware        (default loopback:5021)
    IM_LISTEN_HOST / IM_LISTEN_PORT           # middleware bind                     (default 0.0.0.0:5021)
    IM_DASHBOARD_HOST / IM_DASHBOARD_PORT     # middleware -> dashboard             (default loopback:5050)
    IM_DASHBOARD_URL                          # full URL override for the above
    IM_DASHBOARD_BIND_HOST                    # dashboard bind                      (default loopback)

Entry points also take flags: `plc.plc --host --port`, `middleware.middleware_server --listen-host
--listen-port --plc-host --plc-port --dashboard-url`, `dashboard/app.py --host --port`,
`scada.scada --host --port`, `attacker.attacker --host --port --plc-host --plc-port`.

Optional settings:

    IM_TRUSTED_SOURCES="<scada-ip-or-cidr>"       # SCADA whitelist (default: this machine only)
    IM_LOG_DIR=logs                               # where blocked_attacks.jsonl is written
    IM_HMAC_MAX_SKEW_SECONDS=30                   # signed-command freshness window

## Models (one-time, deterministic)

    python -m models.train_models      # writes models/weights/*.joblib (shipped pre-trained too)

See MODELS_RATIONALE.md. Without weights the middleware still runs on the
deterministic rules alone (models report NO_MODEL).

    IM_CYBER_MODEL_ENFORCE=1          # let a CyberModel anomaly DROP commands (default: monitor only)
    IM_HEALTH_REFRESH_SECONDS=1       # how often machine health / RUL is recomputed
    IM_TELEMETRY_LOG_SECONDS=5        # how often the middleware logs live telemetry + health
    IM_LOG_LEVEL=INFO

## Run (one terminal each, from the project root)

    python -m plc.plc
    python dashboard/app.py                # http://<IM_DASHBOARD_BIND_HOST>:5050
    python -m middleware.middleware_server
    python -m scada.scada

## Attacks

    python attacker/attacker.py flood | impossible-command | replay | false-injection
    python attacker/attacker.py cross-register
    python attacker/attacker.py hmac-missing | hmac-tamper | hmac-forged | delayed-replay
    python attacker/attacker.py hmac-missing --source-ip 127.0.0.2,127.0.0.3   # several attacking IPs

On macOS, add loopback aliases first: `sudo ifconfig lo0 alias 127.0.0.2 up`.
The dashboard Attacks panel has the same buttons plus an optional source-IP box.

Every blocked command is appended to `logs/blocked_attacks.jsonl` and shown in the
Blocked IPs / Blocked Sources section at the bottom of the dashboard.

### Randomised attacks

    python attacker/attacker.py random --type ramp                # new parameters every run
    python attacker/attacker.py random --type flood --seed 42     # reproducible
    python attacker/attacker.py random --dry-run --count 5        # print the plans, send nothing

Types `freeze`, `ramp`, `cross-register` follow behaviours seen in SWaT's labelled attack windows; `impossible-command`,
`flood`, `replay` are **synthetic extensions** (SWaT has no network-layer attacks). The fixed, scripted attacks above stay for
live demos (the three demo attacks are `flood`, `impossible-command`, `cross-register`).

## Multi-laptop demo and Wireshark

See `docs/topology.md` (4 laptops: roles, environment variables, firewall rules, preflight `python -m tools.check_topology`) and
`docs/wireshark_setup.md` (capture filters, Modbus port preference, the side-by-side demo, `python -m tools.wire_correlate`).

## Packet tracer (dashboard, bottom panel)

Click any command in the list to see every hop it met, with the values the backend actually computed: arrival (peer, function
code, register, value, signature present?), the six Cyber Agent checks, the cyber model (rules-only: `NO_MODEL`), the four
Physical Agent checks, the physical model scores against their thresholds, the orchestrator's inputs and the branch it took,
and the outcome (forwarded to the PLC, or dropped and which log file recorded it). Checks after the first failure show
`NOT_RUN`. API: `GET /api/traces`, `GET /api/trace/<tx_id or TX-007>`.

Decisions are `PASS`, `DROP` (a rule layer failed) or `ALERT` (both rule layers passed but the advisory physical model flagged
an attack: the command is forwarded and highlighted; the model never blocks).

## How the HMAC signature works (plain-language narration)

*"Every command SCADA sends is stamped with a seal that only SCADA and the middleware can make."*

1. **A shared secret.** SCADA and the middleware both hold the same long secret key (`IM_HMAC_SECRET`, or an auto-generated
   `config/hmac_secret.key`). The key is never sent over the wire, never logged, never shown on the dashboard.
2. **What gets sealed.** For each command SCADA takes the exact facts that decide what the plant will do: which register, which
   value, a one-time random number (the *nonce*) and the current time. It packs them into a fixed-width binary block, so there is
   only one possible encoding of a command, with no formatting tricks.
3. **The seal.** SCADA runs those bytes plus the secret through HMAC-SHA256 and gets a 32-byte tag. Change one bit of the
   command and you get a completely different tag, and nobody can produce the right tag without the secret.
4. **On the wire.** The frame carries the command, the nonce, the timestamp and the tag. The tag proves *who* sent it and that
   it was not changed.
5. **Verification.** The middleware rebuilds the same block from what it received, computes its own tag with its own copy of
   the secret and compares the two in constant time. Mismatch means `HMAC_INVALID` and the command is dropped (a changed value
   in transit, or a forger without the key). No tag at all means `HMAC_MISSING`.
6. **Freshness.** The timestamp must be within +/-30 s of the middleware's clock, otherwise `HMAC_EXPIRED` (a captured frame
   replayed too late). This is the *delayed replay* attack.
7. **No reuse.** Every nonce is remembered; a second frame with the same nonce is `REPLAY_DETECTED`, even though its tag is
   perfectly valid. This is the *replay* attack.

**What HMAC does not do.** It proves the sender holds the key, not that the command is *sensible*. A compromised engineering
workstation that owns the key can sign a valid but dangerous command; that is why the rate limit, the replay checks and the
Physical Agent (bounds, rate of change, cross-register rules, and the advisory SWaT-trained model) sit behind it. The packet
tracer shows exactly where each demo attack is stopped.

## Tests

    python -m tests.test_cyber_agent
    python -m tests.test_physical_agent
    python -m tests.test_orchestrator
    python -m tests.test_models
    python -m tests.test_pipeline
    python -m plc.plc &  python -m tests.pipeline_test     # needs a running PLC

## Middleware stress test

    python -m tests.test_middleware_efficiency                       # 2400 msgs @ 300/s + 2000 capacity
    python -m tests.test_middleware_efficiency --payloads 40000 --rate 400   # soak

Writes logs/middleware_benchmark_<timestamp>.json and appends logs/middleware_benchmark.csv.

## Benchmarks (latency + accuracy, reproducible)

One command regenerates everything quoted below and the full report:

    python -m benchmark.run_all                                # latency, rule-based checks, twin; reuses a stored SWaT section if present
    python -m benchmark.run_all --data-dir "<SWaT archive>"    # also re-measures the held-out SWaT test block (needs the archive)

<!-- BENCHMARK:START (generated by python -m benchmark.run_all; do not edit by hand) -->

_Regenerate: `python -m benchmark.run_all [--data-dir <SWaT archive>]`. Full tables: `docs/reports/benchmark_report.md`. These numbers: Linux-6.18.44-fc-v114-x86_64-with-glibc2.39, Python 3.13.16, commit `c42e57c`._

* **Decision latency** (real pipeline, in-process, 3000 commands x 3): mean **0.595 ms**, p95 **1.393 ms**, p99 **1.799 ms** per command (not network latency). Live Modbus round trip of a signed write to a running middleware (client side, 300 writes): mean 3.9392 ms, p95 5.9084 ms.
* **Held-out SWaT test block:** NOT RUN on this machine (the data lives only where the archive is). No SWaT number is quoted until measured.
* **Rule-based checks** (constructed scenarios, not SWaT): 4400/4400 violating scenarios dropped with the expected reason, legitimate false-positive rate 0.0%. Deterministic rules: a regression check, not a detection claim.
* **Twin** (synthetic plant, not SWaT): 0.25 model alarm episodes per hour on the healthy twin.

<!-- BENCHMARK:END -->

The old synthetic-spreadsheet evaluation (`evaluation/`) targets register names that no longer exist and is superseded by the above.
