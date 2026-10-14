# IndustrialMind

An inline security middleware that sits between a **SCADA operator simulator** and a **PLC digital twin** of a five-stage water
treatment plant. Every command SCADA sends passes through a **Cyber Agent** (deterministic traffic and authentication rules) and a
**Physical Agent** (deterministic plant-safety rules plus an advisory model trained on the SWaT dataset); an **Orchestrator** turns
their verdicts into `PASS`, `ALERT` or `DROP`. A dashboard shows every decision, and a **Packet Tracer** shows, hop by hop, what each
layer computed for any single command. Wireshark/tshark on the same traffic is the independent proof that the packets are real.

```
 SCADA (operator)            +--------------------- MIDDLEWARE (this project) ----------------------+          PLC digital twin
 signs every command  --->   |  Cyber Agent    (RULES: whitelist, FC, register, rate, HMAC, replay)  |
   Modbus FC16, :5021        |  Physical Agent (RULES: bounds, rate-of-change, cross-register)       | --->     Modbus :5020
 ATTACKER (separate)  --->   |                 (+ MODEL: SWaT-trained, ADVISORY only)                |  only    5 stages x 4 points
   same port                 |  Orchestrator   (RULE-BASED four-branch fusion -> PASS / ALERT / DROP)|  PASS/   10 actuators, 10 sensors
                             +------------------------------------------------------------------------+  ALERT
                                              |  decisions + per-hop traces (HTTP)
                                              v
                                      Dashboard :5050  (live tables, Packet Tracer, blocked-source log)
```

**Status in one paragraph (read this before quoting anything).** The rule layers are deterministic and tested. The only learned
component in use is the **physical model**, trained on real SWaT data, **advisory** (it raises `ALERT`, it never blocks). On the
held-out SWaT test block it ranks attacks reasonably (ROC-AUC about 0.82) but detects only a minority of attack windows at its operating
point and raises more false alarms than its target (see [Benchmarks](#benchmarks) and [Known limitations](#known-limitations)).
The cyber branch has **no learned model by design**: a SWaT-trained candidate was weak and was not promoted. A learned fusion model
was also tried and **rejected**. Nothing here claims real-data performance for the cyber rules: SWaT contains no network traffic.

Contents: [Quick start](#quick-start-one-laptop-10-minutes) · [Architecture](#architecture-what-each-layer-does) ·
[Dataset](#dataset-swat-only) · [Twin](#the-digital-twin) · [Packet journey](#the-journey-of-one-command) ·
[Setup per laptop](#setup-per-laptop-role) · [Training](#training-instructions-per-model) · [Attacker](#attacker-design) ·
[Dashboard](#dashboard-and-packet-tracer) · [Wireshark](#monitoring-with-wireshark) · [**Demo runbook**](#live-demo-verification-runbook) ·
[Benchmarks](#benchmarks) · [Tests](#tests) · [Reference](#reference) · [Limitations](#known-limitations) · [Future work](#future-work) ·
[Troubleshooting](#troubleshooting)

---

## Quick start (one laptop, 10 minutes)

Needs Python 3.13 or 3.14 and a terminal at the project root. Nothing else is required: the SWaT data is **not** needed to run the demo.

```bash
python -m venv venv
source venv/bin/activate            # Windows PowerShell: venv\Scripts\Activate.ps1
pip install -r requirements.txt     # scikit-learn is pinned EXACTLY (==1.9.1): the shipped model is a pickle
```

Open **four terminals** (activate the venv in each), all from the project root, in this order:

```bash
python -m plc.plc                      # 1. the PLC digital twin, Modbus on :5020
python dashboard/app.py                # 2. the dashboard, http://127.0.0.1:5050
python -m middleware.middleware_server # 3. the middleware, Modbus on :5021
python -m scada.scada                  # 4. the operator: one signed write every 2 s
```

No secret needs setting on one machine: the first process that needs it creates `config/hmac_secret.key` (mode 0600, git-ignored) and the others read it.

**What you should see**
* Terminal 4 (SCADA) prints a line like `[SCADA] WRITE SENT tx=0f4bfc74 reg=MV302 value=98.00` every 2 s (it cycles through the actuators, each near its nominal); terminal 3 (middleware) prints `[MIDDLEWARE] PASS src=127.0.0.1 MV302=98.00 reason=OK ...` for each.
* Dashboard (`http://127.0.0.1:5050`): the *SCADA -> PLC* table fills with green `PASS` rows, the telemetry panel shows all 20 points (10 sensors and 10 actuators).
* For the first ~30 s the physical model reports `WARMING_UP` (it needs a 30-second window of telemetry). The middleware terminal prints a status line every 5 s containing `plant=WARMING_UP window=11/30`; it becomes `plant=NORMAL` once the window is full. After that, an occasional yellow `ALERT`
  row on a healthy plant is normal: the model is advisory and has a false-alarm rate (see Limitations).
* Press **Attacks** on the dashboard and click **HMAC Tamper**: a red `DROP` row appears with reason `HMAC_INVALID`, and the bottom
  **Packet Tracer** panel shows the `hmac` check in red and everything after it `NOT_RUN`.

Blocked commands are logged to `logs/blocked_attacks.jsonl` in the project folder (set `IM_LOG_DIR` to put it elsewhere). Stop everything with Ctrl-C. **Restart the PLC (terminal 1) between demo runs**: an attack such as *False Injection* really changes the plant state, and the
twin keeps it until restarted. The dashboard **Reset** button clears only the dashboard.

---

## Architecture: what each layer does

Every box below is labelled **RULE** (deterministic code, no training data) or **MODEL** (learned from SWaT).

### Cyber Agent: RULES only (`middleware/cyber_agent.py`)
Checks *how a command arrived*, not what it means. Checks run in this order; the **first failure wins**:

| # | Check | Drops with | Notes |
|---|---|---|---|
| 1 | Source whitelist | `UNTRUSTED_SOURCE` | real TCP peer address vs `IM_TRUSTED_SOURCES` (default: this machine) |
| 2 | Function code | `INVALID_FUNCTION_CODE` | only 3, 6, 16 |
| 3 | Register allow-list | `INVALID_REGISTER` | only the 20 known registers |
| 4 | Per-source rate limit | `RATE_LIMIT_EXCEEDED` | 5 requests per second per source; before the crypto, as a cheap DoS guard |
| 5 | HMAC-SHA256 | `HMAC_MISSING` / `HMAC_MALFORMED` / `HMAC_INVALID` / `HMAC_EXPIRED` | tag over register, value, nonce, timestamp; freshness +/-30 s |
| 6 | Replay | `REPLAY_DETECTED` | nonce reuse, or identical payload within 2 s |

There is **no cyber ML model** (`NO_MODEL`): a SWaT-trained candidate scored test ROC-AUC 0.63 and was not promoted; the user then decided to drop cyber ML.
SWaT has no signatures, replay tags or source addresses, so these rules cannot be evaluated on SWaT; they are tested with constructed scenarios.

### Physical Agent: RULES (`middleware/physical_agent.py`) plus one advisory MODEL
Checks *whether the command makes physical sense for the plant*:

| Layer | Drops with | What it checks |
|---|---|---|
| 0 | `WRITE_TO_SENSOR_REGISTER`, `UNKNOWN_REGISTER` | only the 10 actuators accept commands |
| 1 | `OUT_OF_BOUNDS` | value inside the register's range |
| 2 | `RATE_OF_CHANGE_EXCEEDED` | the change fits the actuator's maximum slew rate over the time since it last settled |
| 3 | `CROSS_REGISTER_VIOLATION` | 8 two-register safety rules (e.g. `RAW_PUMP_DRY_RUN`: P101 >= 60 with MV101 <= 10) plus `VALVE_CLOSING_LOW_LEVEL` and `RO_PRESSURE_OVERLOAD`, evaluated on the projected plant state; a command that moves an already-unsafe state *toward* safety is allowed |

Upstream (PLC to SCADA telemetry) the agent also applies a **sensor-envelope rule**: every sensor must stay inside the envelope **measured** on SWaT normal data
(`docs/swat_bounds.json`). This rule is **alert-only** (a log line and a dashboard event, never a block).

**The advisory MODEL** (`models/physical_model.py`, weights `models/weights/physical_model.joblib`): a 30-second sliding window of the 10 sensors and 8 actuators at 1 Hz
becomes 87 features; an Isolation Forest (unsupervised, trained on normal windows) and a supervised random-forest head (trained on SWaT's labelled attacks) each give a score. If either
exceeds its threshold the model raises `threat_flag`. The shipped operating point targets 0.5 false-alarm episodes per hour on validation data. It is **advisory**: it can
turn a pass into an `ALERT` but never into a `DROP`.

### Orchestrator: RULE-BASED fusion (`middleware/orchestrator.py`)

| Cyber rules | Physical rules | Physical model | Decision |
|---|---|---|---|
| fail | any | any | **DROP** (reason = the cyber reason) |
| pass | fail | any | **DROP** (reason = the physical reason) |
| pass | pass | flags an attack | **ALERT** (command is **forwarded**, highlighted; reason `PHYSICAL_MODEL:<which score>`) |
| pass | pass | quiet / warming up | **PASS** |

On the upstream path only the physical side exists. The orchestrator also forwards each decision to the dashboard from a single background worker thread, so a slow
dashboard can never delay a command. **A learned fusion model was trained and rejected**: on the held-out test block it ranked attacks worse (ROC-AUC 0.68) than the physical
model alone (0.83) and detected fewer segments (4 vs 6 of 10) (`docs/reports/fusion_training_report_swat.md`). The code is kept as a reproducible negative result
(`models/train_fusion_swat.py`).

---

## Dataset: SWaT only

**SWaT** (Secure Water Treatment testbed, iTrust, Singapore University of Technology and Design) is the **only external dataset** this project uses, and the only
one it will use: a real, labelled water-treatment process with physical attacks. It supplies the plant structure (five stages and their tags), the real operating ranges, and labelled
attack windows. Everything SWaT cannot supply is either **derived from SWaT columns and labels** or **labelled synthetic or rule-tested**, and listed under Limitations.

* The licensed data is **never committed** and never leaves the machine that has it. Everything in `docs/reports/` and `benchmarks/` is aggregate statistics only.
* Archive facts used (measured): 1 Hz; normal and attack files are **not chronological**; the normal file holds an exact duplicate copy of the normal period (de-duplicated by
  `swat/loader.py`); 35 attack segments; no network fields, no attack list, no packet captures.
* **Splits are by calendar block, never random rows**: train 22-29 Dec 2015, validation 30-31 Dec, test 1-2 Jan 2016. Random splits leak (SWaT sensors drift by day).
  One attack segment (segment 22) is about 10 hours and 66 % of all attack rows, so evaluation is always per segment and the selection step excludes any segment that dominates a block.
* **Used for:** the measured sensor bounds and envelope (`docs/swat_bounds.json`), calibration of the twin, training the physical model, and the held-out physical benchmark.
* **Cannot supply:** HMAC signatures, replay behaviour, source addresses, network traffic. The cyber rules are therefore rule-tested, never SWaT-evaluated.

---

## The digital twin

`plc/twin.py` is a small physics model of a five-stage SWaT-style train, exposed over Modbus by `plc/plc.py`. **20 registers = 5 stages x 4 points**; names are SWaT tags;
10 actuators are writable, 10 sensors are read-only (writes to them are dropped). The single source of truth is `docs/interfaces.py` (`MACHINES`); `docs/register_map.md` is generated from it.

| Stage | Process | Actuators | Sensors |
|---|---|---|---|
| S1 Raw water | raw tank | MV101 inlet valve, P101 pump | LIT101 level, FIT101 flow |
| S2 Chemical dosing | pH and chlorine | P203 HCl pump, P205 NaOCl pump | AIT202 pH, FIT201 flow |
| S3 Ultrafiltration | UF tank, membrane | MV302 feed valve, P302 pump | LIT301 level, DPIT301 membrane dP |
| S4 Dechlorination | UV removal | P402 pump, UV401 lamp | LIT401 level, AIT402 ORP |
| S5 Reverse osmosis | RO | P501 high-pressure pump, **MV503** reject valve | PIT501 pressure, FIT501 permeate flow |

**Alignment with SWaT:** sensor ranges and nominal values are the **measured** SWaT medians and ranges (`docs/swat_bounds.json`); actuator nominals are SWaT's "on" states;
`tests/test_bounds_alignment.py` (35 checks) fails if the configuration and the twin drift from the measurements. **Coupling:** stage flows feed forward (S1 pump outflow is S2 flow;
MV302 splits it between the UF tank and a return to the raw tank; S3 outflow fills S4; the S4 pump feeds the RO pump, which starves below ~5 m3/h; dosing pumps act on pH and chlorine, removed by the UV lamp).
UF fouling raises DPIT301 and triggers an automatic backwash. `python -m tests.test_twin_propagation` perturbs stage 1 and asserts stages 2 to 5 respond in order
(about 1.4 s, 5 s, 25 s, 100 s). **Honest caveats:** MV503 has **no SWaT counterpart** (twin-only, labelled synthetic); the twin is a demonstration plant, not a SWaT
replica; the wire format is value x 10 (0.1 resolution, max 6553.5), so pH and permeate flow are coarse. Optional: `IM_TWIN_NOISE=1` adds sensor noise, `IM_TWIN_TIME_SCALE=N` speeds it up.

---

## The journey of one command

Follow a single operator write of `MV101 = 56.0 %`. **There is no encryption in this system: it provides integrity and authenticity, not confidentiality** (see Limitations).

1. **SCADA builds and signs a frame.** It packs `version, register, raw value (=560), nonce, timestamp` into a fixed-width binary block and computes **HMAC-SHA256** over it with
   the shared secret (`docs/hmac_auth.py`). The frame is **27 Modbus registers**, written with **function code 16 to address 100** of the middleware:

   | Words | 0 | 1 | 2 | 3-6 | 7-10 | 11-26 |
   |---|---|---|---|---|---|---|
   | Content | version (1) | target register | value x 10 | 64-bit nonce | 64-bit timestamp (ms) | 32-byte HMAC tag |

2. **The middleware receives it** on :5021 and notes the real peer address and port (not a value the sender claims). It builds a command record and a snapshot of the plant state
   (latest telemetry, and the set-points already approved but still ramping).
3. **Two branches run concurrently** on worker threads: the **cyber branch** (the six rule checks above) and the **physical branch** (the four rule layers, then the advisory model on the current telemetry window).
4. **HMAC verification:** the middleware rebuilds the same byte block from what it received, computes its own tag with its own copy of the secret and compares in constant time.
   Mismatch is `HMAC_INVALID` (changed in transit, or a forger without the key); no frame at all is `HMAC_MISSING`; a timestamp more than 30 s away from the middleware clock is `HMAC_EXPIRED`;
   a nonce seen before is `REPLAY_DETECTED` even though its tag is valid.
5. **The orchestrator fuses** the verdicts with the four-branch table and records the inputs and the branch taken in the decision.
6. **Outcome.** `PASS`/`ALERT`: the middleware registers the pending command, then **writes the value to the PLC** (FC6 to the PLC's port 5020) and later checks the PLC's feedback.
   `DROP`: nothing is sent to the PLC, and the command is appended to `logs/blocked_attacks.jsonl` (never containing the key or the tag).
7. **The dashboard** receives the decision and a **per-hop trace** (below). In Wireshark the same command is one FC16 on :5021 and, if forwarded, one FC6 on :5020.

**HMAC in plain words (for narration).** *"Every command carries a seal only SCADA and the middleware can make. The seal is computed from the exact register, value, a one-time number and the time, using a secret
that is never sent. Change one bit and the seal no longer matches. Reuse an old command and the one-time number gives it away. Hold a command too long and the time gives it away."*
**What HMAC does not do:** it proves the sender holds the key, not that the command is *sensible*. A compromised workstation that owns the key can sign a dangerous command; that is why the rate limit,
the replay check and the whole Physical Agent sit behind it.

---

## Setup per laptop role

Single machine: nothing to configure (all defaults are loopback). For several machines the **only** place defaults live is `docs/netconfig.py`; every component takes environment variables or flags.
The recommended four-laptop layout (2 MacBooks, 2 Windows laptops), the firewall rules, the preflight check and the two attack modes are in **`docs/topology.md`**. Summary:

| Laptop | Role | Runs | Needs set |
|---|---|---|---|
| Mac A | **Middleware** + dashboard + Wireshark | `python dashboard/app.py`, `python -m middleware.middleware_server` | `IM_PLC_HOST=<PLC_IP>`, `IM_TRUSTED_SOURCES="<SCADA_IP>,<ATTACKER_IP>"`, `IM_HMAC_SECRET` |
| Windows A | **PLC twin** + tshark | `python -m plc.plc` | firewall: allow TCP 5020 from the middleware |
| Mac B | **SCADA** | `python -m scada.scada` | `IM_MIDDLEWARE_HOST=<MW_IP>`, `IM_HMAC_SECRET` |
| Windows B | **Attacker** (CLI) | `python attacker\attacker.py ...` | `IM_MIDDLEWARE_HOST=<MW_IP>`, `IM_PLC_HOST=<PLC_IP>` (false-injection only), `IM_HMAC_SECRET` |

Replace `<..._IP>` with the laptops' real addresses (nothing in this repository contains one). Three things always go wrong first: **the secret must be identical** on SCADA, middleware and attacker; **clocks must agree
within 30 s** (turn on automatic time); **firewalls** must allow 5021 into the middleware and 5020 into the PLC. Run `python -m tools.check_topology --role <plc|middleware|dashboard|scada|attacker> --multi`
on each laptop first: it flags leftover loopback settings, unreachable peers and prints the secret's fingerprint so you can compare it across laptops without revealing it.

The multi-laptop run has been **rehearsed on one machine only** (the laptops were not available while this was written): see Limitations.

---

## Training instructions per model

The demo needs **no training**: `models/weights/physical_model.joblib` is shipped. Retrain only if you change the data, features or protocol. All training needs the **SWaT archive on the machine that runs it**
(folder containing `normal.csv`, `attack.csv`; `merged.csv` is used only if those two are missing) and writes **candidates to `models/candidates/`, never to `models/weights/`**.

**Physical model (the only learned model in use)**
```bash
python -m tools.swat_inspect "<SWaT archive>" --out swat_inspection          # optional: aggregate-only report of the archive
python -m models.train_physical_swat --data-dir "<SWaT archive>" --candidate # bounds + model + report -> models/candidates/
python -m models.train_physical_swat --fixture --candidate                   # code-path check on synthetic SWaT-SHAPED data (numbers meaningless)
```
Protocol: 30 s windows at 1 Hz, stride 5 s; split by calendar block; bounds and normalisation from train-block normal rows only; Isolation Forest on train-normal windows; the supervised head's
feature variant and regularisation chosen on **validation** by average precision *excluding* any segment holding more than half of a block's attack windows; threshold set by a false-alarm budget on validation;
test block used for reported numbers. **Disclosed protocol revision:** run 1 used max-F1 thresholds; after it overfit (train AUC 1.0, test 0.66) the selection protocol above was introduced, so the test block is
no longer a pristine blind hold-out. Both runs are in `docs/reports/physical_training_report_swat_run1.md` and `..._run2.md`. To adopt a candidate, review its report, then copy
`models/candidates/physical_model.joblib` over `models/weights/physical_model.joblib` and keep the scikit-learn version identical to the pin in `requirements.txt` (the file is a pickle). The shipped file's
classifier threshold (0.601) is the 0.5 false-alarm-per-hour operating point chosen from the validation operating curve and recorded in its metadata.

**Cyber model: not trained, by design.** A SWaT-based candidate exists (`models/train_cyber_swat.py --data-dir ... --candidate`) and is documented as a negative result: test ROC-AUC 0.63, F1 0.14
(`docs/reports/cyber_training_report_swat.md`). SWaT has no network traffic, so it could only model actuator state-change events, and it was not promoted. The cyber branch is rules-only.

**Fusion (orchestrator) model: trained, rejected.** `python -m models.train_fusion_swat --data-dir "<SWaT archive>" --candidate` reproduces the cross-fitted experiment (out-of-fold physical outputs,
capped dominant segment, thresholds from validation, test touched once). Result: worse than the physical model alone, so the orchestrator is the rule-based table. A fixture mode (`--fixture`) checks the code.

**Reproducing the held-out numbers:** `python -m benchmark.run_all --data-dir "<SWaT archive>"` (next sections).

---

## Attacker design

`attacker/attacker.py` is a **real Modbus client** (it sends real frames to the middleware's port), in two families:

**Fixed, scripted attacks: identical every run, for live-demo reliability.** The three **demo attacks** are `flood`, `impossible-command` and `cross-register`. The other fixed probes: `sensor-write`,
`replay`, `false-injection` (a legitimate command, then a direct write to the PLC that bypasses the middleware), `hmac-missing`, `hmac-tamper`, `hmac-forged`, `delayed-replay`.

**Randomised attacks (`random`): parameters drawn per run, reproducible from a seed** (`attacker/scenarios.py`). Target register, timing, intensity, step size and counts vary; the seed is printed.

| Type | Origin | What varies |
|---|---|---|
| `freeze` | SWaT-derived behaviour | target actuator, held value, repeat count and interval |
| `ramp` | SWaT-derived behaviour | target, direction, how far, step size, interval |
| `cross-register` | SWaT-derived behaviour | which of the 8 rules, which half is set first, step size, interval |
| `impossible-command` | **synthetic extension** | target, overshoot factor (1.1 to 10 x max), write count, gaps |
| `flood` | **synthetic extension** | target, burst size, pace (6.7 to 100 requests per second) |
| `replay` | **synthetic extension** | target, value, replay count, delays |

*"SWaT-derived"* means the behaviour (an actuator forced to a wrong state, a held value, a slow drift, a physically inconsistent combination) is one seen in SWaT's labelled attack windows; SWaT has no network-layer
attacks, so flood, replay and impossible-command are **synthetic extensions**, labelled as such in code and in every plan. Parameter ranges come from `docs/swat_attack_profile.json` when it exists
(`python -m tools.swat_attack_profile --data-dir ...`, aggregate output; only the ramp range is calibrated), otherwise from stated design defaults, and each plan prints which.

```bash
python attacker/attacker.py flood                          # a fixed demo attack
python attacker/attacker.py random --type ramp             # randomised, fresh seed
python attacker/attacker.py random --type flood --seed 42  # reproducible
python attacker/attacker.py random --dry-run --count 5     # print five plans, send nothing
python attacker/attacker.py random --log-file logs/attacks.jsonl   # append plan + per-frame records
python attacker/attacker.py hmac-tamper --source-ip 127.0.0.2      # bind a different local source address
```
**Threat model:** `flood`, `impossible-command`, `replay`, `cross-register`, `delayed-replay`, `freeze`, `ramp` model a **compromised engineering workstation that holds the key** (an insider); the `hmac-*`
attacks model an external attacker **without** the key. For several source addresses on one Mac add loopback aliases first: `sudo ifconfig lo0 alias 127.0.0.2 up`.

---

## Dashboard and Packet Tracer

`python dashboard/app.py` serves `http://127.0.0.1:5050` (set `IM_DASHBOARD_BIND_HOST=0.0.0.0` only if another laptop must open it). It shows KPIs (total/pass/drop), the **SCADA -> PLC** and **PLC -> SCADA** security
tables, live telemetry for all 20 points (10 sensors, 10 actuators), CPU, the **Blocked sources** section (read from `logs/blocked_attacks.jsonl`, so it must run on the machine that runs the middleware), and an **Attacks** panel
that launches the fixed attacks (it runs the attacker on the dashboard's own machine). **Reset** clears the dashboard only, not the plant.

**Packet Tracer** (bottom panel). Click any command in the list (or let it follow the newest): the seven hops it met, with the values the backend computed:
1 Arrival (peer, function code, register, value, signature present, nonce) · 2 Cyber Agent rules (six checks, each `PASS`/`FAIL`/`NOT_RUN`, with values such as the rate-limit count) · 3 Cyber model (`NO_MODEL`) ·
4 Physical Agent rules (five checks with bounds, rate limit, rules evaluated) · 5 Physical model (status, plant state, scores against thresholds, which score flagged) · 6 Orchestrator (inputs and the branch taken) ·
7 Outcome (forwarded to the PLC, or dropped and which log file recorded it). The trace is built from the real verdicts; checks after the first failure show `NOT_RUN` (the agents stop there). API: `GET /api/traces`,
`GET /api/trace/<tx_id or TX-007>`. Only SCADA-to-PLC commands are traced.

---

## Monitoring with Wireshark

Wireshark/tshark (free, built-in Modbus dissector) sees the real packets regardless of what the dashboard says. Full filters, field names and the side-by-side demo are in **`docs/wireshark_setup.md`**; the essentials:

* **Wireshark decodes Modbus only on port 502.** Set the **port preference**, not *Decode As* (which cannot tell requests from responses): Edit -> Preferences -> Protocols -> Modbus/TCP -> port **5021**
  (middleware leg) or **5020** (PLC leg); tshark: `-o mbtcp.tcp.port:5021`.
* Capture filter: `tcp port 5021` (middleware laptop), `tcp port 5020` (PLC laptop). Display filters: signed commands `modbus.func_code == 16 && tcp.dstport == 5021`; forwarded writes `modbus.func_code == 6 && tcp.dstport == 5020`.
* A signed command is one FC16 write of 27 words at address 100; words 3-6 are the **nonce**. The dashboard's tx_id is created inside the middleware and is **not on the wire**: the Packet Tracer's Arrival hop shows the same nonce words, which is how a packet is
  matched to a dashboard row. `python -m tools.wire_correlate --mw mw.tsv --plc plc.tsv` automates it and checks that **a dropped command is on the middleware leg but not on the PLC leg**.

The filters, the port preference and the nonce match were verified on real traffic from this stack (tshark 4.2.2, loopback). The GUI menus and the Windows/macOS interface names were not tried on the real laptops.

---

## Live demo verification runbook

Goal: a presenter who has never seen the project runs the whole demo and can check, at each step, that the system did what it claims. About 15 minutes. Each step has an **observable you can verify**.

### Before the demo (preflight, 10 minutes)
1. **Install** (once per laptop): `pip install -r requirements.txt` in a venv. Check `python -m tests.test_environment` prints `ALL PASS` (scikit-learn pin and model load).
2. **Clocks:** automatic time on every laptop.
3. **Secret:** the same `IM_HMAC_SECRET` (32+ characters) on SCADA, middleware, attacker. Single laptop: leave it unset.
4. **Multi-laptop only:** run `python -m tools.check_topology --role <role> --multi` on each laptop; every line should be `OK` and the secret fingerprints must be equal. Choose the attack mode (below).
5. **Start in order:** PLC, dashboard, middleware, SCADA (commands in the Quick start). **Wait about 40 seconds** for the physical model's window to fill.
6. **Healthy baseline:** the dashboard shows `PASS` rows every 2 s, telemetry values near their nominals (e.g. LIT101 about 526 mm), no recent red rows. An occasional yellow `ALERT` is the advisory model's false-alarm rate: say so out loud, it is part of the honest story.

### The script

| # | Do | You should see (dashboard + terminal) | Why |
|---|---|---|---|
| 1 | Nothing: watch SCADA traffic | Green `PASS` rows; click one: Packet Tracer shows all checks `PASS`, outcome "forwarded" | the normal path |
| 2 | **HMAC Tamper** (or `attacker.py hmac-tamper`) | `DROP` `HMAC_INVALID`; tracer: `hmac` red, `replay` `NOT_RUN`, outcome "dropped", log file named | value changed after signing |
| 3 | **HMAC Missing** | `DROP` `HMAC_MISSING` | unsigned frame |
| 4 | **HMAC Forged** | `DROP` `HMAC_INVALID` | signed with a guessed key |
| 5 | **Delayed Replay** | `DROP` `HMAC_EXPIRED` | valid tag, 5 minutes old |
| 6 | **Replay** | the first frame `PASS`es, the repeat `DROP`s `REPLAY_DETECTED` | nonce already used |
| 7 | **Flood** | several `DROP` `RATE_LIMIT_EXCEEDED` (about 6 of 10 frames) | over 5 requests per second |
| 8 | **Impossible Command** | `DROP` `OUT_OF_BOUNDS` | P101 = 999 |
| 9 | `attacker.py sensor-write` (CLI only: no dashboard button) | `DROP` `WRITE_TO_SENSOR_REGISTER` | LIT101 is read-only |
| 10 | **Cross-Register** (on a clean plant) | the inlet valve ramp is stopped at about 15 %; reason `CROSS_REGISTER_VIOLATION:RAW_PUMP_DRY_RUN...`; the script prints "Unsafe state PREVENTED" | each step is in bounds and slow, the combination is unsafe |
| 11 | `attacker.py random --type ramp` (twice) | different target and pacing each time (the seed is printed; `--seed 3` reproduces one). The outcome depends on the seed and pacing: steps that are too fast `DROP` (`RATE_OF_CHANGE_EXCEEDED`), steps that complete an unsafe pair `DROP` (cross-register), and slow in-bounds steps pass (they may carry an `ALERT`) | randomisation; the rules stop fast or unsafe drift but not slow in-bounds drift |
| 12 | **False Injection** (last: it damages the plant) | a legitimate `PASS`, then a direct PLC write the middleware never saw; afterwards **yellow `ALERT` rows** on later commands (the advisory model sees the wrong plant state) and a `SENSOR_ENVELOPE_VIOLATION` warning in the middleware terminal | an attack that **bypasses** the middleware is only visible through the physical side; restart the PLC afterwards |

Observed on this stack (single laptop, recorded while writing this runbook): all `DROP` reasons above appeared as listed; 14 blocked commands over the ten fixed attacks; flood dropped 6 of its 10 frames; after false-injection the plant drifted
(LIT101 fell from 526 to about 118 mm within two minutes) and every later SCADA command was forwarded with an `ALERT`.

### The side-by-side moment (multi-laptop, 90 seconds)
Mac A: dashboard Packet Tracer next to Wireshark (`modbus.func_code == 16 && tcp.dstport == 5021`); Windows A: Wireshark `modbus.func_code == 6 && tcp.dstport == 5020`.
Step 1 (a normal SCADA command): a frame appears on both captures, and the nonce words in Wireshark equal the Arrival hop's nonce words. Step 2 (`hmac-tamper` from Windows B): the frame is **on the middleware wire** (value word 950 = 95.0),
the tracer says `DROP`, and the **PLC capture shows nothing**. Then `python -m tools.wire_correlate --mw mw.tsv --plc plc.tsv` prints both frames with `on PLC leg: yes` and `NO`.

### Attack modes (multi-laptop)
The first check is the source whitelist. **Mode A (insider, default):** `IM_TRUSTED_SOURCES="<SCADA_IP>,<ATTACKER_IP>"`, so the attacker passes the whitelist and the *later* layers stop it (everything in the table above).
**Mode B (stranger):** `IM_TRUSTED_SOURCES="<SCADA_IP>"`, so every frame from the attacker dies at `UNTRUSTED_SOURCE`. Restart the middleware to switch.

### How to verify the demo independently of the dashboard
`logs/blocked_attacks.jsonl` has one JSON line per drop (time, source, register, requested value, signature state, both verdicts, reason, latency); `grep -c HMAC_INVALID logs/blocked_attacks.jsonl`. The
middleware terminal prints one line per decision. Wireshark/tshark shows the packets. If the three agree, the demo is real.

### Cleanup
Ctrl-C all processes; **restart the PLC before the next run**; `logs/` is git-ignored (delete `logs/blocked_attacks.jsonl` yourself to start the blocked list from empty).

---

## Benchmarks

One command regenerates everything quoted below and the full report (`docs/reports/benchmark_report.md`, `benchmarks/latest.json`); a test fails if the numbers here drift from the JSON:

    python -m benchmark.run_all                                # latency, rule-based checks, twin; reuses the stored SWaT section
    python -m benchmark.run_all --data-dir "<SWaT archive>"    # also re-measures the held-out SWaT test block (needs the archive)
    python -m benchmark.run_all --live                         # also times the Modbus round trip (needs PLC + middleware running)

<!-- BENCHMARK:START (generated by python -m benchmark.run_all; do not edit by hand) -->

_Regenerate: `python -m benchmark.run_all [--data-dir <SWaT archive>]`. Full tables: `docs/reports/benchmark_report.md`. These numbers: Linux-6.18.44-fc-v114-x86_64-with-glibc2.39, Python 3.13.16, commit `c42e57c`._

* **Decision latency** (real pipeline, in-process, 3000 commands x 3): mean **0.595 ms**, p95 **1.393 ms**, p99 **1.799 ms** per command (not network latency). Live Modbus round trip of a signed write to a running middleware (client side, 300 writes): mean 3.9392 ms, p95 5.9084 ms.
* **Held-out SWaT test block** (real data, physical model only, advisory): ROC-AUC **0.82**, precision 0.37, recall 0.26, F1 0.31, 1.786 false-alarm episodes per hour, 6/10 attack segments detected.
* **Rule-based checks** (constructed scenarios, not SWaT): 4400/4400 violating scenarios dropped with the expected reason, legitimate false-positive rate 0.0%. Deterministic rules: a regression check, not a detection claim.
* **Twin** (synthetic plant, not SWaT): 0.25 model alarm episodes per hour on the healthy twin.

<!-- BENCHMARK:END -->

Four sections with different evidential weight, always reported separately: **latency** (real code, constructed workload); **held-out SWaT** (the only real-data detection result, physical side only);
**rule-based checks on constructed scenarios** (a regression check that each deterministic rule fires, not a detection claim); **twin measurements** (synthetic plant). Latency depends on the machine; the report names it.

## Tests

Plain scripts, each ends with `ALL PASS` or an error (run from the project root, with the venv active):

| Command | Covers |
|---|---|
| `python -m tests.test_cyber_agent` | every cyber rule |
| `python -m tests.test_physical_agent` | every physical rule (16 groups) |
| `python -m tests.test_orchestrator` | the four-branch fusion |
| `python -m tests.test_pipeline` | concurrent branches, unified report (24 checks) |
| `python -m tests.test_trace` | the Packet Tracer matches what the backend computed |
| `python -m tests.test_bounds_alignment` | config and twin vs the measured SWaT bounds (35 checks) |
| `python -m tests.test_twin_propagation` (add `--live` with a running PLC) | stage-to-stage propagation |
| `python -m tests.test_attacker_randomization` | randomised attacks really vary; rules catch the synthetic extensions |
| `python -m tests.test_wire_correlate`, `test_check_topology` | wire correlation and the per-laptop preflight |
| `python -m tests.test_benchmark`, `test_environment` | benchmarks run; README numbers equal the JSON; version pin and clean model load |
| `python -m tests.test_swat_physical`, `test_swat_cyber`, `test_swat_fixture`, `test_fusion_scenarios` | the SWaT code paths on a synthetic SWaT-shaped fixture (code paths only, never real metrics) |
| `python -m tests.pipeline_test` | end to end; **needs a running PLC** (`python -m plc.plc`) |
| `python -m tests.test_middleware_efficiency` | stress test: 2400 messages at 300 per second plus a capacity run; writes `logs/middleware_benchmark_*.json` (can flake on a single host stall: re-run) |

---

## Reference

**Ports:** PLC 5020 · middleware 5021 · dashboard 5050.

| Variable | Meaning (default) |
|---|---|
| `IM_PLC_HOST` / `IM_PLC_PORT` | where the middleware and attacker reach the PLC (loopback:5020) |
| `IM_PLC_LISTEN_HOST` / `IM_PLC_LISTEN_PORT` | PLC bind (0.0.0.0:5020) |
| `IM_MIDDLEWARE_HOST` / `IM_MIDDLEWARE_PORT` | where SCADA and the attacker reach the middleware (loopback:5021) |
| `IM_LISTEN_HOST` / `IM_LISTEN_PORT` | middleware bind (0.0.0.0:5021) |
| `IM_DASHBOARD_HOST` / `IM_DASHBOARD_PORT` / `IM_DASHBOARD_URL` | where the middleware posts events (loopback:5050) |
| `IM_DASHBOARD_BIND_HOST` | dashboard bind (loopback) |
| `IM_TRUSTED_SOURCES` | cyber-agent whitelist, IPs and CIDRs (loopback only) |
| `IM_HMAC_SECRET` / `IM_HMAC_SECRET_FILE` | shared secret, 32+ characters (else `config/hmac_secret.key`, auto-generated) |
| `IM_HMAC_MAX_SKEW_SECONDS` | frame freshness window (30) |
| `IM_LOG_DIR` | where `blocked_attacks.jsonl` is written (`logs`) |
| `IM_LOG_LEVEL`, `IM_TELEMETRY_LOG_SECONDS` | middleware log verbosity; how often the telemetry line is logged (5) |
| `IM_ENVELOPE_ALERTS`, `IM_ENVELOPE_ALERT_SECONDS` | sensor-envelope alerts on/off (on); minimum seconds between alerts per sensor (30) |
| `IM_TWIN_NOISE`, `IM_TWIN_TIME_SCALE` | twin sensor noise (off); speed-up factor (1) |
| `IM_CYBER_MODEL_ENFORCE` | only meaningful if a cyber model is ever promoted (none ships): let it DROP (off) |

Entry points also accept flags that override the variables: `plc.plc --host --port`, `middleware.middleware_server --listen-host --listen-port --plc-host --plc-port --dashboard-url`,
`dashboard/app.py --host --port`, `scada.scada --host --port`, `attacker/attacker.py --host --port --plc-host --plc-port`.

**Repository map.** `plc/` PLC and twin · `middleware/` cyber agent, physical agent, orchestrator, trace, server · `pipeline/` concurrent branches · `models/` physical model, trainers, candidate promotion · `swat/` SWaT loader and the single feature
implementation shared by training and live · `attacker/` attacks and randomised plans · `scada/` operator · `dashboard/` web UI · `docs/` shared code (`interfaces.py`, `hmac_auth.py`, `netconfig.py`, `attack_log.py`), the register map,
topology and Wireshark guides, `reports/` (real-data training and benchmark reports, aggregate only) · `benchmark/` the benchmarks · `tools/` data inspection, preflight, wire correlation, twin gap · `tests/`.
`CLAUDE.md` is the working index for AI-assisted development (hard boundaries enforced by hooks, decisions, file index).

---

## Known limitations

Stated plainly. None of these is hidden elsewhere.

1. **Single-dataset dependence.** The only real data is SWaT (one testbed, a few days, 51 tags). Every learned result and every measured bound comes from it. Behaviour on another plant is unknown.
2. **SWaT has no HMAC, replay or network data.** The cyber rules cannot be evaluated on real traffic: they are tested with constructed scenarios, and the benchmark says so. 100 % on those scenarios is a regression check, not a detection rate.
3. **The cyber branch is rules-only.** The SWaT-trained cyber candidate was weak (test ROC-AUC 0.63, F1 0.14) and was dropped by decision; it could only see actuator state changes.
4. **The physical model is weak and advisory.** Held-out SWaT test block (see Benchmarks): the model ranks attacks (ROC-AUC about 0.82) but flags only about a quarter of attack windows at its operating point, detects 6 of 10 attack segments, and raises about 1.8 false-alarm
   episodes per hour against the 0.5 it was tuned for on validation (calendar drift: later days look different). It is advisory by design for this reason.
5. **The test block is not a pristine blind test.** A disclosed protocol revision after the first physical run means the test block informed the final protocol (run 1 vs run 2 reports).
6. **Constructed disagreement cases in the fusion set.** The fusion experiment's DROP class was built from deterministic cyber rules paired with real SWaT windows (SWaT cannot supply cyber failures), so only its PASS-versus-ALERT part is real-data evidence. The learned fusion lost to the physical model alone and is **not used**.
7. **Synthetic-extension attacks.** `flood`, `replay` and `impossible-command` (and every network-layer attack) are constructions: SWaT contains no such attacks. `freeze`, `ramp` and `cross-register` follow SWaT *behaviours*, but their
   parameter ranges are design defaults unless `docs/swat_attack_profile.json` has been generated (only the ramp range is then calibrated). Stealthy in-bounds attacks (`ramp`, `freeze`) are mostly **not** stopped by the rules.
8. **The twin is a demonstration plant, not SWaT.** MV503 is twin-only; physics is simplified; its false-alarm rate (about 0.25 per hour on the healthy twin in the benchmark) is a property of the twin, not of SWaT.
9. **No encryption, no TLS.** Commands are authenticated and integrity-protected, not confidential. Telemetry and the dashboard are unauthenticated plain HTTP/Modbus. Intended for a private demo network.
10. **A shared key means an insider can sign anything.** HMAC with one shared secret cannot separate SCADA from a compromised workstation holding the key; the other layers are the mitigation. The key is a file or an environment variable.
11. **The wire format is value x 10** (0.1 resolution, max 6553.5), so pH and permeate flow are coarse.
12. **The multi-laptop run is untested on real hardware.** Everything was rehearsed and the Wireshark filters and nonce correlation verified on one machine; firewall rules, interface names, Wi-Fi client isolation and the GUI menus were not tried.
13. **Latency numbers are in-process decision latency** on the machine named in the report (plus one loopback Modbus round trip), not network latency across laptops.
14. **Pickled model, pinned library.** The physical model loads only cleanly with scikit-learn 1.9.1 (enforced by a test); retraining must re-pin.
15. **Single-source assumptions.** The rate limit and replay tracking are per source address; the whitelist is by IP. Address spoofing on a hostile network is out of scope.

## Future work

* Run and document the four-laptop demo on real hardware; add Windows and macOS firewall automation.
* A cyber-side learned model **only** if a real labelled Modbus or industrial-protocol dataset can be justified (this project uses SWaT only); until then rules-only is the honest position.
* Drift-robust physical detection: retrain with later calendar blocks, online threshold recalibration, or a per-day normalisation; revisit the false-alarm budget.
* Per-actuator or per-stage physical models and explanations (which sensor drove the flag), shown in the Packet Tracer.
* Trace upstream (PLC to SCADA) decisions, and add a Packet Tracer view for the randomised attacker's runs.
* Per-source keys (or asymmetric signatures) so a compromised workstation cannot impersonate SCADA; TLS or a VPN for confidentiality; authentication on the dashboard.
* Dashboard buttons for `sensor-write` and the randomised attacks; export of a demo session (decisions, traces, capture) as one report.

## Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| Every command is `DROP` `UNTRUSTED_SOURCE` | the sender's address is not in `IM_TRUSTED_SOURCES` on the middleware (multi-laptop); restart the middleware after changing it |
| Every command is `DROP` `HMAC_INVALID` | different `IM_HMAC_SECRET` on SCADA and middleware (compare `check_topology` fingerprints), or one side has a stale `config/hmac_secret.key` |
| Every command is `DROP` `HMAC_EXPIRED` | clocks differ by more than 30 s: enable automatic time |
| `Failed to connect` / timeouts across laptops | firewall, wrong `IM_*_HOST`, or Wi-Fi client isolation (use a phone hotspot or a switch); run `check_topology` |
| Physical model shows `WARMING_UP` | normal for the first ~30 s after start; it needs a full 30 s window |
| `InconsistentVersionWarning` / model status `NO_MODEL` | scikit-learn is not the pinned version: `pip install scikit-learn==1.9.1` |
| Wireshark shows no Modbus | the Modbus/TCP port preference is not set to 5021/5020 (do not use Decode As) |
| Plant looks broken in the next run | an attack changed it; restart `python -m plc.plc` |
| Dashboard empty although the middleware works | the dashboard URL (`IM_DASHBOARD_URL`) on the middleware laptop, or the dashboard is not running; the middleware never blocks on it |
| `Address already in use` | a previous process is still running on 5020, 5021 or 5050 |
