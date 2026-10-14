# IndustrialMind: Complete Technical Description

**Purpose of this file.** A single, self-contained description of what the project is, how every component works, which algorithm each one uses, with which parameters, how it fails, and what was measured. It is written to be lifted into a presentation, a project report and an IEEE-style paper. It deliberately contains **no setup or run instructions** (those are in `README.md`).

**How to use it.**

| For this | Take these sections |
|---|---|
| Slides | 1 (summary), 3 (architecture), 7.3 / 7.4 / 7.5 / 7.7 (one slide each), 8 (results), 10 (limitations) |
| Project report | everything, in order |
| IEEE paper | Abstract <- 1; Introduction <- 2; System Design <- 3 to 6; Methodology <- 4, 7.5, 8.1; Implementation <- 7; Evaluation <- 8; Threats to Validity <- 10; References <- 14 |

**Rule for quoting numbers.** Every number in sections 8 and 9 comes from `benchmarks/latest.json`, `benchmarks/swat_accuracy.json`, `benchmarks/test_results.json` or a report under `docs/reports/`. Re-run `python -m benchmark.run_all` before quoting, and quote latency together with the machine it was measured on. Numbers on constructed scenarios and on the twin must **never** be presented as real-data performance (section 8 labels each result by the strength of its evidence).

---

## 1. Summary (ready to paste as an abstract)

IndustrialMind is an inline security middleware for industrial control systems. It sits between a SCADA operator and a programmable logic controller (PLC) and decides, for every Modbus command, whether to forward it (`PASS`), forward it with a warning (`ALERT`) or block it (`DROP`). Its design separates two kinds of checks. A **Cyber Agent** applies deterministic traffic and authentication rules: a source whitelist, function-code and register allow-lists, a per-source rate limit, HMAC-SHA256 message authentication with a freshness window, and replay detection by nonce and payload. A **Physical Agent** applies deterministic plant-safety rules (value bounds, rate-of-change limits derived from actuator slew rates, and eight cross-register safety rules over a projected plant state) plus one **advisory machine-learning model**: an Isolation Forest and a Random Forest regressor over 30-second telemetry windows, trained only on the SWaT water-treatment dataset. A rule-based **Orchestrator** fuses the verdicts. The plant is a five-stage digital twin calibrated to measured SWaT operating ranges. A per-command **Packet Tracer** exposes every hop's computed values, and Wireshark captures independently confirm that blocked frames are real traffic and never reach the PLC. On the held-out SWaT test block the advisory model reaches ROC-AUC 0.82 (precision 0.37, recall 0.26, 1.79 false-alarm episodes per hour, 6 of 10 attack segments detected); the rule layers pass 4,400 of 4,400 constructed violating commands with no false positives, and catch 83.7 % of constructed attack sessions, missing mainly slow in-bounds drift. Decision latency of the full pipeline is about 0.5 ms per command in-process. Negative results (a weak SWaT-trained cyber model and a learned fusion model that lost to the physical model alone) are reported rather than hidden.

---

## 2. Problem, contributions and threat model

### 2.1 Problem
Industrial control protocols such as Modbus/TCP have no authentication, no integrity protection and no notion of plant safety: any host that can reach the PLC can write any register. Two classes of attack follow. **Cyber-layer attacks** abuse the protocol (forged, replayed, flooded or unsigned commands). **Physical-layer attacks** send protocol-valid commands that drive the process into an unsafe state (for example, closing an inlet valve while the pump runs fast). A defence that handles only one class leaves the other open.

### 2.2 Contributions
1. A **two-layer, inline architecture** that checks both how a command arrived (cyber) and what it would do to the plant (physical), with a transparent, rule-based fusion.
2. A **plant-aware rule set**: rate limits derived from actuator slew rates, plus cross-register safety rules evaluated on a *projected* plant state so that individually harmless commands that form an unsafe combination are caught.
3. A **SWaT-trained advisory model** whose features are computed by a single shared implementation for training and live use (so offline and online scores are identical), with an honest, leakage-aware evaluation (calendar-block splits, per-segment analysis, thresholds from a false-alarm budget).
4. A **SWaT-calibrated digital twin** with inter-stage coupling, so the demonstration plant matches measured operating ranges.
5. **Verifiability tooling**: a hop-by-hop Packet Tracer, wire-level correlation with Wireshark by frame nonce, and one-command reproducible benchmarks whose numbers are generated into the documents.
6. **Reported negative results** and an explicit evidence hierarchy.

### 2.3 Threat model
| Actor | Capability | Modelled by | Stopped by |
|---|---|---|---|
| External attacker without the key | can reach the middleware port; cannot sign | `hmac-missing`, `hmac-forged`, `hmac-tamper`, untrusted source | source whitelist, HMAC |
| Man-in-the-middle | alters a captured frame in transit | `hmac-tamper` | HMAC (tag no longer matches) |
| Replay attacker | resends a captured valid frame, immediately or later | `replay`, `delayed-replay` | nonce store, payload-duplicate check, freshness window |
| Flooder | high-rate valid-looking traffic | `flood` | per-source rate limit |
| Compromised engineering workstation (insider holding the key) | can sign anything | `impossible-command`, `cross-register`, `freeze`, `ramp`, `flood`, `replay` | rate/replay checks and the whole Physical Agent |
| Attacker with direct network path to the PLC | bypasses the middleware | `false-injection` | **not preventable by the middleware**; only detected afterwards by the physical model and the sensor-envelope rule |

Out of scope: confidentiality (there is no encryption), address spoofing on a hostile network, compromise of the middleware host, and attacks that stay entirely inside normal operating behaviour.

---

## 3. System architecture

### 3.1 Data flow
```
SCADA operator ---signed FC16 frame, :5021---> MIDDLEWARE ---forward (FC6), :5020---> PLC (twin)
Attacker --------same port-------------------> [ Cyber Agent  ||  Physical Agent(+model) ] -> Orchestrator
                                                          ^ telemetry poll (every 0.2 s) from the PLC
                                               decisions + per-hop traces (HTTP) --> Dashboard :5050
```
1. SCADA (or an attacker) writes a command to the middleware as if the middleware were the PLC.
2. The middleware extracts the real TCP peer address, builds a command record and a plant-state snapshot, and runs the **cyber** and **physical** branches **concurrently**.
3. The **Orchestrator** fuses the verdicts into `PASS`, `ALERT` or `DROP`.
4. `PASS`/`ALERT`: the value is written to the PLC; the middleware later confirms the plant reached it. `DROP`: nothing reaches the PLC; the event is logged.
5. In parallel, the middleware polls the PLC every 0.2 s, mirrors its registers into the datastore that SCADA reads, feeds the physical model's window, and applies the sensor-envelope rule.
6. Decisions and traces go to the dashboard; Wireshark can observe the same frames independently.

### 3.2 Components
| Component | File(s) | Type | Role |
|---|---|---|---|
| SCADA simulator | `scada/scada.py` | client | issues one signed write every 2 s |
| Middleware server | `middleware/middleware_server.py` | Modbus TCP server and client | ingress, state, polling, forwarding |
| Cyber Agent | `middleware/cyber_agent.py` | **rules** | traffic and authentication checks |
| Physical Agent | `middleware/physical_agent.py` | **rules** | plant-safety checks |
| Physical model | `models/physical_model.py`, `swat/physical_features.py`, `models/tree_inference.py` | **ML (advisory)** | anomaly and attack scoring of telemetry windows |
| Cyber model | `models/cyber_model.py` | ML candidate, **not active** | negative result |
| Orchestrator | `middleware/orchestrator.py` | **rules** | verdict fusion |
| Pipeline | `pipeline/multi_model_pipeline.py` | glue | concurrent branches, failure policy, report |
| Packet Tracer | `middleware/trace.py` | instrumentation | hop-by-hop record |
| Dashboard | `dashboard/` | web UI | live tables, tracer panel |
| PLC and twin | `plc/plc.py`, `plc/twin.py` | simulator | five-stage plant over Modbus |
| Attacker | `attacker/` | client | fixed and randomised attacks |
| HMAC module | `docs/hmac_auth.py` | crypto | frame build/verify |
| Shared interfaces | `docs/interfaces.py`, `docs/netconfig.py` | config | registers, bounds, rules, addresses |
| Benchmarks | `benchmark/` | tooling | latency and accuracy, report generation |

### 3.3 Concurrency and failure policy
* The two branches run on a small thread pool, so decision latency is roughly the slower branch, not the sum.
* **Rule branch raises an exception:** the verdict **fails closed** (`DROP`, reason `AGENT_ERROR:...`).
* **Model raises or has no weights:** the model **abstains** (`NO_MODEL`, `WARMING_UP` or `ERROR`, `threat_flag = False`); the rules still decide. The model can therefore never take the system down and can never block traffic.
* **Dashboard unreachable:** decision forwarding uses a single background worker with a bounded queue (1000); when full, notifications are dropped, never the command.
* **Orchestrator failure:** fails closed.

### 3.4 Trust boundaries
Trusted: the middleware process, the shared secret holder (SCADA, middleware). Untrusted: everything arriving on port 5021, including the claimed content of every frame. The **source address is taken from the TCP connection**, never from the payload.

---

## 4. Dataset: SWaT

### 4.1 What it is and why it is the only dataset
SWaT (Secure Water Treatment testbed, iTrust, Singapore University of Technology and Design) is a real six-stage water-treatment testbed with sensor and actuator logs recorded at 1 Hz, including labelled physical attacks. It is the **only external dataset** this project uses. Anything SWaT cannot supply is either derived from SWaT columns and labels or **labelled synthetic or rule-tested** (section 10). No self-generated data is presented as real-data performance.

### 4.2 Archive structure (measured on the user's copy)
| Fact | Value |
|---|---|
| Files used | `normal.csv` (1,387,098 rows), `attack.csv` (54,621 attack-only rows) |
| Columns | 51 tags + `Timestamp` + `Normal/Attack` |
| Timestamp format | `%d/%m/%Y %I:%M:%S %p`, 1 Hz |
| Order | files are **not chronological** |
| Duplicates | `normal.csv` holds an exact duplicate copy of the normal period: 495,000 rows (0 conflicts) |
| After de-duplication | **946,719 rows** = 496,800 (normal period, 22-28 Dec 2015) + 449,919 (attack period) |
| Attack segments | **35** (maximal runs of attack rows inside one chunk) |
| Chunks | 2 (a chunk breaks at any gap longer than 5 s) |
| Not present | network fields, packet captures, an attack list |
| NaN columns | `MV101`, `AIT201`, `MV201`, `P201`, `P202`, `P204`, `MV303` are NaN for the whole normal period (present only in the attack period) |

### 4.3 Preprocessing (`swat/loader.py`)
1. Read the two CSVs, parse timestamps strictly, convert the label to boolean.
2. Sort chronologically; on identical timestamps the attack-labelled row sorts first.
3. De-duplicate identical timestamps (the loader records whether copies were exact or conflicting).
4. Cut the stream into **chunks** wherever consecutive rows are more than 5 s apart; **feature state is never carried across a chunk boundary**.
5. Number attack **segments** (runs of attack rows within one chunk).
6. Assign rows to **calendar blocks**; a segment goes wholly to the block of its first row, so a split never cuts an attack in two.

### 4.4 Splits and evaluation hazards
* **Blocks:** train 22-29 Dec 2015, validation 30-31 Dec, test 1-2 Jan 2016. Never random rows: SWaT sensors drift by day, and a random split leaks that drift.
* Segments per block: 17 / 8 / 10 (train / validation / test).
* **Dominating segment.** Segment 22 has 35,900 rows (about 10 hours) and holds 66 % of all attack rows (88 % of validation attack windows). Model selection therefore excludes any segment holding more than half of a block's attack windows.
* **Calendar drift.** The sensor-envelope rule's false-violation rate on normal rows rose from 0.04 % (train) to 0.13 % (validation) and 2.24 % (test). Later days look different, which counts against the model.
* **Visibility.** Only the twin's 18 SWaT-backed points are model inputs; attacks whose manipulated points are not among them are invisible by construction.

### 4.5 What SWaT supplies and what it cannot
Supplies: plant structure and tags, real operating ranges, normal behaviour, labelled physical attacks. **Cannot supply:** HMAC signatures, replay behaviour, source addresses, network traffic, run-to-failure degradation. Therefore the cyber rules cannot be evaluated on SWaT, and the old health-index / remaining-useful-life output was removed (never invented).

---

## 5. The digital twin (`plc/twin.py`, `plc/plc.py`)

### 5.1 Structure
Five stages with four points each: **20 Modbus holding registers**, unit id 1, addresses 0-19, wire value = engineering value x 10 (0.1 resolution, 16-bit unsigned, maximum 6553.5). **10 actuators** (writable) and **10 sensors** (read-only; a write is dropped).

| Reg | Tag | Stage | Kind | Range | Nominal | Max slew (per s) |
|---|---|---|---|---|---|---|
| 0 | MV101 | S1 raw water | actuator | 0-100 % | 55 | 10 |
| 1 | P101 | S1 | actuator | 0-100 % | 70 | 8 |
| 2 | LIT101 | S1 | sensor | 0-1200 mm | 526.1 | n/a |
| 3 | FIT101 | S1 | sensor | 0-3.5 m3/h | 2.39 | n/a |
| 4 | P203 | S2 dosing | actuator | 0-100 % | 60 | 8 |
| 5 | P205 | S2 | actuator | 0-100 % | 60 | 8 |
| 6 | AIT202 | S2 | sensor | 5-10 pH | 8.37 | n/a |
| 7 | FIT201 | S2 | sensor | 0-3.5 m3/h | 2.44 | n/a |
| 8 | MV302 | S3 ultrafiltration | actuator | 0-100 % | 98 | 10 |
| 9 | P302 | S3 | actuator | 0-100 % | 70 | 8 |
| 10 | LIT301 | S3 | sensor | 0-1200 mm | 918.4 | n/a |
| 11 | DPIT301 | S3 | sensor | 0-60 kPa | 19.8 | n/a |
| 12 | P402 | S4 dechlorination | actuator | 0-100 % | 70 | 8 |
| 13 | UV401 | S4 | actuator | 0-100 % | 70 | 10 |
| 14 | LIT401 | S4 | sensor | 0-1200 mm | 891.9 | n/a |
| 15 | AIT402 | S4 | sensor | 100-350 mV | 163.7 | n/a |
| 16 | P501 | S5 reverse osmosis | actuator | 0-100 % | 80 | 8 |
| 17 | MV503 | S5 | actuator | 0-100 % | 30 | 10 |
| 18 | PIT501 | S5 | sensor | 0-350 kPa | 252.0 | n/a |
| 19 | FIT501 | S5 | sensor | 0-2.5 m3/h | 1.72 | n/a |

`MV503` has no SWaT counterpart (twin-only, labelled synthetic). Sensor nominals are the **measured SWaT train-block normal medians**.

### 5.2 Physics (continuous time, stepped with dt)
* **Actuators** ramp toward their commanded target at their slew rate: `step = rate * dt`; they never jump.
* **Pump outflow** from a tank: `Q = capacity * speed * head(level) * min(1, level/100)` with `head(level) = 0.4 + 0.6 * level / 1200`: weakly head-dependent, starving when nearly empty.
* **First-order lags** `x <- x + (target - x) * (1 - exp(-dt/tau))` model transport and dosing delay (tau 1 to 4 s).
* **S1:** inlet flow `supply * MV101 * (1 - 0.5 * LIT101/1200)`; pump outflow is the S2 flow (FIT201); rejected flow returns to the raw tank.
* **S2:** dosing is flow-proportional; pH falls with acid dose over flow, chlorine rises with hypochlorite dose over flow; reaction time about 3 s.
* **S3:** MV302 splits the S2 flow between the UF tank and a return to the S1 tank. Membrane pressure `DPIT301` rises with flow and with a fouling state. Fouling grows with throughput; when `DPIT301` exceeds 1.12 x nominal an automatic **backwash** runs for 8 s, cutting UF output to 60 %.
* **S4:** the S4 tank fills from the S3 filtrate; the UV lamp removes chlorine (`chlorine4 = chlorine_in * (1 - 0.85 * UV)`); ORP follows chlorine (`ORP = ORP0 + 60 * chlorine`).
* **S5:** feed pressure is `pmax * P501 * starve * (1 - 0.5 * MV503)` where `starve = min(1, S4 outflow / starve_flow)`; permeate flow follows pressure above a base value.
* **Tank balances** are integrators clamped to the physical walls (0 to 1200 mm).
* Optional sensor noise: Gaussian, standard deviation 0.2 % of range. `IM_TWIN_TIME_SCALE` speeds the simulation up.

### 5.3 Calibration and verification
Every constant is **derived in `_calibrate()` from the nominal values** in `docs/interfaces.py`, so the twin sits at the measured SWaT operating point at nominal set-points. Two tests guard this:
* `tests/test_bounds_alignment.py` (34 checks): configuration and twin versus the measured bounds; over a simulated hour with noise, 0 of 3,600 samples leave the measured envelope; a 20-hour run with backwash keeps `DPIT301` inside the envelope.
* `tests/test_twin_propagation.py`: perturb stage 1 and assert stages 2 to 5 respond in order (about 1.4 s, 5 s, 25 s, 100 s).

---

## 6. Communication and security protocol

### 6.1 Modbus mapping
Modbus/TCP over ports 5021 (middleware) and 5020 (PLC). SCADA does not write machine registers directly: it writes one **signed command frame** to address 100 of the middleware with function code 16. The middleware writes the approved value to the PLC with function code 6 (write single register). Plain writes to machine registers are still routed through the pipeline so they are visibly rejected (`HMAC_MISSING`) and logged; writes to unmapped addresses give `INVALID_REGISTER`.

### 6.2 Signed command frame (27 registers)
| Words | 0 | 1 | 2 | 3-6 | 7-10 | 11-26 |
|---|---|---|---|---|---|---|
| Content | version (=1) | target register | raw value (value x 10) | 64-bit nonce | 64-bit timestamp (ms) | 32-byte HMAC-SHA256 tag |

### 6.3 Authentication algorithm (`docs/hmac_auth.py`)
* **Primitive:** HMAC with SHA-256 (RFC 2104, FIPS 180-4), 32-byte tag, shared secret of at least 32 characters (`IM_HMAC_SECRET`, a key file, or an auto-generated key file with mode 0600). The secret is never logged, printed, returned by an API or sent to the dashboard.
* **Canonical message:** `b"IM-CMD-v1|" + pack(">BHHQQ", version, register, raw_value, nonce, timestamp_ms)`. A domain-separation prefix and fixed-width big-endian binary give **exactly one encoding per command**, so there is no whitespace, ordering or number-format ambiguity.
* **Verification order (important):** (1) frame present? else `HMAC_MISSING`; (2) well-formed and version correct? else `HMAC_MALFORMED`; (3) recompute the MAC and compare in **constant time** (`hmac.compare_digest`), else `HMAC_INVALID`; (4) only then check freshness `|now - timestamp| <= 30 s`, else `HMAC_EXPIRED`. **The MAC is checked before the timestamp, so freshness decisions are made only on authenticated data.**
* **What it guarantees:** the frame was produced by a holder of the key and was not altered. **What it does not guarantee:** that the command is sensible, or confidentiality.

### 6.4 Source identity
`SourceTrackingRequestHandler` captures the peer address and port of the TCP connection per request. Nothing the client sends is used as its address.

---

## 7. Components in depth

### 7.1 SCADA operator simulator (`scada/scada.py`)
Simulates a human operator: every 2 s it issues one signed write to one of the ten actuators in rotation. Each actuator has an **operator profile** (a target, a step size and a current value); the next set-point moves from the current value toward the target by at most one step (a gradual ramp, never a jump). It reads the live plant (mirrored by the middleware) and, if something else moved an actuator more than two steps away from the operator's own set-point (another operator, an attack that got through, a reset), it continues **from the actual reading** instead of issuing a large jump back to a stale value. Commands are HMAC-signed frames. Command values are clamped to the register range before scaling.

### 7.2 Middleware server (`middleware/middleware_server.py`)
**Ingress.** An asyncio Modbus TCP server (pymodbus 3.6.9) with a source-tracking request handler. A custom datastore intercepts every write and routes it through `_process_write`: frame at address 100 -> parsed and verified; machine register writes -> unsigned (`HMAC_MISSING`); anything else -> `INVALID_REGISTER`.

**State.** The middleware keeps its own copy of the plant state (from polling), a table of **pending commands** (approved, awaiting confirmation) and, per register, the time it last **settled**. The Physical Agent's rate-of-change check measures time since that settle moment. The **projected set-points** used by the cross-register rules are the approved-but-still-ramping targets, otherwise live telemetry.

**Polling loop (every 0.2 s).** (1) read all 20 PLC registers; (2) update the state copy; (3) mirror the registers into the datastore SCADA reads; (4) once per second report telemetry to the dashboard; (5) feed the physical model's window and log a status line (`plant=NORMAL|ALERT|WARMING_UP window=n/30`); (6) apply the sensor-envelope rule; (7) for each pending command, if `|reported - commanded| < 0.05` the plant has **confirmed** it, a PLC-to-SCADA confirmation event is created, the command is removed and the register's settle time is recorded. A write that is dropped therefore never produces a confirmation.

**Downstream decision path.** Build the command record -> snapshot the state -> `pipeline.process_command` -> on `DROP` log to `logs/blocked_attacks.jsonl` and stop; otherwise register the pending command **before** forwarding, write to the PLC (FC6), and remove the pending entry if forwarding fails. The packet trace is completed with the real outcome and sent to the dashboard.

**Upstream path.** The sensor-envelope rule (7.4.4) runs on every poll; violations are rate-limited to one alert per sensor per 30 s and raised as `DROP`-labelled upstream events on the dashboard. The telemetry is still mirrored to SCADA (**detect-and-alert**, not block).

### 7.3 Cyber Agent: rules only (`middleware/cyber_agent.py`)
**Algorithm class:** deterministic rule evaluation; no training data. Checks run in a fixed order and the **first failure wins** (so a cheap check protects the expensive one).

| # | Check | Reason | Mechanism | Parameters |
|---|---|---|---|---|
| 1 | Source whitelist | `UNTRUSTED_SOURCE` | peer address tested against IPs/CIDRs (IPv4-mapped IPv6 normalised) | `IM_TRUSTED_SOURCES`, default loopback only |
| 2 | Function code | `INVALID_FUNCTION_CODE` | set membership | {3, 6, 16} |
| 3 | Register allow-list | `INVALID_REGISTER` | set membership | the 20 known registers |
| 4 | Rate limit | `RATE_LIMIT_EXCEEDED` | **sliding window**: per-source deque of timestamps; expire older than 1 s; reject if count > limit | 5 requests per 1 s per source (before the crypto: a cheap DoS guard) |
| 5 | HMAC | `HMAC_MISSING` / `_MALFORMED` / `_INVALID` / `_EXPIRED` | section 6.3 | skew 30 s |
| 6a | Nonce replay | `REPLAY_DETECTED: nonce reused` | global map nonce -> first-seen time with an **ordered expiry queue** (amortised O(1)); a nonce seen twice inside the retention window is rejected | retention 2 x 30 s + 5 s = 65 s |
| 6b | Payload replay | `REPLAY_DETECTED` | per-source deque of (function code, register, value); an identical payload within the window is rejected | 2 s |

**Memory safety.** State for sources that went quiet is swept every 10 s, so traffic from many distinct addresses cannot grow memory without bound.
**The verdict** carries the reason and `auth_status` (`HMAC_OK`, `HMAC_INVALID`, ...).
**No cyber ML model exists** (`NO_MODEL`); the cyber branch is rule-based by decision (7.6).

### 7.4 Physical Agent: rules (`middleware/physical_agent.py`)
**Algorithm class:** deterministic rules over the command and a plant-state snapshot.

#### 7.4.1 Command checks (first failure wins)
| Layer | Reason | Rule |
|---|---|---|
| 0 | `UNKNOWN_REGISTER`, `WRITE_TO_SENSOR_REGISTER` | only actuators can be commanded |
| 1 | `OUT_OF_BOUNDS` | `min <= value <= max` for the register |
| 2 | `RATE_OF_CHANGE_EXCEEDED` | `|value - current| > rate_per_sec * 1.10 * dt`, with `dt = max(command_time - time_register_last_settled, 0.05 s)`: the requested change must be physically achievable in the elapsed time (10 % headroom so marginal-but-legitimate commands are not dropped) |
| 3 | `CROSS_REGISTER_VIOLATION` | cross-register rules, 7.4.2 |

Rate limits (slew per second): 10 for the valves MV101, MV302, MV503 and the UV lamp; 8 for the pumps.

#### 7.4.2 Cross-register rules
Each rule is a pair of conditions on two actuators that is unsafe when **both** hold. They are evaluated on the **projected** state: the current approved set-points with the requested value substituted for the commanded register. This is what catches a low-and-slow attack in which every individual command is in bounds and within rate limits.

| Rule | Unsafe when | Physical meaning |
|---|---|---|
| RAW_PUMP_DRY_RUN | P101 >= 60 and MV101 <= 10 | pump runs hard while the inlet is nearly shut: tank drains |
| RAW_TANK_OVERFLOW | MV101 >= 80 and P101 <= 10 | inlet wide open, pump nearly stopped: tank overflows |
| ACID_OVERDOSE_LOW_FLOW | P203 >= 80 and P101 <= 20 | acid dosing at high rate on low flow: pH crash |
| UF_PUMP_DEADHEAD | P302 >= 60 and MV302 <= 10 | UF pump against a nearly closed valve |
| UF_TANK_OVERFLOW | MV302 >= 80 and P302 <= 10 | UF tank overflows |
| CHLORINE_BREAKTHROUGH | P205 >= 80 and UV401 <= 10 | heavy hypochlorite with the UV lamp nearly off |
| RO_PUMP_DEADHEAD | P501 >= 70 and MV503 <= 10 | RO pump against a nearly closed reject valve |
| RO_FEED_STARVATION | P501 >= 60 and P402 <= 10 | RO pump fast while its feed pump is nearly off |

Two state-dependent rules: `VALVE_CLOSING_LOW_LEVEL` (MV101 closes by at least 25 points while LIT101 is in the bottom 20 % of its range) and `RO_PRESSURE_OVERLOAD` (P501 above 90 % of range while PIT501 exceeds 90 % of its range).
**Recovery exemption:** a command that moves an *already-violating* state **toward safety** is allowed, so an operator can always recover the plant.

#### 7.4.3 Why rate-of-change and cross-register are separate
Rate-of-change stops physically impossible jumps; cross-register stops physically unsafe *combinations* reached by possible moves. A slow, in-bounds attack passes the first and is caught by the second only if it completes a listed combination.

#### 7.4.4 Upstream sensor-envelope rule
Every sensor reading must lie inside the envelope **measured on SWaT train-block normal data**: the 0.1st to 99.9th percentile, widened by 10 % of that span, clipped at 0 for never-negative sensors (`docs/swat_bounds.json`). This is a **rule**, validated on held-out blocks (7.5.8), **alert-only**.

| Sensor | Median | Envelope low | Envelope high |
|---|---|---|---|
| LIT101 | 526.1 | 55.2 | 885.3 |
| FIT101 | 2.491 | 0.0 | 2.954 |
| AIT202 | 8.372 | 8.196 | 9.026 |
| FIT201 | 2.443 | 0.0 | 2.730 |
| LIT301 | 918.4 | 48.6 | 1101.4 |
| DPIT301 | 19.82 | 0.0 | 22.88 |
| LIT401 | 891.9 | 45.4 | 1087.9 |
| AIT402 | 163.7 | 142.6 | 242.2 |
| PIT501 | 252.0 | 0.0 | 284.8 |
| FIT501 | 1.722 | 0.0 | 1.928 |

(Measured on 624,918 normal train-block rows.)

#### 7.4.5 Feedback check
`check_feedback` (reported versus commanded, tolerance 20 % of range) is implemented and unit-tested; the live loop uses the settle-tolerance confirmation (7.2) and the envelope rule.

### 7.5 Physical model: the only learned model in use (`models/physical_model.py`)
**Role:** an **advisory** plausibility check on plant telemetry. It can turn a pass into an `ALERT`; it can **never block**.

#### 7.5.1 Inputs
Exactly what the live twin provides: **10 sensors** (LIT101, FIT101, AIT202, FIT201, LIT301, DPIT301, LIT401, AIT402, PIT501, FIT501) and **8 actuators** (P101, P203, P205, MV302, P302, P402, UV401, P501, as on/off). Excluded on purpose: `MV101` (NaN for the whole SWaT normal period), `MV503` (twin-only), and 33 other SWaT columns the twin does not have (a model using them could not run live).

#### 7.5.2 Window management
A **30-sample sliding window at 1 Hz**. The live poll runs at 5 Hz and is **decimated** to 1 Hz (samples closer than 1 s are skipped, matching SWaT's rate). A gap longer than 5 s **restarts** the window (as chunk boundaries do in training). Until the window is full the model reports `WARMING_UP` and abstains. Actuator values are converted to on/off with a threshold of 50 %. Scoring is cached per window update.

#### 7.5.3 Features (87 per window; one shared implementation)
`window_features` is **the same function** used to build training windows and to score live windows (training builds windows from the SWaT stream; live builds one window from telemetry), so offline and online scores are identical (verified in `tests/test_swat_physical.py`).

| Group | Count | Definition (sensors are z-scored with train-normal mean and standard deviation) |
|---|---|---|
| Per sensor (x10): `last`, `mean`, `std`, `slope`, `range`, `delta` | 60 | final value; window mean; window standard deviation; least-squares slope; max minus min; last minus first |
| Per actuator (x8): `state`, `toggles`, `frac_on` | 24 | final on/off state; number of switches in the window; fraction of the window on |
| `flow_balance_101_201` | 1 | difference of window-mean z-scores of FIT101 and FIT201 (stage 1 to 2 continuity) |
| `sensors_outside_envelope`, `max_envelope_excess` | 2 | count of sensors outside the measured envelope, and the largest excess in standard deviations |

**Variants.** `full` uses all 87. **`drift_robust` (selected)** drops the absolute levels (`last`, `mean` of every sensor: 20 features) and keeps the 67 features that describe dynamics, actuators and envelope distance. Absolute levels carry SWaT's day-to-day drift (the leakage tell), so removing them is the main reason the model generalises to later days.

#### 7.5.4 Head 1: Isolation Forest (unsupervised, trained on normal windows only)
* **Algorithm:** Isolation Forest (Liu, Ting and Zhou, 2008): an ensemble of random trees that isolate samples by random feature splits; anomalies are isolated in fewer splits (shorter average path length).
* **Parameters:** 100 trees, `max_samples = 256` per tree, `contamination = "auto"`, `random_state = 42`.
* **Training data:** up to **60,000** randomly sampled train-block **normal** windows.
* **Score:** `anomaly_score = -score_samples(x)`; higher means more anomalous (on the healthy twin the median is about 0.53 and the 95th percentile about 0.55, against the threshold below).
* **Threshold:** the **99.5th percentile of train-normal scores** = **0.6108**.
* **What it detects:** departures from normal joint behaviour of the 67 features, with no knowledge of attacks.

#### 7.5.5 Head 2: Random Forest regressor on the 0/1 attack label (supervised)
* **Algorithm:** `RandomForestRegressor` fitted to the binary label (window inside a SWaT attack segment). The leaf mean is the fraction of attack windows in that leaf, so the average over trees is an **attack probability estimate** (a regression forest is used so that leaf means are probabilities and inference stays simple).
* **Parameters:** 150 trees, `max_depth = 6`, `min_samples_leaf = 10`, `max_features = sqrt`, `random_state = 42`.
* **Class imbalance:** **balanced sample weights** (`n / (2 * n_class)`), because attack windows are about 1 % of the training block (1,733 of 126,715 windows).
* **Selection:** the feature variant and the (depth, leaf) pair were chosen on the **validation block by average precision, excluding any dominating segment** (segment 22). Grid: depth in {6, 10} x leaf in {10, 40} x variant in {full, drift_robust}. Validation average precision: drift_robust 0.69 versus full 0.33 to 0.39.
* **Threshold:** set by a **false-alarm budget** on validation normal windows: the smallest threshold whose alarm episodes per normal hour stay within the budget (episodes are runs of flagged windows separated by more than 30 s). The shipped model uses the **0.5 episodes per hour** operating point: **classifier threshold 0.601** (the trainer's default 1.0 per hour budget gave 0.558; 0.601 was selected from the validation operating curve and recorded in the model metadata).

#### 7.5.6 Decision logic
`threat_flag = (anomaly_score > 0.6108) OR (attack_probability > 0.601)`. `flagged_by` lists which head fired. The report also carries `bounds_violations` (sensors outside the measured envelope) and `plant_state` = `ALERT` if flagged or any bounds violation, else `NORMAL`. Only `threat_flag` makes the orchestrator emit `ALERT`.

#### 7.5.7 Fast inference
scikit-learn adds 1 to 10 ms of fixed overhead per call, which dominates when scoring one command. `models/tree_inference.py` copies the fitted trees into padded NumPy arrays and walks all trees at once (the same leaves as scikit-learn, bit for bit, verified in tests), including the Isolation Forest path-length normalisation `c(n) = 2(ln(n-1) + gamma) - 2(n-1)/n`. A model assessment takes about 0.006 ms on a cache hit and about 1 ms when the window changed.

#### 7.5.8 Training protocol and the disclosed revision
* **Split:** by calendar block, never by random rows; bounds and normalisation from train-normal rows only.
* **Windows:** 189,333 in total (30 s, stride 5 s): train 126,715 (1,733 attack), validation 34,538 (8,126 attack), test 28,080 (1,061 attack).
* **Run 1** used a maximum-validation-F1 threshold and one feature set. It **overfit** (train ROC-AUC 1.0 versus test 0.66) and validation was 88 % one segment.
* **Run 2 (revised)** introduced the variant selection, the dominating-segment exclusion and the false-alarm-budget threshold. **Because this revision was made after seeing run 1, the test block is not a pristine blind hold-out**; this is disclosed in the report and everywhere results are quoted.
* **Candidates only:** training writes to `models/candidates/`; promotion into `models/weights/` needs explicit approval.

#### 7.5.9 Measured results (held-out test block)
See section 8.1 (confusion matrix and all scores) and `docs/reports/physical_training_report_swat_run2.md` (operating curve, per-segment table).

#### 7.5.10 Failure handling
Missing, stale (feature schema mismatch), corrupt or version-incompatible weights, a warming window, or any exception -> the model abstains (`NO_MODEL`, `WARMING_UP`, `ERROR`) and **never raises into the middleware**. The shipped weights are a pickle and require the pinned scikit-learn version (1.9.1), enforced by `tests/test_environment.py`.

### 7.6 Cyber model: a documented negative result (`models/cyber_model.py`, `swat/cyber_events.py`)
**There is no cyber ML model in the running system.** A candidate was built and measured; it was weak and was not promoted, and the user then decided to drop cyber ML.
* **Why it was hard:** SWaT has no network data, so a "command" can only be an **actuator state-change event** (on to off or closed to open). The candidate used **8 features**: `turns_on`, `stage`, `is_valve`, `log_dt_same_ms`, `log_dt_any_ms`, `events_1s`, `events_10s`, `same_reg_60s`; an Isolation Forest plus a supervised head; it abstained on any write that was not a flip.
* **Result:** 2,377 train events (79 attack), 609 validation (42), 680 test (30). Test ROC-AUC **0.63**, F1 **0.14** (Isolation Forest alone: precision 0.50, recall 0.033). Event labels are inherited from the attack window, so some flagged-attack events may simply be ordinary control reactions.
* **Conclusion:** the cyber layer is **rule-based by design**. Dropped for honest reasons, not hidden.

### 7.7 Orchestrator: rule-based fusion (`middleware/orchestrator.py`)

| Cyber rules | Physical rules | Physical model | Decision | Reason |
|---|---|---|---|---|
| fail | any | any | **DROP** | the cyber reason |
| pass | fail | any | **DROP** | the physical reason |
| pass | pass | flags an attack | **ALERT** (forwarded) | `PHYSICAL_MODEL:<heads that fired>` |
| pass | pass | quiet or warming up | **PASS** | `OK` |

On the upstream path only the physical side exists. The decision dictionary carries `tx_id`, `verdict`, `reason`, `latency_ms`, `direction` and a `fusion` block (the inputs the fusion saw and the branch that fired: `cyber_rules_failed`, `physical_rules_failed`, `rules_passed_physical_model_flagged`, `all_clear`). Decisions are forwarded to the dashboard by one bounded background worker.

**The learned-fusion experiment (rejected).** A cross-fitted gradient-boosted classifier (`HistGradientBoostingClassifier`) was trained to fuse cyber and physical outputs. Protocol: the scenario set pairs every **real SWaT window** (cyber assumed to pass; truth PASS/ALERT from the SWaT label) with **constructed** rows (a named cyber rule fails; truth DROP); labels are **ground truth, not functions of the observed flags** (otherwise a tree just memorises the truth table); train-block physical outputs are **out-of-fold** (4 folds: attack windows by segment, benign windows by hour) so the fusion never sees in-sample scores; dominant segment weight capped to the median segment's; hyper-parameters and the ALERT threshold chosen on validation with a false-alarm budget; test block used once. **Result:** validation ROC-AUC 0.93 but **test ROC-AUC 0.68, below the physical model alone (0.83)**, detecting 4 of 10 test segments versus 6 of 10. It was **not promoted**; the rule table above is the design. (`docs/reports/fusion_training_report_swat.md`.)

### 7.8 Pipeline (`pipeline/multi_model_pipeline.py`)
`process_command` submits the cyber and physical branches to a two-worker thread pool, waits for both, optionally applies the cyber-model enforcement (disabled; no model ships), calls the orchestrator and builds the **unified report**: decision, per-branch rule verdicts and model reports, timings, mode, and the packet trace. Telemetry is ingested with `ingest_telemetry` (which never raises). Failures follow the policy in 3.3.

### 7.9 Packet Tracer (`middleware/trace.py`)
For each downstream command it builds a **hop-by-hop record from the real verdicts, model reports and decision** (nothing is re-decided or simulated). Seven hops: (1) **arrival** (peer address and port, function code, register, value, raw value, signature state, **frame nonce as four 16-bit words**); (2) **cyber rules** (six checks, each `PASS`/`FAIL`/`NOT_RUN`, with values such as the rate-limit count); (3) cyber model (`NO_MODEL`); (4) **physical rules** (five checks with bounds, the rate limit and elapsed time, and the rules evaluated); (5) **physical model** (status, plant state, both scores, thresholds, which head fired, bounds violations); (6) **orchestrator** (inputs and the branch taken); (7) **outcome** (forwarded or dropped, and which log file recorded a drop). Because the agents stop at the first failure, the per-check list is reconstructed from the fixed check order: earlier checks `PASS`, the failing one `FAIL`, later ones `NOT_RUN`.
**Wire correlation.** The tx_id exists only inside the middleware and is not on the wire; the **nonce** is. The tracer shows the same four nonce words that Wireshark shows in the FC16 frame, which is how a packet is matched to a dashboard entry (`tools/wire_correlate.py` automates it).

### 7.10 Dashboard (`dashboard/app.py`, Flask)
KPIs (total, pass, drop), two security tables (**SCADA to PLC** decisions and **PLC to SCADA** confirmations), live telemetry for all 20 points with a process schematic, CPU history, a **Blocked sources** section (reads the blocked-attack log, grouped by source with attack-type counts), an **Attacks** panel, and the **Packet Tracer**. Endpoints: `/api/security-event`, `/api/telemetry`, `/api/dashboard`, `/api/blocked-ips`, `/api/blocked-ips/<ip>`, `/api/trigger-attack`, `/api/reset`, `/api/trace` (POST), `/api/traces`, `/api/trace/<id>`. Event tables keep the latest 100 events; the tracer keeps the latest 300. Transaction ids are shortened for display (`TX-001`) with a stable mapping.

### 7.11 Attack log (`docs/attack_log.py`)
Every `DROP` appends one JSON line to `logs/blocked_attacks.jsonl`: time, direction, source address and port, tx id, function code, register and name, requested and current value, signature state (`present`, `absent`, `malformed`), HMAC status, both verdicts with reasons, orchestrator decision, latency, and a model summary (plant state, scores). The attack **type is derived from the agents' reason codes**, never from anything the sender claims. The HMAC key and tag are never written.

### 7.12 Attacker (`attacker/attacker.py`, `attacker/scenarios.py`)
A real Modbus client. **Fixed scripted attacks** are identical every run for demo reliability (demo set: `flood`, `impossible-command`, `cross-register`; others: `sensor-write`, `replay`, `false-injection`, `hmac-missing`, `hmac-tamper`, `hmac-forged`, `delayed-replay`).
**Randomised attacks** are generated as **plans** (lists of timed steps) from a seeded NumPy generator, so each run varies and any run is reproducible from its seed. Each plan is labelled `swat-derived` or `synthetic-extension`.

| Type | Origin | What is randomised and how |
|---|---|---|
| `freeze` | SWaT behaviour | target actuator; a wrong-but-valid held value (50 % far below nominal, 50 % far above); 3-8 repeats; interval 0.4-3.0 s (+/-30 % jitter) |
| `ramp` | SWaT behaviour | target; direction (kept inside the range); how far (15-60 % of range); step 1-12 % of range; interval 0.5-3.0 s |
| `cross-register` | SWaT behaviour | one of the 8 rules; which half is set first; goal values just past each threshold; step 4-15 %; interval 0.5-3.0 s |
| `impossible-command` | synthetic | target; 1-3 writes; value 1.1-10 x the register maximum; gaps 0.3-2.0 s |
| `flood` | synthetic | target; 8-40 writes; pace 0.01-0.15 s (always above the 5 per second limit) |
| `replay` | synthetic | target; value near current; capture one signed frame; 1-5 replays with delays 0.05-1.5 s |

"SWaT behaviour" means the pattern (a forced or held actuator, a slow drift, a physically inconsistent combination) is seen in SWaT's labelled attack windows. `tools/swat_attack_profile.py` (run on the archive, aggregate output) classifies each labelled segment's sensors as **freeze** (constant for at least 30 s while normally varying), **ramp** (linear fit R^2 at least 0.9 and a change of at least 2 standard deviations) or **shift** (mean more than 3 standard deviations from normal), and can calibrate **only the ramp-range**; all other ranges are stated design defaults, and each plan prints which it used. **SWaT has no network-layer attacks**, so flood, replay and impossible-command are synthetic extensions.

---

## 8. Evaluation and results

Every result is labelled by the strength of its evidence. **Do not pool them.**

### 8.1 Real data: held-out SWaT test block (physical model, advisory)
Test block 1-2 Jan 2016: 28,075 windows (stride 5 s): 1,060 attack, 27,015 benign (37.5 benign hours). Operating point: Isolation Forest threshold 0.6108, classifier threshold 0.601, variant `drift_robust`. Measured on the user's machine from the promoted weights. **Protocol note:** the test block was also seen in the revised training protocol (7.5.8), so these are held-out numbers, not a blind test.

**Confusion matrix of the advisory flag** (rows = truth, columns = prediction):

| | predicted PASS (no flag) | predicted ALERT (flag) |
|---|---|---|
| benign | **26,532** (TN) | **483** (FP) |
| attack | **781** (FN) | **279** (TP) |

| Decision rule | Precision | Recall | F1 | False-positive rate | Accuracy | Balanced accuracy | Alarm episodes per benign hour |
|---|---|---|---|---|---|---|---|
| Advisory model flag (drives `ALERT`) | 0.366 | 0.263 | 0.306 | 0.018 | 0.955 | 0.623 | 1.786 |
| Envelope rule alone (alert-only) | 0.273 | 0.216 | 0.241 | 0.022 | 0.949 | 0.597 | 0.853 |
| Model flag or envelope | 0.274 | 0.271 | 0.272 | 0.028 | 0.945 | 0.621 | 1.999 |

* **ROC-AUC (attack probability) 0.8245**; ROC-AUC (Isolation Forest score) 0.634; average precision 0.312.
* **Attack segments detected: 6 of 10**; median detection latency about 50 s after the segment starts.
* **Plain accuracy is not the headline.** Attacks are 3.8 % of windows, so a system that never flags anything scores accuracy **0.962** (balanced accuracy 0.5). Judge by recall, precision, false-alarm rate and AUC.
* Excluding the largest test segment (segment 35, 32 % of attack windows): precision 0.366, recall 0.386, F1 0.376.
* **Operating curve** (test block; threshold set on validation): at 0.25 per hour, recall 0.26 and 1.52 false-alarm episodes per hour; at 2 per hour, recall 0.50 and 3.36 per hour; at 4 per hour, recall 0.53 and 4.58 per hour. The validation budget is not reproduced on test (calendar drift).
* **Honest reading:** the model **ranks** attacks reasonably (AUC 0.82), but at its conservative operating point it flags about a quarter of attack windows and produces more false alarms than its target. It is advisory for this reason.
* Other model results (run 2, test): classifier alone precision 0.267, recall 0.260, F1 0.264, ROC-AUC 0.826; Isolation Forest alone precision 0.107, recall 0.012, ROC-AUC 0.633 (mostly useful as a drift-independent second opinion); "flag everything" baseline precision 0.038, recall 1.0, F1 0.073.

### 8.2 Constructed scenarios: the rule layers (not SWaT, not a learned model)
23 case types x 200 randomised scenarios per case on a virtual clock; a scenario counts as detected only when the real pipeline returns `DROP` **with the expected reason**.

**Command level** (violating versus legitimate; flagged = `DROP` or `ALERT`):

| | Predicted PASS | Predicted ALERT | Predicted DROP |
|---|---|---|---|
| legitimate (200) | **200** | 0 | 0 |
| violating (4,400) | 0 | 0 | **4,400** |

Accuracy 1.000, precision 1.000, recall 1.000, F1 1.000, false-positive rate 0.000. Per layer (cyber 1,800 and physical 2,600 violating scenarios, each against the 200 legitimate): all 1.000. Every individual case (untrusted source, bad function code, unknown register, rate burst, missing HMAC, tampered HMAC, wrong-key HMAC, expired or future-dated HMAC, replay; sensor write, out-of-bounds, rate of change, the two stage rules and all eight cross-register rules) scores 200/200.
**Interpretation:** the rules are deterministic, so 100 % is **expected**: this is a **regression check that each rule fires on what it was written for**, not evidence about unknown attackers. A negative-control test shows the checker can fail (the first full run flagged one scenario whose "tamper" had left the value unchanged: a builder bug, now fixed).

**Session level** (randomised attacker plans versus legitimate operator sessions, through the rule layers; the physical model is cold here):

| | no flag | flagged |
|---|---|---|
| benign session (100) | **100** | 0 |
| attack session (600) | **98** | **502** |

Accuracy 0.860, precision 1.000, recall **0.837**, F1 0.911, false-positive rate 0. Per type (runs with at least one drop, 100 each): impossible-command 100, flood 100, replay 100, cross-register 100, **freeze 80, ramp 22**. **The rules stop network-layer and unsafe-combination attacks but largely miss slow, in-bounds drift (ramp) and partially miss frozen values** (a re-sent identical payload within 2 s is caught only by the duplicate-payload check). This is the gap the advisory model is for, and the honest weak spot of the rule layers.

### 8.3 Digital twin measurements (synthetic plant, not SWaT)
4 simulated hours of nominal operation with sensor noise: the learned model raised **0.25 alarm episodes per hour** on the healthy twin; the envelope rule raised 0. Synthetic actuator attacks (10 minutes to settle, then the change, 15 minutes observed): first model flag after 3 s (raw pump stops), 2 s (acid overdose), 3 s (chlorine breakthrough), 1 s (RO dead-head), 4 s (UF valve shut); first envelope violation after 4, 2, 8, 1 and 17 s. **These describe the demonstration plant only and say nothing about SWaT detection performance.**

### 8.4 Latency (in-process decision latency; not network latency)
Real pipeline, 3,000 commands x 3 repeats after 300 warm-up, seed 7; workload 70 % legitimate and 30 % attacks (tamper, unsigned, replay, out-of-bounds, untrusted source, cross-register); a telemetry sample fed about once per virtual second so model refreshes are included. Measured on a 2-CPU Linux container, Python 3.13.

| Hop | mean (ms) | p50 | p95 | p99 |
|---|---|---|---|---|
| Cyber Agent rules | 0.041 | 0.039 | 0.071 | 0.092 |
| Cyber model (NO_MODEL stub) | 0.009 | 0.008 | 0.014 | 0.035 |
| Physical Agent rules | 0.027 | 0.026 | 0.042 | 0.061 |
| Physical model assess (includes window refresh) | 0.221 | 0.006 | 0.921 | 1.106 |
| Orchestrator | 0.011 | 0.009 | 0.023 | 0.036 |
| Packet-trace build | 0.044 | 0.038 | 0.075 | 0.108 |
| Both branches (concurrent) | 0.446 | n/a | 1.175 | 1.380 |
| **Total per command** | **0.518** | n/a | **1.266** | **1.488** |

Live Modbus round trip of a signed write to a running middleware (300 writes, includes sockets): mean **4.17 ms**, p95 4.76 ms, p99 13.2 ms. The hops overlap (two threads), so they do not sum to the total.

### 8.5 Component-level evidence not in the tables above
Physical model train / validation / test ROC-AUC 0.907 / 0.901 / 0.826 (the drop to test is calendar drift). Envelope rule on held-out normal rows: false violations 0.04 % (train), 0.13 % (validation); attack-row recall 30 % (train), 83 % (validation), 22 % (test, where 2.24 % of normal rows are also outside the envelope: 0.85 false-alarm episodes per hour). Cyber candidate: test ROC-AUC 0.63. Learned fusion: validation 0.93, test 0.68.

---

## 9. Verification and testing

* **20 test scripts, 280 individual checks, all passing** (`benchmarks/test_results.json`; regenerate with `python -m tests.run_all`, add `--with-stress --with-plc` for the two that need extras). They cover: every cyber rule, every physical rule (16 groups), the orchestrator's four branches, the concurrent pipeline (24 checks), the Packet Tracer (28 checks: trace values match the backend), twin calibration (34) and propagation, attacker randomisation (31: payloads differ, targets vary, synthetic extensions are caught), wire correlation (9), per-laptop preflight (9), benchmarks and README-equals-JSON (23), environment pin and clean model load (4), and SWaT code paths on a **synthetic SWaT-shaped fixture** (code paths only, never real metrics).
* **Shared feature code:** a test asserts that live scores equal training scores.
* **Quoted numbers come from the data:** `tests/test_benchmark.py` fails if the README or the report drifts from `benchmarks/latest.json`.
* **End-to-end evidence:** a full single-machine run of every fixed attack produced the expected reason for each; the cross-register attack on a clean plant was stopped at the inlet-valve step ("unsafe state prevented"); after `false-injection` (which bypasses the middleware) the plant drifted (raw tank level 526 mm to about 118 mm within two minutes) and every later command was forwarded with an `ALERT`.
* **Independent wire proof:** with tshark on loopback the frame nonce words matched the dashboard trace for both a normal and a tampered command; the tampered frame was visible on the middleware leg and produced no write on the PLC leg.
* **Fresh-reader test:** an independent agent followed the README literally and verified each promise it tested.

---

## 10. Limitations and threats to validity

1. **Single dataset.** SWaT is one testbed over a few days; every learned result and measured bound comes from it. Generalisation to other plants is unknown.
2. **No network ground truth.** SWaT has no HMAC, replay or traffic data; the cyber rules are evaluated only on constructed scenarios.
3. **The physical model is weak at its operating point** (recall 0.26, precision 0.37, 1.79 false-alarm episodes per hour versus a 0.5 target) because of calendar drift; it is advisory by design.
4. **The test block is not pristine** (revised protocol disclosed in 7.5.8).
5. **Constructed disagreement cases.** The fusion set's `DROP` class was built from deterministic rules paired with real windows; only its PASS-versus-ALERT part is real-data evidence. The learned fusion lost and is not used.
6. **Synthetic-extension attacks.** Flood, replay and impossible-command are constructions; the SWaT-derived types' parameter ranges are design defaults unless the attack-profile tool has been run (then only the ramp range is calibrated). Stealthy in-bounds attacks (ramp, freeze) are mostly not stopped by the rules.
7. **The twin is a demonstration plant,** not a SWaT replica (MV503 is synthetic; simplified physics; its false-alarm rate is a property of the twin).
8. **No encryption or TLS.** Integrity and authenticity only; telemetry and the dashboard are unauthenticated.
9. **Shared-key insider.** A holder of the key can sign anything; the other layers are the mitigation.
10. **Bypass.** An attacker with a direct path to the PLC defeats the middleware; only detection (model, envelope) remains.
11. **Wire resolution** is 0.1 (value x 10, maximum 6553.5): pH and permeate flow are coarse.
12. **Multi-laptop operation was not tested on real hardware** (single-machine rehearsal only); latency is in-process decision latency.
13. **Pickled model.** The weights require the pinned scikit-learn version.
14. **Per-source assumptions.** Rate and replay tracking are per source address; address spoofing on a hostile network is out of scope.

---

## 11. Design decisions and rationale (for questions and viva)

| Decision | Why |
|---|---|
| Two independent branches, rules as the hard gate, ML advisory | rules are explainable and testable; ML can have false alarms and must never block legitimate traffic; abstention keeps the system safe if the model fails |
| HMAC-SHA256 with nonce, timestamp, constant-time compare | standard, fast, message integrity and authenticity; the nonce defeats replay, the timestamp bounds the replay window; the MAC is checked before the timestamp so freshness is judged only on authenticated data |
| Rate limit before the crypto | cheap denial-of-service guard: do not spend HMAC work on a flood |
| Cross-register rules on the projected state | catches combinations of individually harmless commands; the recovery exemption keeps the plant operable |
| Rate-of-change from actuator slew rates | derives a physical limit instead of a guess; 10 % headroom avoids false drops |
| Isolation Forest plus a supervised forest | the unsupervised head needs no attack labels and is robust to unseen attacks; the supervised head ranks known attack patterns; they are complementary (the supervised head carries the AUC, the Isolation Forest is a drift-independent second opinion) |
| Window features, one shared implementation | identical scores offline and live; no train/serve skew |
| `drift_robust` features | absolute levels carry SWaT's day-to-day drift; dropping them improved validation average precision from about 0.35 to 0.69 and test ROC-AUC from 0.53 to 0.83 |
| Calendar-block splits and per-segment evaluation | random splits leak drift; one 10-hour segment dominates; per-segment reporting is the honest unit |
| Threshold by false-alarm budget | operators care about alarms per hour, not F1 on a skewed set |
| Regression forest for probabilities | leaf means are probabilities; simple to pack for fast inference |
| Packed tree inference | decision latency is dominated by library overhead otherwise |
| Rule-based orchestrator | a learned fusion was tried and lost to the physical model alone; a transparent four-branch table is also auditable |
| No cyber ML | the only SWaT-derived candidate scored ROC-AUC 0.63; SWaT has no traffic; no other dataset is used |
| Fail closed for rules, abstain for models | an unknown rule failure must not let traffic through; a model failure must not stop legitimate traffic |
| Twin calibrated to SWaT medians | the demo plant sits at a measured operating point |
| Generated benchmark numbers | what the paper and slides quote is exactly what the code measured |

---

## 12. Glossary
**SCADA** supervisory control and data acquisition. **PLC** programmable logic controller. **Modbus/TCP** industrial protocol over TCP. **FC6 / FC16** Modbus function codes: write single register / write multiple registers. **HMAC** hash-based message authentication code. **Nonce** number used once. **Replay** resending a captured valid message. **Slew rate** maximum rate at which an actuator can change. **Cross-register rule** safety rule over two actuators. **Isolation Forest** unsupervised anomaly detector based on random partitioning. **Random Forest** ensemble of decision trees. **ROC-AUC** area under the receiver operating characteristic curve (ranking quality). **Average precision** area under the precision-recall curve. **False-alarm episode** a run of consecutive flags separated from the next by more than 30 s. **Segment** a maximal run of attack rows in SWaT. **Block** a calendar split (train, validation, test). **Advisory** can warn but never block. **Fail closed** deny when a check cannot be completed. **Abstain** return no opinion. **Calendar drift** change of the process statistics from day to day.

---

## 13. Figures and tables available for reuse
Under `docs/reports/figures/` (generated from `benchmarks/latest.json`): `middleware_confusion_matrices.png` (three-level confusion matrices), `swat_confusion_matrix.png`, `latency_per_hop.png`, `rule_checks.png`, `attacker_plans.png`, `twin_detection_latency.png`. Full tables: `docs/reports/benchmark_report.md`. Training reports: `docs/reports/physical_training_report_swat_run1.md`, `..._run2.md`, `cyber_training_report_swat.md`, `fusion_training_report_swat.md`, `twin_domain_gap_report.md`. Suggested diagrams to draw for slides and the paper: the data-flow diagram (3.1), the signed-frame layout (6.2), the decision table (7.7), the physical-model pipeline (window -> 87 features -> 67 selected -> two heads -> thresholds -> `threat_flag`), and the evidence hierarchy of section 8.

## 14. References (verify every entry before submission)
1. J. Goh, S. Adepu, K. N. Junejo and A. Mathur, "A Dataset to Support Research in the Design of Secure Water Treatment Systems," in *Critical Information Infrastructures Security (CRITIS)*, 2016. (SWaT dataset; iTrust, Singapore University of Technology and Design.)
2. F. T. Liu, K. M. Ting and Z.-H. Zhou, "Isolation Forest," in *Proc. IEEE International Conference on Data Mining (ICDM)*, 2008.
3. L. Breiman, "Random Forests," *Machine Learning*, vol. 45, no. 1, pp. 5-32, 2001.
4. H. Krawczyk, M. Bellare and R. Canetti, "HMAC: Keyed-Hashing for Message Authentication," RFC 2104, 1997.
5. National Institute of Standards and Technology, "Secure Hash Standard (SHS)," FIPS PUB 180-4, 2015.
6. Modbus Organization, "MODBUS Application Protocol Specification V1.1b3" and "MODBUS Messaging on TCP/IP Implementation Guide," 2012.
7. F. Pedregosa et al., "Scikit-learn: Machine Learning in Python," *Journal of Machine Learning Research*, vol. 12, pp. 2825-2830, 2011.
8. National Institute of Standards and Technology, "Guide to Industrial Control Systems (ICS) Security," NIST SP 800-82 (current revision).

## 15. Appendix: where each fact lives in the repository
| Topic | File |
|---|---|
| Registers, bounds, slew rates, cross-register rules, message shapes | `docs/interfaces.py`, `docs/register_map.md` |
| Addresses and environment variables | `docs/netconfig.py` |
| HMAC frame and verification | `docs/hmac_auth.py` |
| Measured SWaT bounds | `docs/swat_bounds.json` |
| Cyber rules | `middleware/cyber_agent.py` |
| Physical rules and envelope | `middleware/physical_agent.py` |
| Fusion | `middleware/orchestrator.py` |
| Server, polling, state | `middleware/middleware_server.py` |
| Tracer | `middleware/trace.py` |
| Pipeline | `pipeline/multi_model_pipeline.py` |
| Physical model, features, fast inference | `models/physical_model.py`, `swat/physical_features.py`, `models/tree_inference.py` |
| SWaT loader | `swat/loader.py` |
| Training | `models/train_physical_swat.py` (also `train_cyber_swat.py`, `train_fusion_swat.py` for the negative results) |
| Twin | `plc/twin.py`, `plc/plc.py` |
| Attacker | `attacker/attacker.py`, `attacker/scenarios.py`, `tools/swat_attack_profile.py` |
| Benchmarks and generated report | `benchmark/`, `benchmarks/latest.json`, `docs/reports/benchmark_report.md` |
| Test records | `tests/`, `benchmarks/test_results.json` |
