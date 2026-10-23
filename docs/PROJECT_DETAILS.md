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

IndustrialMind is an inline security middleware for industrial control systems. It sits between a SCADA operator and a programmable logic controller (PLC) and decides, for every Modbus command, whether to forward it (`PASS`), forward it with a warning (`ALERT`) or block it (`DROP`). Its design separates two kinds of checks. A **Cyber Agent** applies deterministic traffic and authentication rules: a source whitelist, function-code and register allow-lists, a per-source rate limit, HMAC-SHA256 message authentication with a freshness window, and replay detection by nonce and payload. A **Physical Agent** applies deterministic plant-safety rules (value bounds, rate-of-change limits derived from actuator slew rates, and eight cross-register safety rules over a projected plant state) plus one **advisory machine-learning model** (physical model v2): a gradient-boosted classifier over 117 features of a 120-second telemetry window, trained only on the SWaT water-treatment dataset. A rule-based **Orchestrator** fuses the verdicts. The plant is a five-stage digital twin calibrated to measured SWaT operating ranges. A per-command **Packet Tracer** exposes every hop's computed values, and Wireshark captures independently confirm that blocked frames are real traffic and never reach the PLC. On the held-out SWaT test block the advisory model reaches ROC-AUC 0.836 (precision 0.461, recall 0.513, F1 0.485, 1.17 false-alarm episodes per hour, 8 of 10 attack segments detected); the rule layers pass 4,400 of 4,400 constructed violating commands with no false positives, and catch 83.7 % of constructed attack sessions, missing mainly slow in-bounds drift. Decision latency of the full pipeline is 0.50 ms median (0.80 ms mean, 2.8 ms p99) per command in-process. Negative results (a weak SWaT-trained cyber model and a learned fusion model that lost to the physical model alone) are reported rather than hidden.

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
| Physical model (live: v2; v1 kept as fallback) | `models/physical_model_v2.py`, `swat/features_v2.py`, `swat/physical_features.py`, `models/tree_inference.py` (v1: `models/physical_model.py`) | **ML (advisory)** | attack probability of 120 s telemetry windows |
| Cyber model | `models/cyber_model.py` | ML candidate, **not active** | negative result |
| Orchestrator | `middleware/orchestrator.py` | **rules** | verdict fusion |
| Pipeline | `pipeline/multi_model_pipeline.py` | glue | concurrent branches, failure policy, report |
| Packet Tracer | `middleware/trace.py` | instrumentation | hop-by-hop record |
| Dashboard | `dashboard/` | web UI | live tables, tracer panel |
| PLC and twin | `plc/plc.py`, `plc/twin.py` | simulator | five-stage plant over Modbus |
| Attacker | `attacker/` | client | fixed and randomised attacks |
| HMAC module | `core/hmac_auth.py` | crypto | frame build/verify |
| Shared interfaces | `core/interfaces.py`, `core/netconfig.py` | config | registers, bounds, rules, addresses |
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
Every constant is **derived in `_calibrate()` from the nominal values** in `core/interfaces.py`, so the twin sits at the measured SWaT operating point at nominal set-points. Two tests guard this:
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

### 6.3 Authentication algorithm (`core/hmac_auth.py`)
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

### 7.5 Physical model: the only learned model in use
**The live model is v2 (section 7.5.11).** Sections 7.5.1 to 7.5.10 describe the v1 model (`models/physical_model.py`), which shares the window, decimation and failure-handling machinery with v2, remains in the repository and is selectable with `IM_PHYSICAL_MODEL=v1`, and is the fallback if the v2 weights cannot be loaded.

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

#### 7.5.11 Promoted model v2 (`models/physical_model_v2.py`, `swat/features_v2.py`, `models/train_physical_v2.py`)
* **What changed versus v1:** (1) it is fitted on train **and** validation windows; (2) a **120 s** history (1 Hz) replaces the 30 s window; (3) two feature groups are added to the 67 drift-robust v1 statistics (computed over the last 30 s): **long-context features** over the full 120 s (per sensor: slope, standard deviation, net change; per actuator: number of toggles) and **cross-sensor consistency residuals**; (4) the two heads are replaced by **one gradient-boosted classifier** (`HistGradientBoostingClassifier`), so there is no Isolation Forest and `anomaly_score` is `None`; (5) the model and threshold are chosen by **segment-grouped 5-fold cross-validation** with segment-balanced average precision, so that one long attack segment cannot dominate the choice.
* **Residual features:** for each sensor a ridge regression (alpha 10) predicts its 30 s trend (z-scored slope) from the other sensors' window means and the actuators' on-fractions. It is fitted on **normal windows only**; at run time the standardised prediction error of every sensor (plus the maximum and mean absolute error) is a feature. A physical relationship that breaks (a level that does not follow the flows) makes the residual grow. 117 features in total.
* **Decision:** `threat_flag = attack_probability > 0.7880`. The threshold is the out-of-fold development threshold for a false-alarm budget of **0.5 episodes per benign hour**. A "k of the last m windows" persistence rule was evaluated and made F1 worse on the held-out block (0.416 against 0.485), so it is not used.
* **Live inference:** the same feature functions the trainer calls build the 117 features from the live window (checked to 1e-9 against training in `tests/test_physical_v2_live.py`); `PackedHistGB` evaluates all 150 trees with numpy (identical to scikit-learn to 1e-15, about 0.05 ms against 1.6 ms), so one assessment costs about 0.6 ms including the features. Warm-up is 120 s. Failure handling is as in 7.5.10 (abstain, never raise).
* **Why the twin must be noisy:** SWaT sensors are noisy; a perfectly flat, noiseless plant is out-of-distribution (constant standard deviations of zero) and made the model sit at p = 0.84 in ALERT. The PLC therefore runs the twin with sensor noise by default (`IM_TWIN_NOISE=0` turns it off); with noise the healthy twin shows `NORMAL`, probability about 0.03.
* **Measured results (held-out test block, 0.5 budget):** section 8.1b.

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
KPIs (total, pass, drop), two security tables (**SCADA to PLC** decisions and **PLC to SCADA** confirmations), live telemetry for all 20 points with a process schematic, CPU history, a **Blocked sources** section (reads the blocked-attack log, grouped by source with attack-type counts), the **Live Network Flow** panel (each command drawn from its real TCP source host through the three middleware layers to the PLC, or stopped at the layer that dropped it; built from the same traces as the tracer; host names from `IM_HOST_LABELS`), and the **Packet Tracer**. The dashboard has no attack controls: attacks come only from the attacker system. Endpoints: `/api/security-event`, `/api/telemetry`, `/api/dashboard`, `/api/blocked-ips`, `/api/blocked-ips/<ip>`, `/api/flow`, `/api/reset`, `/api/trace` (POST), `/api/traces`, `/api/trace/<id>`. Event tables keep the latest 100 events; the tracer keeps the latest 300. Transaction ids are shortened for display (`TX-001`) with a stable mapping.

### 7.11 Attack log (`core/attack_log.py`)
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

### 8.1 Real data: held-out SWaT test block (physical model v1, advisory; superseded by v2, section 8.1b)
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
* **Honest reading (v1):** the model **ranks** attacks reasonably (AUC 0.82), but at its conservative operating point it flags about a quarter of attack windows and produces more false alarms than its target. It is advisory for this reason.
* Other model results (run 2, test): classifier alone precision 0.267, recall 0.260, F1 0.264, ROC-AUC 0.826; Isolation Forest alone precision 0.107, recall 0.012, ROC-AUC 0.633 (mostly useful as a drift-independent second opinion); "flag everything" baseline precision 0.038, recall 1.0, F1 0.073.

### 8.1b Real data: the promoted v2 model on the same held-out block
Test block 1-2 Jan 2016: 28,080 windows (each with a full 120 s history), 1,061 attack, 37.53 benign hours. Source: `docs/reports/physical_training_report_v2_swat.md` (the user's local SWaT run of `models/train_physical_v2.py`). The test block was used for exactly two refits and looks (baseline and selected) and had been seen by v1's revised protocol: held-out, not blind.

**Confusion matrix of the advisory flag (threshold 0.788):** TN 26,382, FP 637, FN 517, TP 544.

| Variant (budget 0.5 per benign hour) | Precision | Recall | F1 | Accuracy | Balanced acc. | FP rate | Alarm episodes / h | Segments | ROC-AUC |
|---|---|---|---|---|---|---|---|---|---|
| v1 (shipped before; 1,060 attack windows) | 0.366 | 0.263 | 0.306 | 0.955 | 0.623 | 0.018 | 1.79 | 6/10 | 0.825 |
| refit baseline (v1 features, random forest, train + validation) | 0.453 | 0.499 | 0.474 | 0.958 | 0.737 | 0.024 | 0.99 | 7/10 | 0.771 |
| **v2 as promoted** (selected features, gradient boosting) | **0.461** | **0.513** | **0.485** | **0.959** | **0.745** | 0.024 | 1.17 | **8/10** | **0.836** |
| v2 with persistence (not used) | 0.328 | 0.568 | 0.416 | 0.940 | 0.761 | 0.046 | 1.28 | 8/10 | 0.836 |

* **Cross-validation on train + validation (out-of-fold, selected):** segment-balanced AP 0.499, AP 0.794, ROC-AUC 0.925.
* **Where the gain comes from:** most of the F1 gain (0.31 to 0.47) comes from fitting on train + validation (the later calendar days resemble the test block more); the new features and the boosted classifier add a further 0.01 F1, +0.065 AUC and one more detected segment. Be precise about this in any publication.
* **Not detected:** segments 29 and 33 (96 and 80 windows) are never flagged. Median detection latency 57.5 s.
* **Plain accuracy is not the headline:** always-benign scores 0.962.
* **On the healthy twin** (4 simulated hours, noise on; synthetic plant, not SWaT performance): 0 alarm episodes; synthetic actuator attacks flagged after 1 to 10 s (`docs/reports/twin_domain_gap_report.md` is v1's; the v2 twin numbers are in the generated benchmark report).

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
| Cyber Agent rules | 0.064 | 0.059 | 0.104 | 0.138 |
| Cyber model (NO_MODEL stub) | 0.010 | 0.009 | 0.015 | 0.041 |
| Physical Agent rules | 0.031 | 0.028 | 0.047 | 0.070 |
| Physical model assess (includes window refresh) | 0.330 | 0.009 | 1.377 | 2.145 |
| Orchestrator | 0.016 | 0.014 | 0.027 | 0.044 |
| Packet-trace build | 0.071 | 0.067 | 0.111 | 0.139 |
| Both branches (concurrent) | 0.640 | 0.342 | 1.724 | 2.569 |
| **Total per command** | **0.801** | 0.501 | **1.972** | **2.797** |

Live Modbus round trip of a signed write to a running middleware (300 writes, includes sockets): mean **4.17 ms**, p95 4.76 ms, p99 13.2 ms. *This figure was measured before the middleware split and the move of the decision onto a worker thread (audit A2); it has not been re-measured since, so quote it as a pre-refactor number.* The hops overlap (two threads), so they do not sum to the total.

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
3. **The physical model is weak at its operating point** (recall 0.513, precision 0.461, 1.17 false-alarm episodes per hour versus a 0.5 target, 8 of 10 segments; the v1 model it replaced was 0.26 / 0.37 / 1.79 / 6 of 10) because of calendar drift; it is advisory by design.
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
| Registers, bounds, slew rates, cross-register rules, message shapes | `core/interfaces.py`, `docs/register_map.md` |
| Forensic record (append-only JSONL, replayed at dashboard start) | `core/forensics.py` |
| Addresses and environment variables | `core/netconfig.py` |
| HMAC frame and verification | `core/hmac_auth.py` |
| Measured SWaT bounds | `docs/swat_bounds.json` |
| Cyber rules | `middleware/cyber_agent.py` |
| Physical rules and envelope | `middleware/physical_agent.py` |
| Fusion | `middleware/orchestrator.py` |
| Transport and entry point | `middleware/middleware_server.py` |
| Decision path (queue, worker, routing a write) | `middleware/ingest.py` |
| PLC write path (client, forward queue, worker) | `middleware/forwarding.py` |
| PLC read path (poll loop, telemetry, settling) | `middleware/polling.py` |
| Config, shared state, health | `middleware/runtime.py` |
| Tracer | `middleware/trace.py` |
| Pipeline | `pipeline/multi_model_pipeline.py` |
| Physical model, features, fast inference | `models/physical_model.py`, `swat/physical_features.py`, `models/tree_inference.py` |
| SWaT loader | `swat/loader.py` |
| Training | `models/train_physical_swat.py`, `models/train_physical_v2.py`; negative results (v3, learned fusion, cyber ML) live in `research/` |
| Twin | `plc/twin.py`, `plc/plc.py` |
| Attacker | `attacker/attacker.py`, `attacker/scenarios.py`, `tools/swat_attack_profile.py` |
| Benchmarks and generated report | `benchmark/`, `benchmarks/latest.json`, `docs/reports/benchmark_report.md` |
| Test records | `tests/`, `benchmarks/test_results.json` |

## Physical model v3 (candidate; real-data results pending)

Files: `research/features_v3.py`, `research/train_physical_v3.py`, `research/physical_model_v3.py`, `research/package_physical_v3.py`.
Design: 120 s windows with 30/60/120 s dynamics and time-since-last-toggle (no absolute levels); normal-only ridge consistency
residuals and PCA (T2/SPE, total and per stage) fitted on normal rows and cross-fitted by hour-fold to avoid in-sample optimism;
per-stage and global gradient-boosted heads combined by a logistic stacker; segment-grouped CV with segment-balanced AP for
selection; thresholds from a false-alarm budget on out-of-fold scores; the test block is used for exactly two fits (v2-recipe
refit baseline and the selected v3); window and event metrics, bootstrap 95% CIs, confusion/PR/segment figures.
Status: verified on the synthetic fixture only (code paths); NO real-data accuracy is claimed. v2 remains the live default
(`IM_PHYSICAL_MODEL=v3` opts in once packaged). Update this section with the numbers from `physical_v3_report.md` after the run.

## Response layer (rule-based): authorization policy, quarantine, incident correlation

- `middleware/policy.py`: JSON policy (`IM_POLICY_FILE`, default `config/policy.json`): source address -> role -> writable registers and
  optional [min, max] limits; `default_role` allow/deny/role. Evaluated after HMAC, nonce and replay succeed (identity first, then
  permission). Reasons: UNAUTHORIZED_REGISTER / UNAUTHORIZED_VALUE / UNAUTHORIZED_SOURCE. Malformed file -> POLICY_ERROR on writes (fail closed);
  reads are never restricted; hot reload every `IM_POLICY_RELOAD_S` (2 s).
- `middleware/quarantine.py` (opt-in `IM_QUARANTINE=1|auto|force`; `auto`/`1` switch themselves OFF when every trusted source is loopback, i.e. a one-laptop demo, `force` overrides; the launcher sets `auto`): each blocked command adds severity-weighted strikes (forged tag 6, unsigned 4,
  replay 4, unauthorised 6, bounds 2, cross-register 3, flood 1); limit 12 within 30 s -> quarantine 60 s, doubling per repeat up to 600 s,
  automatic release; quarantine-refused commands add no strikes; checked right after the whitelist (before any crypto).
- `middleware/incidents.py`: non-PASS decisions grouped per source (gap 30 s) with attack types, registers, counts, timeline (40 events kept,
  exact count), severity low/medium/high/critical (critical = quarantined or 3+ distinct types), forwarded to the dashboard panel.
- Evidence: `tests/test_response_layer.py`; live check on the real stack: two forged-HMAC frames -> critical incident, source quarantined.

## Evidence pack (`benchmark/evidence_pack.py`)

One command produces the panel proof set: (1) a LIVE campaign (real PLC twin, middleware, dashboard on free loopback ports; labelled legitimate
traffic = 40 in-bounds signed writes, then each scripted attack; outcomes read from the dashboard's `/api/flow` traces and the blocked-attack log);
(2) a deterministic response-layer demonstration (quarantine after 2 forged commands, policy cases); (3) recorded results (held-out REAL SWaT,
rule regression on constructed scenarios). Commands are labelled by the phase that sent them, so multi-step attacks whose early steps are
allowed by design (flood's first 5 frames, the original frame of a replay, the early ramp steps of cross-register) count as command-level misses;
a note column explains each. First run: command-level TN 40 / FP 0 / FN 11 / TP 15 (precision 1.0, recall 0.577, F1 0.732); campaigns detected
9/10, 9/9 of those passing through the middleware; `false-injection` bypasses the middleware (documented limit). The physical ML model is cold
during the campaign (120 s warm-up), so it measures the rules. Outputs: docs/reports/evidence_pack.md, benchmarks/evidence_pack.json,
docs/reports/figures/evidence_live_campaign.png, evidence_swat_heldout.png.

## Explaining the physical model's verdict (no retraining)

`models/explain.py` turns one probability into a sentence. The 18 live channels (10 sensors, 8 actuators) are grouped by plant stage;
when the model flags, the 120 s window is rebuilt five times, each time with one stage's RAW CHANNELS replaced by those of the most recent
window the model itself scored as normal, every feature is recomputed and the window is rescored. The drop in probability is that stage's
contribution and the largest names `suspect_stage`. Swapping raw channels rather than feature columns is essential: several features
(`sensors_outside_envelope`, `max_envelope_excess`, `resid_abs_*`) summarise the whole plant, so editing columns leaves them stale and the
attribution collapses onto them. The explanation is contrastive ("what changed since the plant last looked fine"), needs no training data at
run time, costs about 2-3 ms, and runs only on a flag. Measured on synthetic single-sensor spoofs it names S1, S3 and S5 correctly with the
driving stage contributing 0.6-0.9 probability while the others stay within +/-0.02.

Each assessment also reports the three sensors furthest from measured normal (z-score, direction, whether outside the measured envelope),
`confidence` (`marginal` when the probability is within 0.05 of the threshold), `reference_age_s` and `warmup_remaining_s`. `suspect_stage`
reaches the ALERT reason (`PHYSICAL_MODEL:classifier S3`), the fusion record, the packet tracer and the blocked-attack log.

`models/operating_points.py` exposes named operating points read from the held-out report, never invented: `balanced` (shipped, 0.5/h budget,
threshold 0.7880, measured 1.17 alerts/h, 8/10 segments, F1 0.485) and `sensitive` (1.0/h budget, threshold 0.6895, 2.0 alerts/h, recall 0.563,
F1 0.468), selected with `IM_PHYSICAL_SENSITIVITY`; `IM_PHYSICAL_THRESHOLD` still overrides with a raw number. `model_card()` and
`docs/MODEL_CARD.md` state what the model is, its measured performance and its known limits; the middleware publishes the card to the
dashboard at startup (`/api/model`) so the panel describes the model that is actually running. Tests: `tests/test_physical_explain.py`.

## End-to-end system-flow verification (four laptops, simulated and captured)

`tools/sim_four_laptops.py` runs the complete demo on a single machine with each role on its own loopback address, so the cyber agent
genuinely sees four distinct peers: 127.0.0.1 middleware + dashboard, 127.0.0.2 PLC twin, 127.0.0.3 SCADA operator (trusted),
127.0.0.4 attacker (trusted segment, malicious), 127.0.0.9 rogue (untrusted). Nine phases run over real Modbus/TCP while tshark
captures both legs to TSV and to a pcapng. The tool then cross-checks four independent records of the same traffic - packet capture,
Packet Tracer, blocked-attack log, dashboard flow - matching wire frames to tracer entries by the 64-bit frame nonce (the tx_id is
generated inside the middleware and never appears on the wire).

Recorded result (docs/reports/system_flow_verification.md): 24 signed frames captured, 24 consistent with the tracer, 0 mismatches.
Every DROP (forged HMAC, out-of-bounds, replay, five rate-limit frames, unsigned, untrusted source, cross-register) is present on the
middleware leg and absent from the PLC leg; every PASS and ALERT is present on both. The single direct-to-PLC write from the attacker
appears on the PLC leg only, confirming the documented limit of an inline control. Each DROP produces exactly one blocked-attack-log
record and the events correlate into per-source incidents. A Modbus-level response is still returned to the sender on a DROP (the
frame write itself is accepted by the datastore); what does not happen is the forward to the PLC, so no PLC response follows.

## The investigation layer (opt-in LLM agent, out of band)

Design principle: an LLM-powered agent still uses code and rules. Authentication, access control and the hard safety limits stay
deterministic; what stops being a fixed chain of if/else statements is the investigation and decision workflow above them.

`middleware/investigator.py` implements exactly that split. The pipeline's verdict is unchanged and unchangeable: the investigator
is triggered from `_respond` AFTER the decision has been published, runs in a worker thread, and produces a report. Its evidence
tools are read-only accessors over records this process already holds (incident, per-command traces, plant state and the physical
model's explanation, the rule catalogue, live policy and quarantine settings, the model card, the blocked-attack log); the model
chooses which to call and in what order, which is the part a fixed rule chain cannot do, and every call is recorded so a finding
can be audited back to the evidence it rests on.

Containment is in code, not in the prompt: recommendations are validated against a fixed allow-list (`ACTIONS`) and anything
invented is dropped into `rejected_actions` rather than executed; every recommendation is marked `requires_human_approval` and
`applied: false`, and the dashboard panel has no Apply control; turns, tool calls and tokens are capped; tool results are wrapped
as `untrusted_evidence` because register values, source addresses and reason strings are attacker-influenced, and the system
prompt states that instructions found inside evidence are themselves evidence of manipulation. If the SDK, the API key or the
network is missing - or anything at all fails - `offline_finding()` writes the same finding shape deterministically and the system
behaves exactly as it did before. The agent loop is written out rather than delegated to the SDK's tool runner so that the caps
and the audit trail are explicit.

Model: `claude-opus-5-5` with adaptive thinking and server-side refusal fallbacks (the evidence describes cyberattacks on a plant,
which a safety classifier may decline). Opt in with `IM_INVESTIGATOR=1`; tune with `IM_INVESTIGATOR_MODEL`, `IM_INVESTIGATOR_EFFORT`
and `IM_INVESTIGATOR_MIN_SEVERITY`. `anthropic` is an optional dependency. Run it by hand with
`python -m tools.investigate --incident INC-0001 [--offline] [--publish]`. Tests: `tests/test_investigator.py`, whose stub client
exercises the real loop, caps, validation and injection resistance without a network call.

## Adversarial audit and hardening (after the evaluation above)

The system was reviewed adversarially (`final-results/AUDIT.md`); the pre-review state is frozen, never edited, in `final-results/before-review/`. The review found defects that all of the then-passing tests had missed, because they checked components against their own specification, not what an operator needs. Each fix is pinned by an operator-level test (`tests/test_audit_fixes.py`, `test_sprint_fixes.py`, `test_quarter_fixes.py`) and re-verified live (`final-results/_verify_fixes.py`, 14/14).

| Finding | Before | After |
|---|---|---|
| C1 approved command never delivered | reported PASS | reported `UNDELIVERED`, moved out of the pass count |
| C2 unresponsive PLC stalls every client | 2,002 ms per command | 504 ms (bounded timeout), then 1.9 ms (forward moved off the event loop) |
| C3 library log flood in a 30 s outage | 99 lines | 1 line (filter attached to the handler, not the logger) |
| C4 poll retries a dead PLC | ~18,000 attempts/hour | 720 (exponential backoff to 5 s) |
| C5 replay check not atomic | unsynchronised | 12 threads replaying one nonce: exactly 1 accepted |
| S1 PLC accepts writes from anything | bypass moves the plant | refused at the PLC, logged; default allow-list is the middleware host |
| S3 open dashboard on a network | POST endpoints unauthenticated | refuses to start off loopback without `IM_DASHBOARD_TOKEN` |
| S4 quarantine keyed to source address | 2 forged frames quarantine the real operator | strikes only from HMAC-authenticated commands; check runs after authentication |
| A4 forensic record in UI memory | lost on restart | append-only JSONL, replayed at startup; Reset sets files aside |
| A1/A2 1,478-line module, pipeline inside the storage hook | decision ran in `setValues` | five modules; the hook enqueues; one ordered decision worker |
| N2 dashboard CDN assets | blank chart on an air-gapped lab | vendored chart and icons, zero console errors offline |

Code layout after the refactor: source modules live in `core/`, rejected experiments in `research/` (v3 physical model, learned fusion, cyber ML), and `docs/` is documentation only. **Caveats worth stating in a paper:** the PLC allow-list is defence in depth, not a substitute for segmentation (a spoofed source address still passes); the quarantine is spoof-proof only with per-device keys (`IM_HMAC_KEYS`); and the four-laptop deployment is verified on loopback addresses with a real capture, not yet on four physical machines.

## Evaluation protocol for the physical model (`benchmark/swat_protocol.py`, `swat/scoring.py`)

The v2 held-out result is one calendar split with 10 test attacks and no error bars. The protocol re-measures the model on **all 35 attacks** and reports it so that it can be compared with the literature without being inflated.

- **Rolling blocked cross-validation.** Attack segments, in time order, are cut into contiguous groups (5 folds by default). Each group is the test fold once; everything else trains, minus a 300 s embargo around the test fold. The 22-28 Dec normal period never tests (no attacks) but always trains. Thresholds are set per fold from inner out-of-fold scores of the training part, so the test fold never sets them; the realised false-alarm rate is reported next to the budget.
- **Five scoring schemes on the same alarms** (`swat/scoring.py`): strict per window; composite (window precision, attack recall; Garg et al.); PA%K at K = 20 / 50 / 80 (Kim et al., AAAI 2022); point-adjust (one flagged window credits the whole attack); event level (attacks detected, delay, false-alarm episodes per benign hour, share of alarm episodes inside an attack).
- **Cluster-bootstrap 95 % intervals**: attacks and benign hours are resampled, not windows.
- **Baselines on the same folds**: never alarm; chance alarms matched to the model's alarm rate and length (scored under every scheme: the point-adjust proof); the envelope rule alone; PCA reconstruction error; Isolation Forest; the 67-feature random-forest refit baseline. Plus the result with and without the 10-hour attack, and an attack-by-attack table with a heuristic description from the data (SWaT ships no attack list): which of the 51 tags moved and whether any of the 18 tags the model reads did.
- **Already measured, no data needed** (`--from-report`, `docs/reports/swat_scoring_comparison.md`): the saved v2 test result re-scored from its per-attack aggregates. Same alarms, only the counting changes: strict F1 0.485, composite 0.585, PA%K(50) 0.618, point-adjust 0.685; 8/10 attacks, 1.17 false-alarm episodes per hour, accuracy 0.959 against 0.962 for a never-alarm system. Its intervals resample the 10 attacks only (the report keeps one benign total) and are therefore too narrow.
- **Not yet measured**: the cross-validated all-attack numbers, intervals and baseline comparison need the archive (`python -m benchmark.swat_protocol --data-dir <SWaT>`, about 20-40 minutes). A fixture run (`--fixture --quick`) checks the code path only; its numbers are meaningless.

Why published SWaT scores of 0.8-0.9 are higher: they mostly use point-adjust (the 10-hour attack is 66 % of all attack seconds, so one flagged second inside it credits two thirds of the attack time), and many pick the threshold on the test labels. Our threshold is fixed beforehand and false alarms are counted.

## Physical-invariant rules (`swat/invariants.py`, `models/invariant_monitor.py`; opt-in `IM_INVARIANTS=1`)

Deterministic consistency rules learned from normal operation only (no labels, no classifier), advisory (ALERT, never DROP). Three families over the 18 live signals: **rate** (a sensor cannot move faster than it ever did, 10 s and 60 s), **state** (while an actuator holds a state for 30 s, a sensor stays in the band it always had), **balance** (a tank's 60 s level change is explained by the flows and pump states around it). Each yields an excess that is at most 1 inside the normal range; it must persist (2 / 10 / 20 s); the score is the largest and the rule fires above `theta` (1 = beyond everything normal training showed).

Validation is part of the method: proposals are fitted on the first 75 % of the normal rows and checked on the last 25 %, held out in time; a rule that misfires on unseen normal rows is dropped with the reason recorded; state bands must be tighter than the sensor's marginal range, a balance must explain the level change and beat the plain rate cap, and tolerances are the worst per-block quantile. On a synthetic plant with exact physics the fit finds the tank balance and the pump-to-flow coupling, invents no relation for independent signals, stays silent on a fresh healthy run and detects a stuck flow meter (9 s), a frozen level sensor (21 s), a 200 mm jump (1 s), a biased flow meter, a creeping level and a mismatched pump state (`tests/test_invariants.py`, 68 checks). The live monitor agrees with the offline score on every second.

Measured so far: on the **twin** (`docs/reports/twin_invariants_report.md`, twin measurement, not SWaT) only the rate family survives validation, the fresh healthy run is silent at the calibrated `theta` 1.5, and four of five synthetic actuator attacks raise a violation within 2-8 s (chlorine breakthrough, a slow consistent drift, does not). On the **real stack** (`python -m tools.live_invariants_check`) the healthy plant stayed silent for 100 s and a synthetic attack raised an upstream ALERT in 4 s that the dashboard showed. **Not yet measured: detection and false alarms on real SWaT** (`python -m tools.fit_invariants --data-dir <SWaT>` fits on the 22-28 Dec normal period only and tests every attack out of sample; the protocol also scores "v2 OR invariants"). Consistency rules cannot see an actuator-only attack whose consequences are internally consistent. Full description: `docs/INVARIANTS.md`.

**Before/after of the invariant rules on the twin** (`python -m benchmark.invariants_ab`, `docs/reports/invariants_ab_report.md`; twin measurement, not SWaT). BEFORE = v2 model flag OR the measured-envelope rule; AFTER = plus the invariants (four families: rate, state, balance, flat); nothing else differs. Over 5 seeds: actuator attacks 25/25 detected both ways (the previous system already caught them, median 4 s); **sensor tampering 10/25 -> 25/25** (a level jump and a dead flow meter within about 1 s and a frozen level sensor within about 22 s, none of which the model or envelope flagged; the invariants alone catch 15/25, and a flow-meter bias and a slow ramp are caught only by the previous system); false-alarm episodes per healthy hour 0.0 -> 0.0 over 9 hours; decision latency p50 0.435 -> 0.449 ms (interleaved, no measurable change; the monitor costs 1.5 ms per telemetry sample off the decision path and 0.8 microseconds per decision). **Disclosed:** the flat family was added after the first run showed the frozen-sensor case missed, so that scenario is not independent evidence, and the five sensor attacks are our own construction. The shipped v2 model and its SWaT numbers are unchanged.

**Campaign view of the live run** (`docs/reports/evidence_pack.md`): command-level recall 0.58 counts the commands an attack is allowed to send before it is recognisable as misses. Read as campaigns: 9 of 9 attack campaigns through the middleware detected (slowest at its 6th command), 10 attack-labelled commands passed before the first flag (the first frames of a flood under the rate limit, the original of a replay, the individually safe early steps of a ramp), **0 passed after detection began**, 0 of 40 legitimate commands flagged. `false-injection` writes directly to the PLC and cannot be stopped inline (the PLC allow-list refuses it across hosts).

## End-to-end assurance (`benchmark/assurance.py`, `docs/reports/assurance_report.md`)

One command runs seven assurance dimensions and writes a generated report. Everything except the recorded SWaT row is measured on the digital twin with attacks of our own construction: that shows the system does what it was designed to do, not that it generalises to attacks nobody anticipated.

| dimension | result |
|---|---|
| **Functional accuracy** (30 twin runs, 3 with no attack; 33,150 scored seconds, 4.71 benign hours) | layered system F1 **0.917**, precision 0.995, recall 0.851, accuracy 0.925 against a never-alarm baseline of 0.511; model alone F1 0.840 (ROC-AUC 0.972, PR-AUC 0.974), envelope rule 0.833, invariants 0.497 (ROC-AUC 0.805); 27/27 attack runs detected, median 2 s |
| **Robustness** | 0 crashes and 0 wrongly accepted of 24 commands that must be refused (tampered `mac`, `register` or `raw_value`, zeroed nonce, stale timestamp, NaN/infinite/absurd values, bad function codes, empty dict); unusable telemetry makes both detectors abstain; 640 commands from 8 threads with 0 exceptions |
| **Bias and fairness** (equal treatment; there are no people in this data) | identical outcome from every trusted source address and acceptance ratio 1.0 across all 10 actuators; **per-stage detection ratio 0.33 at a 1 sigma perturbation** |
| **Consistency** | 1 distinct outcome over 200 identical commands; order-independent rules unaffected by order; live monitor matches the offline engine exactly (max difference 0.0 over ~1,700 s); the same seed reproduces the run |
| **Explainability** | every decision carries a machine-readable reason and a complete tracer record, and every refusal names the failing check; stage attribution **100% top-1** against a 20% chance level, and the invariants name the tampered sensor 100% of the time |
| **Drift** | PSI 0.0 for an identical repeated run (the control), 0.21 between halves of one healthy run, 1.0 against an independent one; **alarm seconds rise from 18 to 695 across 4 healthy hours** |
| **Safety** | fail-closed on a fault injected into each of the cyber agent, the physical agent and the orchestrator, and working again afterwards; an advisory flag alone always yields ALERT, never DROP; all 8 documented unsafe cross-register states refused by their own rule with recovery allowed in all 8; both queues bounded; the PLC refuses a foreign writer |

**Two findings to carry into the limitations section.** (1) *Uneven stage coverage:* at a 1 sigma perturbation, detection is 100 % in stages 1 and 4 but 33 % in stages 2, 3 and 5. The weakest is stage 2 (AIT202, pH), whose measured spread is close to the Modbus wire's 0.1 resolution, so small perturbations there are partly unrepresentable. (2) *Alarms grow over a long healthy run* (18 alarm seconds in the first half of four hours, 695 in the second) with the model's 95th-percentile probability sitting on its threshold: the SWaT-to-twin domain gap surfacing as the twin's fouling cycle develops. Neither is a defect in the decision path, which stays fail-closed and rule-governed, but both bound what the advisory layer can be trusted to do unattended.

The harness also audited itself: its first run reported 3/8 unsafe states blocked, trivially perfect precision, a saturated fairness test and a "wrongly accepted" truncated signature. All four were defects in the harness (a test state already in violation, a benign side that was only the settle period, an 8 sigma step that everything catches, and a fuzz case that patched a non-existent `tag` field instead of `mac`). Correcting them gives the numbers above, and the exercise found one genuine defect in the system: `PhysicalModel._value` raised on a non-numeric reading instead of abstaining as documented.
