# IndustrialMind benchmark report

_Generated 2026-10-14 21:33:44 UTC by `python -m benchmark.run_all` at commit `4dffbcb`. Every number below comes from `benchmarks/latest.json`; nothing is typed by hand._

Four sections, deliberately separate because they answer different questions and have different evidential weight:

| Section | Data | What it supports |
|---|---|---|
| 1. Latency | constructed workload, real code | speed of the decision pipeline |
| 2. Held-out SWaT | REAL data (test block) | the only real-data detection performance (physical side) |
| 3. Rule-based checks | constructed scenarios | each deterministic rule fires on what it was written for |
| 4. Twin measurements | synthetic plant | demo behaviour of the model on the digital twin |

## Whole middleware at a glance

| What is scored | Evidence | n | Accuracy | Precision | Recall | F1 | False-positive rate | TN / FP / FN / TP |
|---|---|---|---|---|---|---|---|---|
| Physical model flag -> ALERT | REAL SWaT held-out windows | 28075 | 0.955 | 0.366 | 0.263 | 0.306 | 0.018 | 26,532 / 483 / 781 / 279 |
| Rule layers, all violations vs legitimate commands | constructed commands | 4600 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 200 / 0 / 0 / 4,400 |
|   cyber layer only | constructed commands | 2000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 200 / 0 / 0 / 1,800 |
|   physical layer only | constructed commands | 2800 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 200 / 0 / 0 / 2,600 |
| Rule layers, attack sessions vs benign sessions (incl. stealthy freeze/ramp) | constructed sessions | 700 | 0.860 | 1.000 | 0.837 | 0.911 | 0.000 | 100 / 0 / 98 / 502 |

Three-class decision matrix of the rule layers on constructed commands (rows = truth, columns = decision):

| truth | PASS | ALERT | DROP |
|---|---|---|---|
| truth_PASS (legitimate) | 200 | 0 | 0 |
| truth_DROP (violating) | 0 | 0 | 4,400 |

![Whole-middleware confusion matrices](figures/middleware_confusion_matrices.png)

**How to read this.** There is no single accuracy for the whole middleware, because the evidence has different strengths and must not be pooled. Only the first row is real-data performance (physical model, advisory, SWaT held-out). The other rows test the deterministic RULE layers on scenarios *we built*: perfect scores there mean each rule fires on what it was written for (a regression check), and the session-level row shows the honest gap, the stealthy in-bounds attacks the rules do not stop. Accuracy alone is misleading on imbalanced data: judge by recall, precision and the false-positive rate.

## 1. Latency (per hop)

**What this is.** In-process decision latency of the real pipeline on a constructed workload (no sockets). 3000 commands x 3 repeats after 300 warm-up, seed 7; 70% legitimate, 30% attacks (tamper, unsigned, replay, out-of-bounds, untrusted source, cross-register).

Measured on Linux-6.18.44-fc-v114-x86_64-with-glibc2.39, Python 3.13.16, 4 CPUs, scikit-learn 1.9.1, commit `4dffbcb`. Latency depends on the machine: re-run `python -m benchmark.run_all` on yours.

| Hop | mean (ms) | p50 (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|
| Cyber Agent rules | 0.0406 | 0.0354 | 0.0706 | 0.0921 |
| Cyber model (NO_MODEL stub) | 0.0086 | 0.0072 | 0.0139 | 0.0350 |
| Physical Agent rules | 0.0270 | 0.0245 | 0.0416 | 0.0607 |
| Physical model (assess; includes window refresh) | 0.2206 | 0.0051 | 0.9207 | 1.1063 |
| Orchestrator fusion | 0.0112 | 0.0089 | 0.0226 | 0.0360 |
| Packet-trace build | 0.0436 | 0.0365 | 0.0750 | 0.1084 |
| Both branches (concurrent, wall time) | 0.4458 | 0.2444 | 1.1751 | 1.3795 |
| TOTAL per command | 0.5180 | 0.3150 | 1.2659 | 1.4883 |

![Per-hop latency](figures/latency_per_hop.png)

Spread of the total across repeats: mean 0.509-0.5297 ms, p95 1.2435-1.3055 ms. The two branches overlap, so hops do not sum to the total.

Live Modbus round trip of a signed write to a running middleware (300 writes): mean 4.1684 ms, p95 4.764 ms, p99 13.1886 ms.

## 2. Held-out SWaT (real data)

**PROMOTED physical model on the HELD-OUT SWaT test block (real data, aggregate only).** test block was also seen in physical training run 2 (revised protocol): held-out, not a pristine blind test.

_Source: reused from benchmarks/swat_accuracy.json (measured earlier on the machine that holds the archive)_

Test block: 28,075 windows (stride 5 s): 1,060 attack, 27,015 benign (37.521 benign hours). Operating point: Isolation Forest threshold 0.6108, classifier threshold 0.601, variant `drift_robust`.

| Decision rule | precision | recall | F1 | false-positive rate | accuracy | balanced accuracy | alarm episodes / benign hour |
|---|---|---|---|---|---|---|---|
| Advisory model flag (drives ALERT) | 0.366 | 0.263 | 0.306 | 0.018 | 0.955 | 0.623 | 1.786 |
| Envelope rule alone (alert-only) | 0.273 | 0.216 | 0.241 | 0.022 | 0.949 | 0.597 | 0.853 |
| Model flag or envelope | 0.274 | 0.271 | 0.272 | 0.028 | 0.945 | 0.621 | 1.999 |

Plain accuracy is shown but is **not the headline**: attacks are only 3.8% of windows, so a system that never flags anything would score **0.962** accuracy (balanced accuracy 0.5). Judge the model by recall, precision, false alarms per hour and AUC.

Confusion counts (windows; rows = true label, columns = prediction):

| Decision rule | benign, no flag (TN) | benign, flagged (FP) | attack, no flag (FN) | attack, flagged (TP) |
|---|---|---|---|---|
| Advisory model flag | 26,532 | 483 | 781 | 279 |
| Envelope rule alone | 26,406 | 609 | 831 | 229 |
| Model flag or envelope | 26,254 | 761 | 773 | 287 |

![Confusion matrices on the held-out SWaT test block](figures/swat_confusion_matrix.png)

ROC-AUC (attack probability) **0.825**, ROC-AUC (Isolation Forest score) 0.634, average precision 0.311.
Attack segments detected: **6/10**; median detection latency 50.0 s (first flagged attack window after the segment starts).

Excluding the largest segment (35, 31.9% of attack windows): precision 0.366, recall 0.386, F1 0.376.

The per-segment table is not part of this record (it was taken from the printed console summary); re-run `python -m benchmark.swat_accuracy ... --out benchmarks/swat_accuracy.json` to include it.

## 3. Rule-based checks and constructed scenarios (NOT SWaT, NOT a learned model)

**RULE-BASED checks on CONSTRUCTED scenarios (deterministic rules; NOT SWaT, NOT a learned model).** 200 randomised scenarios per case, seed 7, virtual clock. A scenario counts as detected only when the real pipeline returns DROP **with the expected reason**. The rules are deterministic, so 100 % is expected: this is a regression check that each rule fires on what it was written for, not evidence of performance against an unknown attacker.

| Layer | Case | Expected | As expected |
|---|---|---|---|
| legitimate | operator command, in bounds, slow | `PASS` | 200/200 (100.0%) |
| cyber | untrusted source | `UNTRUSTED_SOURCE` | 200/200 (100.0%) |
| cyber | invalid function code | `INVALID_FUNCTION_CODE` | 200/200 (100.0%) |
| cyber | unknown register | `INVALID_REGISTER` | 200/200 (100.0%) |
| cyber | rate-limit burst | `RATE_LIMIT_EXCEEDED` | 200/200 (100.0%) |
| cyber | HMAC missing (unsigned) | `HMAC_MISSING` | 200/200 (100.0%) |
| cyber | HMAC invalid: value tampered | `HMAC_INVALID` | 200/200 (100.0%) |
| cyber | HMAC invalid: wrong key | `HMAC_INVALID` | 200/200 (100.0%) |
| cyber | HMAC expired / future-dated | `HMAC_EXPIRED` | 200/200 (100.0%) |
| cyber | replayed frame | `REPLAY_DETECTED` | 200/200 (100.0%) |
| physical | write to a sensor register | `WRITE_TO_SENSOR_REGISTER` | 200/200 (100.0%) |
| physical | out-of-bounds value | `OUT_OF_BOUNDS` | 200/200 (100.0%) |
| physical | rate of change too fast | `RATE_OF_CHANGE_EXCEEDED` | 200/200 (100.0%) |
| physical | stage rule VALVE_CLOSING_LOW_LEVEL | `CROSS_REGISTER_VIOLATION:VALVE_CLOSING_LOW_LEVEL` | 200/200 (100.0%) |
| physical | stage rule RO_PRESSURE_OVERLOAD | `CROSS_REGISTER_VIOLATION:RO_PRESSURE_OVERLOAD` | 200/200 (100.0%) |
| physical | cross-register RAW_PUMP_DRY_RUN | `CROSS_REGISTER_VIOLATION:RAW_PUMP_DRY_RUN` | 200/200 (100.0%) |
| physical | cross-register RAW_TANK_OVERFLOW | `CROSS_REGISTER_VIOLATION:RAW_TANK_OVERFLOW` | 200/200 (100.0%) |
| physical | cross-register ACID_OVERDOSE_LOW_FLOW | `CROSS_REGISTER_VIOLATION:ACID_OVERDOSE_LOW_FLOW` | 200/200 (100.0%) |
| physical | cross-register UF_PUMP_DEADHEAD | `CROSS_REGISTER_VIOLATION:UF_PUMP_DEADHEAD` | 200/200 (100.0%) |
| physical | cross-register UF_TANK_OVERFLOW | `CROSS_REGISTER_VIOLATION:UF_TANK_OVERFLOW` | 200/200 (100.0%) |
| physical | cross-register CHLORINE_BREAKTHROUGH | `CROSS_REGISTER_VIOLATION:CHLORINE_BREAKTHROUGH` | 200/200 (100.0%) |
| physical | cross-register RO_PUMP_DEADHEAD | `CROSS_REGISTER_VIOLATION:RO_PUMP_DEADHEAD` | 200/200 (100.0%) |
| physical | cross-register RO_FEED_STARVATION | `CROSS_REGISTER_VIOLATION:RO_FEED_STARVATION` | 200/200 (100.0%) |

![Rule-based checks](figures/rule_checks.png)

Legitimate-command false-positive rate: **0.0%**. Violating scenarios detected with the expected reason: **4400/4400**.

**Randomised attacker plans through the rule agents** (Randomised ATTACKER PLANS through the RULE agents (constructed; swat-derived types follow SWaT behaviours, synthetic-extension types are network-layer constructions; physical ML model cold)). 100 runs per type, seed 11.

| Attack type | Origin | Runs with at least one DROP | Drop reasons (frames) |
|---|---|---|---|
| freeze | swat-derived | 80/100 (80.0%) | REPLAY_DETECTED 319, CROSS_REGISTER_VIOLATION 29 |
| ramp | swat-derived | 22/100 (22.0%) | CROSS_REGISTER_VIOLATION 35, RATE_OF_CHANGE_EXCEEDED 28 |
| cross-register | swat-derived | 100/100 (100.0%) | CROSS_REGISTER_VIOLATION 148, RATE_OF_CHANGE_EXCEEDED 100 |
| impossible-command | synthetic-extension | 100/100 (100.0%) | OUT_OF_BOUNDS 215 |
| flood | synthetic-extension | 100/100 (100.0%) | RATE_LIMIT_EXCEEDED 2088, REPLAY_DETECTED 12, RATE_OF_CHANGE_EXCEEDED 9 |
| replay | synthetic-extension | 100/100 (100.0%) | REPLAY_DETECTED 327 |

![Attacker plans through the rules](figures/attacker_plans.png)

The stealthy SWaT-derived behaviours (`freeze`, `ramp`) are mostly in-bounds and slow, so the rules alone do not stop them (a frozen value re-sent within 2 s is caught only by the duplicate-payload replay check). They are what the advisory physical model is for.

## 4. Digital-twin measurements (synthetic plant, NOT SWaT)

**TWIN MEASUREMENT (synthetic plant calibrated to SWaT) - NOT SWaT detection performance.** Promoted physical model on the calibrated twin: 4.0 simulated hours of nominal operation with sensor noise.

* learned-model alarm episodes on the HEALTHY twin: **0.25 per hour** (13 flagged seconds)
* measured-envelope rule alarm episodes: **0.0 per hour**

| Synthetic actuator attack | first model flag (s after) | first envelope violation (s after) |
|---|---|---|
| p101_stop (raw pump stops) | 3 | 3 |
| acid_overdose (HCl max, raw pump low) | 2 | 2 |
| chlorine_breakthrough (NaOCl max, UV off) | 8 | 8 |
| ro_deadhead (RO pump max, reject valve shut) | 1 | 1 |
| uf_valve_shut (UF feed valve closes) | 4 | 16 |

![Twin detection latency](figures/twin_detection_latency.png)

This measures the demonstration plant only. It says nothing about SWaT detection performance.

## Known limitations

* The cyber layer cannot be evaluated on SWaT (no signatures, replay tags or source addresses in the archive): Section 3 is rule testing.
* The cyber branch has no learned model by design (a SWaT-trained candidate was weak and was not promoted); the physical model is advisory.
* A learned fusion model was tried and rejected (test AUC below the physical model alone): `docs/reports/fusion_training_report_swat.md`.
* The SWaT test block was also seen in physical training run 2 (disclosed protocol revision): held-out, not a pristine blind test.
* SWaT has no network-layer attacks: flood, replay and impossible-command are synthetic extensions; freeze, ramp and cross-register follow SWaT behaviours.
* Latency is in-process decision latency on the machine named above, not network latency.
