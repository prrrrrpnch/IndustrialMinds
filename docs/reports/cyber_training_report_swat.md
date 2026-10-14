# CyberModel - SWaT-only training report (CANDIDATE)

## Scope and honesty notes

* Trained and evaluated on **SWaT only** (actuator state-change events, labelled by attack segment).
* **Rule-based checks (HMAC, replay, whitelist, rate limit) are NOT evaluated here.** SWaT has no signatures, replay tags or source addresses; those rules are validated only by unit tests and the rule-tested/constructed scenarios in later phases.
* SWaT has no network data: a 'command' is an actuator state change. Event labels are inherited from the attack window (1 binary flag per row), so some flagged-attack events may be ordinary control reactions.
* The model abstains on commands with no SWaT counterpart (writes that do not flip on/off, sensors, MV503 which is twin-only).

## Data

* rows after de-duplication: 946,719 (read 1,441,719); duplicate timestamps dropped 495,000 (exact 495,000, conflicting 0)
* chunks (gaps > 5 s): 2; attack segments: 35; segments crossing midnight: 0

| block | rows | attack rows | segments | events | attack events |
|---|---|---|---|---|---|
| train | 633,600 | 8,682 | 17 | 2,377 | 79 |
| val | 172,719 | 40,634 | 8 | 609 | 42 |
| test | 140,400 | 5,305 | 10 | 680 | 30 |

Events per actuator: {'MV101': 240, 'MV302': 914, 'P101': 504, 'P203': 504, 'P205': 546, 'P302': 917, 'P402': 17, 'P501': 11, 'UV401': 13}

## Thresholds (chosen WITHOUT the test block)

* Isolation Forest: 0.6763 (99.5th percentile of train-normal scores)
* Classifier: 0.4241 (max validation F1 = 0.225)

## Held-out TEST block (1-2 Jan) - confusion matrices

**Isolation Forest**

| | predicted normal | predicted attack |
|---|---|---|
| actual normal | 649 | 1 |
| actual attack | 29 | 1 |

precision 0.500, recall 0.033, F1 0.062, ROC-AUC 0.569, AP 0.084

**Supervised classifier**

| | predicted normal | predicted attack |
|---|---|---|
| actual normal | 517 | 133 |
| actual attack | 19 | 11 |

precision 0.076, recall 0.367, F1 0.126, ROC-AUC 0.631, AP 0.095

**Combined (either)**

| | predicted normal | predicted attack |
|---|---|---|
| actual normal | 517 | 133 |
| actual attack | 18 | 12 |

precision 0.083, recall 0.400, F1 0.137

**Baseline: flag everything**

| | predicted normal | predicted attack |
|---|---|---|
| actual normal | 0 | 650 |
| actual attack | 0 | 30 |

precision 0.044, recall 1.000, F1 0.085

Test false alarms: 133 normal events flagged over 37.53 normal hours (3.544 per hour).

## Validation block (for transparency)

| model | precision | recall | F1 |
|---|---|---|---|
| isolation_forest | 0.571 | 0.095 | 0.163 |
| classifier | 0.150 | 0.452 | 0.225 |
| combined_either | 0.146 | 0.452 | 0.221 |

## Per-segment detection (combined flag)

**val**: 8 segments, 7 contain actuator events, 6 detected (a segment with no actuator events cannot be detected by an event-based model)

| segment | start | rows | events | flagged |
|---|---|---|---|---|
| 18 | 2015-12-30 01:42:34 | 697 | 4 | 3 |
| 19 | 2015-12-30 09:51:08 | 321 | 5 | 1 |
| 20 | 2015-12-30 10:01:50 | 612 | 2 | 1 |
| 21 | 2015-12-30 17:04:56 | 1445 | 8 | 2 |
| 22 | 2015-12-31 01:17:08 | 35900 | 16 | 11 |
| 23 | 2015-12-31 15:32:00 | 121 | 0 | 0 |
| 24 | 2015-12-31 15:47:40 | 1171 | 4 | 1 |
| 25 | 2015-12-31 22:05:34 | 367 | 3 | 0 |

**test**: 10 segments, 10 contain actuator events, 6 detected (a segment with no actuator events cannot be detected by an event-based model)

| segment | start | rows | events | flagged |
|---|---|---|---|---|
| 26 | 2016-01-01 10:36:00 | 601 | 3 | 0 |
| 27 | 2016-01-01 14:21:12 | 444 | 5 | 3 |
| 28 | 2016-01-01 17:12:40 | 101 | 1 | 0 |
| 29 | 2016-01-01 17:18:56 | 481 | 5 | 1 |
| 30 | 2016-01-01 22:16:01 | 540 | 1 | 1 |
| 31 | 2016-01-02 11:17:02 | 469 | 8 | 4 |
| 32 | 2016-01-02 11:31:38 | 281 | 2 | 0 |
| 33 | 2016-01-02 11:43:48 | 401 | 1 | 0 |
| 34 | 2016-01-02 11:51:42 | 297 | 2 | 1 |
| 35 | 2016-01-02 13:13:02 | 1690 | 2 | 2 |

## Feature provenance

| feature | SWaT source / derivation | status |
|---|---|---|
| turns_on | actuator state column: 1->2 (on/open) vs 2->1 (off/closed) | derived |
| stage | tag digit of the actuator column (P1..P5) | derived |
| is_valve | tag prefix MV | derived |
| log_dt_same_ms | Timestamp deltas between changes of the same actuator column (1 s resolution) | derived |
| log_dt_any_ms | Timestamp deltas between changes of any twin actuator column | derived |
| events_1s | count of actuator changes in the preceding 1 s | derived |
| events_10s | count of actuator changes in the preceding 10 s | derived |
| same_reg_60s | count of changes of the same actuator in the preceding 60 s | derived |

Legacy 13-feature schema items that SWaT cannot supply:

| legacy feature | why | handling |
|---|---|---|
| fc_write_single / fc_write_multiple / fc_other | no Modbus function codes in SWaT (no network data) | dropped |
| register_known | constant 1 by construction (only known actuators are events) | dropped (no variance) |
| value_norm | replaced by turns_on: SWaT actuators are binary | dropped (redundant) |
| out_of_range | constant 0: SWaT states are always in range | dropped (no variance) |
| delta_norm | constant 1 after quantising to on/off | dropped (no variance) |
| signature_present / signature_age | SWaT has no HMAC signatures - rule-based check only, NOT validated on SWaT | dropped |
| requests_last_1s / 10s (per source) | SWaT has no source addresses; replaced by global event counts | replaced |
| same_payload_recent | a repeated write with no state change is not an event in SWaT | dropped (no variance) |

## Reproducibility

`{"python": "3.14.4", "platform": "Windows-11-10.0.26300-SP0", "numpy": "2.4.3", "pandas": "3.0.5", "sklearn": "1.8.0"}`  seeds: {'model': 42}
