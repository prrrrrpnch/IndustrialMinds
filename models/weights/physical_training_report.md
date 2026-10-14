# PhysicalModel - SWaT-only training report (CANDIDATE)

## Scope and honesty notes

* Trained and evaluated on **SWaT only**; inputs are limited to the twin's SWaT-backed points (10 sensors, 8 actuators) so the model can run live.
* Window label = attack flag of the window's last second (one binary flag per row). Segments whose attacked points are not among the twin's 18 inputs are invisible by construction; the per-segment table says which segments were visible at all.
* The old health/RUL output is removed: SWaT has no degradation labels, so it cannot be derived and is never invented.
* Calendar drift between days exists in SWaT; held-out blocks are later days than training, so drift counts against the model (honestly).

## Data

* rows 946,719 after de-duplication; segments 35; chunks 2

* windows: 30 s, stride 5 s; total 189,333, attack 10,920

| block | windows | attack windows | segments |
|---|---|---|---|
| train | 126,715 | 1,733 | 17 |
| val | 34,538 | 8,126 | 8 |
| test | 28,080 | 1,061 | 10 |

## Regularisation and thresholds (chosen WITHOUT the test block)

> REVISION NOTE: this selection protocol (feature variants, false-alarm-budget thresholds, exclusion of dominating segments) was introduced AFTER run 1 showed validation dominated by one segment and a large train/test gap. The test block is therefore not pristine for this revised pipeline.

Validation selection excludes segment(s) [22] (each holds > 50 % of the validation attack windows).

| variant | max_depth | min_samples_leaf | validation AP |
|---|---|---|---|
| full | 6 | 10 | 0.3873 |
| full | 6 | 40 | 0.3554 |
| full | 10 | 10 | 0.3318 |
| full | 10 | 40 | 0.3859 |
| drift_robust | 6 | 10 | 0.6946 |
| drift_robust | 6 | 40 | 0.6929 |
| drift_robust | 10 | 10 | 0.6919 |
| drift_robust | 10 | 40 | 0.6917 |

Chosen: {'variant': 'drift_robust', 'max_depth': 6, 'min_samples_leaf': 10}. Isolation Forest threshold 0.6108 (99.5th pct of train-normal scores); classifier threshold 0.5578 (false-alarm budget 1.0 alarm episodes per normal hour on validation).
Variant test ROC-AUC, shown for transparency only (never used for selection): {'full': 0.5262169683434623, 'drift_robust': 0.8339621132320786}

## Held-out TEST block (1-2 Jan) - window-level confusion matrices

**Isolation Forest**

| | predicted normal | predicted attack |
|---|---|---|
| actual normal | 26910 | 109 |
| actual attack | 1048 | 13 |

precision 0.107, recall 0.012, F1 0.022, ROC-AUC 0.633, AP 0.052

**Supervised classifier**

| | predicted normal | predicted attack |
|---|---|---|
| actual normal | 26263 | 756 |
| actual attack | 785 | 276 |

precision 0.267, recall 0.260, F1 0.264, ROC-AUC 0.826, AP 0.313

**Combined (either)**

| | predicted normal | predicted attack |
|---|---|---|
| actual normal | 26165 | 854 |
| actual attack | 775 | 286 |

precision 0.251, recall 0.270, F1 0.260

**Baseline: flag everything**

| | predicted normal | predicted attack |
|---|---|---|
| actual normal | 0 | 27019 |
| actual attack | 0 | 1061 |

precision 0.038, recall 1.000, F1 0.073

Test false alarms: 854 normal windows flagged = 91 alarm episodes over 37.53 normal hours (2.425 per hour).

## Validation block (for transparency)

| model | precision | recall | F1 | ROC-AUC |
|---|---|---|---|---|
| isolation_forest | 0.831 | 0.079 | 0.143 | 0.920 |
| classifier | 0.949 | 0.393 | 0.556 | 0.901 |
| combined_either | 0.922 | 0.423 | 0.580 | n/a |

ROC-AUC train / val / test (classifier): 0.907 / 0.901 / 0.826

## Per-segment detection (combined flag)

**val**: 8 segments; 6 visible in the twin's sensors (shift > 3 sd or outside the measured envelope); 4 detected, of which 4 among the visible ones

| segment | start | rows | windows | flagged | first detection (s) | max shift (sd) | visible | envelope hit |
|---|---|---|---|---|---|---|---|---|
| 18 | 2015-12-30 01:42:34 | 697 | 140 | 132 | 0.000 | 3.83 | True | True |
| 19 | 2015-12-30 09:51:08 | 321 | 64 | 0 | n/a | 1.81 | False | False |
| 20 | 2015-12-30 10:01:50 | 612 | 122 | 0 | n/a | 2.19 | False | False |
| 21 | 2015-12-30 17:04:56 | 1445 | 289 | 284 | 3.000 | 1.32 | True | True |
| 22 | 2015-12-31 01:17:08 | 35900 | 7180 | 2794 | 1746.000 | 12.31 | True | True |
| 23 | 2015-12-31 15:32:00 | 121 | 24 | 0 | n/a | 3.45 | True | False |
| 24 | 2015-12-31 15:47:40 | 1171 | 234 | 230 | 4.000 | 2.28 | True | True |
| 25 | 2015-12-31 22:05:34 | 367 | 73 | 0 | n/a | 3.43 | True | False |

**test**: 10 segments; 7 visible in the twin's sensors (shift > 3 sd or outside the measured envelope); 7 detected, of which 6 among the visible ones

| segment | start | rows | windows | flagged | first detection (s) | max shift (sd) | visible | envelope hit |
|---|---|---|---|---|---|---|---|---|
| 26 | 2016-01-01 10:36:00 | 601 | 120 | 112 | 42.000 | 3.47 | True | True |
| 27 | 2016-01-01 14:21:12 | 444 | 89 | 10 | 55.000 | 2.5 | False | False |
| 28 | 2016-01-01 17:12:40 | 101 | 20 | 0 | n/a | 2.44 | False | False |
| 29 | 2016-01-01 17:18:56 | 481 | 96 | 5 | 51.000 | 3.43 | True | False |
| 30 | 2016-01-01 22:16:01 | 540 | 108 | 0 | n/a | 3.56 | True | False |
| 31 | 2016-01-02 11:17:02 | 469 | 94 | 71 | 50.000 | 3.98 | True | True |
| 32 | 2016-01-02 11:31:38 | 281 | 56 | 43 | 69.000 | 5.64 | True | True |
| 33 | 2016-01-02 11:43:48 | 401 | 80 | 0 | n/a | 2.77 | False | False |
| 34 | 2016-01-02 11:51:42 | 297 | 60 | 43 | 55.000 | 4.09 | True | False |
| 35 | 2016-01-02 13:13:02 | 1690 | 338 | 2 | 1330.000 | 3.35 | True | False |

## Operating curve on the TEST block (threshold set on validation; Isolation Forest threshold fixed)

| setting | classifier thr | precision | recall | F1 | false-alarm episodes / normal hour | segments detected (of 10) | visible segments detected |
|---|---|---|---|---|---|---|---|
| budget 0.25 /h | 0.627 | 0.390 | 0.260 | 0.312 | 1.519 | 6 | 5 |
| budget 0.5 /h | 0.601 | 0.365 | 0.263 | 0.306 | 1.759 | 6 | 5 |
| budget 1.0 /h | 0.558 | 0.251 | 0.270 | 0.260 | 2.425 | 7 | 6 |
| budget 2.0 /h | 0.483 | 0.294 | 0.499 | 0.370 | 3.358 | 8 | 7 |
| budget 4.0 /h | 0.478 | 0.289 | 0.531 | 0.374 | 4.583 | 9 | 7 |
| val-F1-optimal (run-1 rule) | 0.540 | 0.238 | 0.293 | 0.263 | 2.638 | 7 | 6 |

## Measured-envelope RULE validated on held-out data

Rule: a sensor outside its measured train-normal envelope [p0.1, p99.9] widened by 10 % is a violation. This is a RULE validated on real SWaT, not a model.

| block | normal rows outside | false-alarm episodes / normal hour | attack-row recall | segments with any row outside |
|---|---|---|---|---|
| train | 234 of 624,918 (0.04%) | 0.046 | 30.02% | 7 of 17 |
| val | 177 of 132,085 (0.13%) | 0.109 | 83.26% | 4 of 8 |
| test | 3,024 of 135,095 (2.24%) | 0.853 | 21.58% | 3 of 10 |

## Measured bounds (train-block normal rows)

| sensor | min | p0.1 | median | p99.9 | max | envelope lo | envelope hi |
|---|---|---|---|---|---|---|---|
| LIT101 | 120.62 | 124.39 | 526.07 | 816.10 | 1000.00 | 55.22 | 885.28 |
| FIT101 | 0.00 | 0.00 | 2.49 | 2.69 | 2.75 | 0.00 | 2.95 |
| AIT202 | 6.00 | 8.27 | 8.37 | 8.96 | 8.99 | 8.20 | 9.03 |
| FIT201 | 0.00 | 0.00 | 2.44 | 2.48 | 2.80 | 0.00 | 2.73 |
| LIT301 | 132.82 | 136.34 | 918.39 | 1013.68 | 1200.00 | 48.61 | 1101.42 |
| DPIT301 | 0.00 | 0.03 | 19.82 | 20.80 | 45.00 | 0.00 | 22.88 |
| LIT401 | 130.39 | 132.31 | 891.93 | 1001.05 | 1003.93 | 45.44 | 1087.92 |
| AIT402 | 150.29 | 150.91 | 163.68 | 233.89 | 297.03 | 142.61 | 242.19 |
| PIT501 | 8.89 | 9.15 | 252.00 | 259.71 | 264.64 | 0.00 | 284.77 |
| FIT501 | 0.00 | 0.00 | 1.72 | 1.75 | 1.76 | 0.00 | 1.93 |

## Top features (classifier importance)

| feature | importance |
|---|---|
| P203.frac_on | 0.1526 |
| P205.state | 0.149 |
| LIT101.last | 0.0671 |
| LIT101.std | 0.0602 |
| LIT101.range | 0.0441 |
| FIT101.last | 0.0372 |
| FIT201.last | 0.0357 |
| P203.toggles | 0.0329 |
| DPIT301.mean | 0.0301 |
| AIT202.range | 0.0299 |
| LIT301.delta | 0.0298 |
| FIT201.mean | 0.0287 |
| LIT101.slope | 0.0282 |
| LIT101.mean | 0.0257 |
| LIT301.range | 0.0247 |

## Feature provenance

| feature | SWaT source / derivation | status |
|---|---|---|
| <sensor>.last/mean/std/slope/range/delta (10 sensors x 6) | z-scored 1 Hz sensor columns LIT101, FIT101, AIT202, FIT201, LIT301, DPIT301, LIT401, AIT402, PIT501, FIT501 over a 30 s trailing window (mean/std from train-block normal rows) | real (SWaT columns), derived statistics |
| <actuator>.state/toggles/frac_on (8 actuators x 3) | actuator state columns P101, P203, P205, MV302, P302, P402, UV401, P501 mapped 1->off, 2->on; valve transit state 0 forward-filled | derived |
| flow_balance_101_201 | difference of window-mean z-scores of FIT101 and FIT201 (stage 1 -> stage 2 continuity) | derived |
| sensors_outside_envelope, max_envelope_excess | distance outside the MEASURED train-normal envelope [p0.1, p99.9] +10 % | derived from measured bounds |

Inputs NOT used:

| input | reason |
|---|---|
| MV101 | NaN for the whole 7-day normal period in the archive (only present in the attack period) |
| MV503 | twin-only synthetic actuator: no SWaT column, covered by rules only |
| health index / RUL | SWaT has no degradation or run-to-failure labels; not derivable, so removed (never invented) |
| 33 other SWaT columns (P102, AIT201, FIT301, MV301, PIT502, ...) | the live twin has no such points, so a model using them could not run live |

## Reproducibility

`{"python": "3.14.4", "platform": "Windows-11-10.0.26300-SP0", "numpy": "2.4.3", "pandas": "3.0.5", "sklearn": "1.8.0"}`
