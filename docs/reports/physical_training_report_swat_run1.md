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

| max_depth | min_samples_leaf | validation AP |
|---|---|---|
| 6 | 10 | 0.2676 |
| 6 | 40 | 0.2734 |
| 10 | 10 | 0.4149 |
| 10 | 40 | 0.431 |

Chosen: {'max_depth': 10, 'min_samples_leaf': 40}. Isolation Forest threshold 0.6348 (99.5th pct of train-normal scores); classifier threshold 0.4627 (max validation F1 = 0.714).

## Held-out TEST block (1-2 Jan) - window-level confusion matrices

**Isolation Forest**

| | predicted normal | predicted attack |
|---|---|---|
| actual normal | 27005 | 14 |
| actual attack | 1060 | 1 |

precision 0.067, recall 0.001, F1 0.002, ROC-AUC 0.672, AP 0.058

**Supervised classifier**

| | predicted normal | predicted attack |
|---|---|---|
| actual normal | 23632 | 3387 |
| actual attack | 841 | 220 |

precision 0.061, recall 0.207, F1 0.094, ROC-AUC 0.663, AP 0.140

**Combined (either)**

| | predicted normal | predicted attack |
|---|---|---|
| actual normal | 23622 | 3397 |
| actual attack | 841 | 220 |

precision 0.061, recall 0.207, F1 0.094

**Baseline: flag everything**

| | predicted normal | predicted attack |
|---|---|---|
| actual normal | 0 | 27019 |
| actual attack | 0 | 1061 |

precision 0.038, recall 1.000, F1 0.073

Test false alarms: 3397 normal windows flagged = 105 alarm episodes over 37.53 normal hours (2.798 per hour).

## Validation block (for transparency)

| model | precision | recall | F1 | ROC-AUC |
|---|---|---|---|---|
| isolation_forest | 0.992 | 0.290 | 0.449 | 0.930 |
| classifier | 0.619 | 0.842 | 0.714 | 0.812 |
| combined_either | 0.625 | 0.866 | 0.726 | n/a |

ROC-AUC train / val / test (classifier): 1.000 / 0.812 / 0.663

## Per-segment detection (combined flag)

**val**: 8 segments; 6 visible in the twin's sensors (shift > 3 sd or outside the measured envelope); 5 detected, of which 4 among the visible ones

| segment | start | rows | windows | flagged | first detection (s) | max shift (sd) | visible | envelope hit |
|---|---|---|---|---|---|---|---|---|
| 18 | 2015-12-30 01:42:34 | 697 | 140 | 132 | 0.000 | 3.83 | True | True |
| 19 | 2015-12-30 09:51:08 | 321 | 64 | 48 | 1.000 | 1.81 | False | False |
| 20 | 2015-12-30 10:01:50 | 612 | 122 | 0 | n/a | 2.19 | False | False |
| 21 | 2015-12-30 17:04:56 | 1445 | 289 | 284 | 3.000 | 1.32 | True | True |
| 22 | 2015-12-31 01:17:08 | 35900 | 7180 | 6345 | 3941.000 | 12.31 | True | True |
| 23 | 2015-12-31 15:32:00 | 121 | 24 | 0 | n/a | 3.45 | True | False |
| 24 | 2015-12-31 15:47:40 | 1171 | 234 | 225 | 4.000 | 2.28 | True | True |
| 25 | 2015-12-31 22:05:34 | 367 | 73 | 0 | n/a | 3.43 | True | False |

**test**: 10 segments; 7 visible in the twin's sensors (shift > 3 sd or outside the measured envelope); 5 detected, of which 5 among the visible ones

| segment | start | rows | windows | flagged | first detection (s) | max shift (sd) | visible | envelope hit |
|---|---|---|---|---|---|---|---|---|
| 26 | 2016-01-01 10:36:00 | 601 | 120 | 112 | 42.000 | 3.47 | True | True |
| 27 | 2016-01-01 14:21:12 | 444 | 89 | 0 | n/a | 2.5 | False | False |
| 28 | 2016-01-01 17:12:40 | 101 | 20 | 0 | n/a | 2.44 | False | False |
| 29 | 2016-01-01 17:18:56 | 481 | 96 | 4 | 21.000 | 3.43 | True | False |
| 30 | 2016-01-01 22:16:01 | 540 | 108 | 0 | n/a | 3.56 | True | False |
| 31 | 2016-01-02 11:17:02 | 469 | 94 | 62 | 160.000 | 3.98 | True | True |
| 32 | 2016-01-02 11:31:38 | 281 | 56 | 4 | 39.000 | 5.64 | True | True |
| 33 | 2016-01-02 11:43:48 | 401 | 80 | 0 | n/a | 2.77 | False | False |
| 34 | 2016-01-02 11:51:42 | 297 | 60 | 38 | 110.000 | 4.09 | True | False |
| 35 | 2016-01-02 13:13:02 | 1690 | 338 | 0 | n/a | 3.35 | True | False |

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
| FIT101 | 0.00 | 0.00 | 2.49 | 2.69 | 2.75 | -0.27 | 2.95 |
| AIT202 | 6.00 | 8.27 | 8.37 | 8.96 | 8.99 | 8.20 | 9.03 |
| FIT201 | 0.00 | 0.00 | 2.44 | 2.48 | 2.80 | -0.25 | 2.73 |
| LIT301 | 132.82 | 136.34 | 918.39 | 1013.68 | 1200.00 | 48.61 | 1101.42 |
| DPIT301 | 0.00 | 0.03 | 19.82 | 20.80 | 45.00 | -2.05 | 22.88 |
| LIT401 | 130.39 | 132.31 | 891.93 | 1001.05 | 1003.93 | 45.44 | 1087.92 |
| AIT402 | 150.29 | 150.91 | 163.68 | 233.89 | 297.03 | 142.61 | 242.19 |
| PIT501 | 8.89 | 9.15 | 252.00 | 259.71 | 264.64 | -15.91 | 284.77 |
| FIT501 | 0.00 | 0.00 | 1.72 | 1.75 | 1.76 | -0.17 | 1.93 |

## Top features (classifier importance)

| feature | importance |
|---|---|
| AIT402.mean | 0.1353 |
| AIT402.last | 0.1213 |
| PIT501.last | 0.0759 |
| PIT501.mean | 0.0617 |
| AIT202.mean | 0.0584 |
| AIT202.last | 0.0505 |
| FIT501.mean | 0.0443 |
| max_envelope_excess | 0.0364 |
| sensors_outside_envelope | 0.0349 |
| FIT501.last | 0.0344 |
| LIT401.mean | 0.0201 |
| LIT101.mean | 0.0194 |
| LIT401.last | 0.0193 |
| LIT101.last | 0.0189 |
| DPIT301.mean | 0.018 |

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
