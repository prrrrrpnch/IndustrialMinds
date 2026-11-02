# Physical model v2 - experiment report (CANDIDATE, not promoted)

Changes versus the shipped model: (1) fit on train + validation, (2) 120 s long-context features and cross-sensor consistency residuals, (3) segment-grouped cross-validation with SEGMENT-BALANCED average precision for selection, (4) 'k of the last m windows' persistence with a false-alarm-budget threshold. Everything is chosen on out-of-fold dev scores. **The test block is used for exactly two refits and looks (baseline and selected); it was already seen by the shipped model's revised protocol, so this is held-out, not blind.**

Windows with a full 120 s history: dev (train+val) 161,217, test 28,080. Folds: 5. Run time 778.3 s.

## Cross-validation on train + validation (out-of-fold)

| features | model | segment-balanced AP | AP | ROC-AUC |
|---|---|---|---|---|
| v1_long_resid | hgb **(selected)** | 0.4989 | 0.794 | 0.9252 |
| v1_67 | hgb | 0.4367 | 0.7774 | 0.8944 |
| v1_long | hgb | 0.4291 | 0.7752 | 0.9171 |
| v1_long_resid | rf6 | 0.396 | 0.6878 | 0.9363 |
| v1_67 | rf6 | 0.3563 | 0.6738 | 0.9219 |
| v1_long | rf6 | 0.3469 | 0.6692 | 0.9239 |

Feature sets: `v1_67` = the 67 shipped features (30 s window, no absolute levels); `v1_long` = v1_67 + 120 s long-context features; `v1_long_resid` = v1_67 + 120 s long-context features + cross-sensor consistency residuals. Models: rf6 = random forest depth 6, rf10 = depth 10, hgb = gradient boosting.

## Alarm rules chosen on dev (out-of-fold)

| budget (episodes per benign hour) | rule | k | m | threshold | dev segment-balanced recall |
|---|---|---|---|---|---|
| 0.5 | baseline | 1 | 1 | 0.5068 | n/a |
| 0.5 | selected_without_persistence | 1 | 1 | 0.7880 | n/a |
| 0.5 | selected | 3 | 6 | 0.6418 | 0.391 |
| 1.0 | baseline | 1 | 1 | 0.4914 | n/a |
| 1.0 | selected_without_persistence | 1 | 1 | 0.6895 | n/a |
| 1.0 | selected | 3 | 6 | 0.5595 | 0.405 |

## Held-out TEST block (1-2 Jan)

28,080 windows, 1,061 attack windows, 37.53 benign hours.

### False-alarm budget 0.5 per benign hour (chosen on dev)

| variant | precision | recall | F1 | accuracy | balanced acc. | FP rate | false-alarm episodes / h | segments detected | median latency (s) | ROC-AUC | TN / FP / FN / TP |
|---|---|---|---|---|---|---|---|---|---|---|---|
| refit baseline (v1 features, rf6, no persistence) | 0.4525 | 0.4986 | 0.4744 | 0.9583 | 0.7374 | 0.0237 | 0.986 | 7/10 | 55.0 | 0.7713 | 26,379 / 640 / 532 / 529 |
| selected features, no persistence | 0.4606 | 0.5127 | 0.4853 | 0.9589 | 0.7446 | 0.0236 | 1.173 | 8/10 | 57.5 | 0.8362 | 26,382 / 637 / 517 / 544 |
| selected features + persistence | 0.3277 | 0.5683 | 0.4157 | 0.9396 | 0.7613 | 0.0458 | 1.279 | 8/10 | 62.5 | 0.8362 | 25,782 / 1,237 / 458 / 603 |

### False-alarm budget 1.0 per benign hour (chosen on dev)

| variant | precision | recall | F1 | accuracy | balanced acc. | FP rate | false-alarm episodes / h | segments detected | median latency (s) | ROC-AUC | TN / FP / FN / TP |
|---|---|---|---|---|---|---|---|---|---|---|---|
| refit baseline (v1 features, rf6, no persistence) | 0.4322 | 0.4986 | 0.463 | 0.9563 | 0.7364 | 0.0257 | 1.093 | 7/10 | 55.0 | 0.7713 | 26,324 / 695 / 532 / 529 |
| selected features, no persistence | 0.4001 | 0.5627 | 0.4677 | 0.9516 | 0.7648 | 0.0331 | 1.999 | 8/10 | 52.5 | 0.8362 | 26,124 / 895 / 464 / 597 |
| selected features + persistence | 0.2466 | 0.5853 | 0.347 | 0.9168 | 0.7575 | 0.0702 | 1.919 | 8/10 | 62.5 | 0.8362 | 25,122 / 1,897 / 440 / 621 |

The shipped model for reference (held-out test, same block): precision 0.366, recall 0.263, F1 0.306, accuracy 0.955, 1.79 false-alarm episodes per hour, 6/10 segments, ROC-AUC 0.8245 (`benchmarks/swat_accuracy.json`; its window set differs slightly because v2 windows need a 120 s history).

Plain accuracy is not the headline: attacks are a few percent of windows, so 'never flag' scores about 0.96. Judge by F1, recall at the false-alarm rate, and segments detected.
