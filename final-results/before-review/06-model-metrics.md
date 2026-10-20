# Model Metrics — Before Review

Evaluated on: **SWaT held-out test calendar block (1–2 Jan)** | **28,080 window samples** | recorded by the user's local run,
transcribed here 2026-10-20

---

## CRITICAL FINDING C1 — these metrics could not be re-measured in this environment

The SWaT archive is not in this container and, by the project's own dataset policy, never has been. Everything in this file is
**arithmetic performed on a confusion matrix recorded from a run executed on the user's Windows machine**. No model was scored
against any data during this audit.

What that means in practice:

- The confusion matrix is a transcription. If it were wrong, nothing in this repository would catch it.
- Nobody but the user can reproduce the headline numbers. The reproducibility tooling (`benchmark/run_all.py --data-dir`) is
  correct and would re-measure them — but only on a machine holding a dataset that requires an institutional request to iTrust.
- The project is honest about this in its own docs, which is to its credit, and it is still a single point of failure for every
  accuracy claim the project makes.

**Rating: CRITICAL.** Not because the numbers are suspect — the per-segment detail and the protocol notes are too specific to
be invented — but because an unverifiable metric is an unmanaged metric.

### Protocol caveat recorded with the data

> "test block was used for exactly two refits in the v2 experiment (baseline and selected) and was also seen by the shipped
> model's revised protocol: **held-out, not a pristine blind test**."

The project discloses this itself. It is the right disclosure and it means the numbers below are an optimistic bound.

---

## Overall Performance

| Metric | Score |
|---|---|
| Accuracy | **95.89%** |
| **Majority-class baseline accuracy** | **96.22%** |
| **Accuracy minus baseline** | **−0.33 pp** |
| Balanced accuracy | 74.46% |
| Macro F1 | **0.7319** |
| Weighted F1 | 0.9600 |
| Macro precision / recall | 0.7207 / 0.7446 |
| Weighted precision / recall | 0.9611 / 0.9589 |
| AUC-ROC | **0.8362** |
| Average precision (PR-AUC) | **0.3628** |
| False-alarm episodes per benign hour | 1.173 |

### Read this before quoting anything above

**Accuracy is worse than doing nothing.** A detector that flags nothing scores 96.22% on this block; this model scores 95.89%.
Accuracy is not merely uninformative here, it is *negatively* informative. Any slide that leads with "95.9% accurate" is
misleading, and the number must not appear without the baseline beside it.

**Weighted F1 is the same trap.** 0.96 is the benign class wearing the model's coat: the benign class is 25.5× larger, so the
weighted average is ~96% benign performance. The only honest summary figures are **macro F1 0.7319**, **balanced accuracy
0.7446**, and — most honest of all — the **attack-class F1 of 0.4853**.

**AUC 0.836 vs AP 0.363.** The gap is the imbalance. AUC flatters a rare-positive problem; average precision is the metric that
tracks what an operator experiences. 0.363 against a 0.038 base rate is a real improvement (roughly 10× lift) and is nowhere
near a reliable detector.

---

## Per-Class Breakdown

| Class | Precision | Recall | F1 | Specificity | FPR | FNR | Support |
|---|---|---|---|---|---|---|---|
| **attack** | 0.4606 | 0.5127 | **0.4853** | 0.9764 | 0.0236 | **0.4873** | 1,061 |
| benign | 0.9808 | 0.9764 | 0.9786 | 0.5127 | 0.4873 | 0.0236 | 27,019 |
| *macro avg* | 0.7207 | 0.7446 | 0.7319 | — | — | — | 28,080 |
| *weighted avg* | 0.9611 | 0.9589 | 0.9600 | — | — | — | 28,080 |

The attack class — the only class anyone built this system for — **misses 48.7% of attack windows** and is **wrong on 53.9% of
the windows it flags**.

---

## Confusion Matrix

```
                        PREDICTED
                   benign        attack          total
  TRUE  benign     26,382 (TN)     637 (FP)      27,019
        attack        517 (FN)     544 (TP)       1,061
        total      26,899         1,181          28,080
```

- Class prevalence: attack = **3.78%** of windows. Imbalance **25.5 : 1**.
- At the shipped operating point the model raises **1.17 false-alarm episodes per benign hour**. Over a 24-hour shift that is
  ~28 false alarms. Alarm fatigue is not hypothetical at this rate.

---

## Per-Segment Recall (the number that actually matters operationally)

Window-level metrics over-count the one long attack; segment-level recall is what a plant operator cares about.

**8 of 10 held-out attack segments detected. Median detection latency 57.5 s.**

| Segment | Attack windows | Flagged | Detected | Latency (s) |
|---|---|---|---|---|
| 26 | 120 | 112 | yes | 40.0 |
| 27 | 89 | 77 | yes | 55.0 |
| 28 | **20** | 1 | yes | 60.0 |
| 29 | 96 | 0 | **NO** | — |
| 33 | — | — | **NO** | — |
| *(remaining 5 detected — full table in `_raw/model.json`)* | | | | |

---

## Red Flags

| # | Flag | Detail |
|---|---|---|
| R1 | **Class with F1 < 0.70** | `attack`, F1 **0.4853**. This is the class the system exists to detect. |
| R2 | **Dataset imbalance beyond 70/30** | **96.2 / 3.8**, a ratio of 25.5:1 — far beyond the threshold. |
| R3 | **Accuracy below the do-nothing baseline** | 95.89% vs 96.22%. The headline number is actively misleading. |
| R4 | **Test segment with fewer than 30 samples** | Segment 28 has **20** attack windows. It is counted as "detected" on **one** flagged window — a coin flip dressed as a detection. |
| R5 | **Only 10 attack segments in the test set** | No difference between two models can be shown significant on 10 events. This is exactly why physical model v3 was correctly not promoted. |
| R6 | **Two segments missed entirely** | Segments 29 and 33: zero windows flagged. An attack class the model is blind to, not merely slow on. |
| R7 | **ROC/PR curves cannot be drawn** | Only the scalar AUC was recorded; per-window scores were never persisted. See `screenshots/roc-curve.png`. |
| R8 | **Test block is not blind** | Disclosed by the project: used for two refits and seen by the shipped model's protocol. Treat every figure as an optimistic bound. |

---

## Measured in THIS environment (these numbers are real, not transcribed)

| Property | Value |
|---|---|
| Weights file | 0.29 MB (`physical_model_v2.joblib`) |
| Load time | **0.12 s** (plus ~1.0 s to import scikit-learn/numpy/joblib) |
| Process RSS after load | 149 MB (scikit-learn + numpy dominate) |
| Middleware process RSS, steady state | **169.2 MB** |
| Inference latency, normal window | p50 **0.64 ms**, p95 2.27 ms, p99 5.23 ms, max 5.33 ms |
| Inference latency, flagged window (runs stage attribution) | p50 **1.72 ms**, p95 2.24 ms, max 4.58 ms |
| Throughput | **863 assessments/s** single-threaded |
| Warm-up before first verdict | 120 s of telemetry |
| Healthy-plant probability (synthetic nominal) | 0.249 against a 0.788 threshold |

Inference cost is a non-issue: the model is three orders of magnitude faster than the 1 Hz telemetry it consumes. Cold start
of the whole middleware is 1.31 s, almost all of it importing scikit-learn rather than loading weights.

---

## Other models in the repository (recorded, all correctly rejected)

| Model | Held-out result | Decision |
|---|---|---|
| Cyber ML candidate | test ROC-AUC 0.63, F1 0.137 | **Not promoted.** Correct — it is barely better than chance. |
| Learned orchestrator fusion | val AUC 0.93, **test AUC 0.68** vs physical-alone 0.83 | **Not promoted.** The val/test gap is textbook overfitting and was caught. |
| Physical v3 | test F1 0.352 vs v2-recipe refit 0.432; 6/10 vs 8/10 segments | **Not promoted.** Correct. |

Three rejected models with recorded evidence is the strongest signal of methodological health in this repository.

---

## Not computable, and why

| Metric | Why not |
|---|---|
| Fresh held-out evaluation | SWaT archive absent from this environment (CRITICAL C1 above) |
| ROC / PR curve images | Only the scalar AUC was recorded; per-window scores never saved |
| MAE / RMSE | No regression component; the RUL regressor was removed deliberately |
| Per-class metrics for the cyber branch | It has no classifier. Its checks are specification conformance (HMAC, whitelist, rate limit), which have no error rate to measure, and SWaT contains no network traffic to validate them against. The "100% accuracy" reported for rules in `benchmarks/latest.json` is a **regression test on self-authored scenarios**, not detection performance, and must never be quoted as such. |

---

## Metrics verdict

The model's numbers are **honestly produced and badly presented**. The protocol is better than most published SWaT work — per
segment, calendar-block splits, no point-adjust inflation, with limitations disclosed. The failure is in which numbers reach
the surface: `README.md` and the dashboard both lead with figures whose benign-dominated denominators hide an attack-class F1
of 0.49. Fix the presentation, not the measurement.
