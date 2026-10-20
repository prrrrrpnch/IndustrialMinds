# Model card: live physical model (PhysicalModelV2)

Every number here was measured on the held-out SWaT test block and is reproduced by
`python -m benchmark.run_all --data-dir <SWaT archive>`. The short machine-readable form of this page is
`models.physical_model_v2.model_card()`, which the middleware publishes to the dashboard at startup, so the panel always
describes the model that is actually running, environment overrides included.

## What it is

| | |
|---|---|
| Name | `PhysicalModelV2` (`models/physical_model_v2.py`), weights `models/weights/physical_model_v2.joblib` |
| Job | Decide whether the *plant state* looks like it is under attack, from telemetry alone |
| Input | The last 120 s of the plant at 1 Hz: 10 sensors and 8 actuators, the points the live twin provides |
| Features | 117: 30 s dynamics (no absolute levels, which drift by day in SWaT), 120 s long-context slope/std/net-change, and cross-sensor consistency residuals from ridge models fitted on normal windows only |
| Detector | One gradient-boosted classifier (HistGradientBoosting). No persistence rule: it was measured and made F1 worse |
| Output | An attack probability, plus `threat_flag = probability > threshold` |
| Trained on | SWaT train + validation blocks, selected by segment-grouped cross-validation |

## What it is allowed to do

**It is advisory and cannot block anything.** A flag becomes an `ALERT`, the orchestrator still forwards the command, and only
the deterministic rules produce a `DROP`. This is deliberate: a detector with the precision measured below must not be wired to
a shut-off. It also abstains rather than guessing: on missing or mismatched weights, during its 120 s warm-up, or on any internal
error it reports `NO_MODEL` / `WARMING_UP` / `ERROR` with `threat_flag` false, and never raises into the middleware.

## Measured performance

Held-out SWaT test block: 28,080 windows, 1,061 of them attack windows, 37.53 benign hours.

| Operating point | Threshold | Precision | Recall | F1 | Alerts / benign hour | Attack segments | Median detection |
|---|---|---|---|---|---|---|---|
| **balanced** (shipped, 0.5/h budget) | 0.7880 | 0.461 | 0.513 | **0.485** | 1.17 | 8 of 10 | 57.5 s |
| sensitive (1.0/h budget) | 0.6895 | 0.400 | 0.563 | 0.468 | 2.00 | 8 of 10 | 52.5 s |

ROC-AUC 0.836, average precision 0.363, balanced accuracy 0.745.

Select an operating point with `IM_PHYSICAL_SENSITIVITY=balanced|sensitive`; only measured points are offered, so the list can
never contain an invented trade-off. `IM_PHYSICAL_THRESHOLD=<probability>` still overrides it with a raw number if you need one.

**Plain accuracy is 0.959 and is not the headline.** A detector that never flags anything scores 0.962 on this block, because
attacks are a few percent of windows. Judge it by F1, recall at a stated false-alarm rate, and attack segments detected.

## Why a flag happens

When the model flags, it also reports *where*. The 18 live channels are grouped by plant stage; the window is rescored five
times, each time with one stage's channels replaced by those of the most recent window the model itself called normal, and the
drop in probability is that stage's contribution. The result is a contrastive explanation — what changed since the plant last
looked fine — needing no training data at run time and costing a few milliseconds. Alongside it the report lists the sensors
furthest from measured normal, which works even before a reference exists. `suspect_stage` reaches the `ALERT` reason, the
blocked-attack log and the Packet Tracer.

The explanation describes the model's own behaviour on this window. It is not a causal claim about the plant.

## Known limits

- **It catches about half of real attack windows.** It is a second opinion, not a gate.
- **Roughly one false alarm per hour** of normal operation at the shipped point. On a real plant that is a lot.
- **The held-out block is not blind.** Earlier experiments saw it, so it is held out, not a pristine test.
- **Only 10 attack segments** in that block, so the confidence intervals are wide and no small difference between models is
  provable. This is why physical model v3 was not promoted despite a higher cross-validation score.
- **The twin is not SWaT.** It is calibrated to measured SWaT statistics, but numbers measured on the twin are twin numbers.
- **It cannot see an attacker who bypasses the middleware** and writes to the PLC directly. Only the sensor-envelope rule and
  the plant's own behaviour reveal that afterwards.
- **It needs 120 s of history** after every start or telemetry gap, and abstains until then.
- **Analyser sensors (AIT202, AIT402) have wide normal ranges**, so a moderate step on those alone may not be flagged.

## Not used, and why

A cyber ML model and a learned orchestrator fusion were both trained on real SWaT and both rejected on held-out evidence
(`docs/reports/cyber_training_report_swat.md`, `docs/reports/fusion_training_report_swat.md`). Physical model v3 was built,
measured and also not promoted. Those decisions, and the numbers behind them, are kept in the repository rather than removed.
