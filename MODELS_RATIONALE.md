# Industrial Mind - Model Rationale

> **Status (Phase 5):** section 2 (CyberModel) describes the ORIGINAL synthetic 13-feature Isolation Forest and is
> superseded: the CyberModel is now trained on SWaT only, with an 8-feature schema derived from actuator state
> changes plus a supervised head. See `swat/cyber_events.py` (feature provenance) and
> `models/candidates/cyber_training_report.md` (generated). The physical-model section stays until Phase 6.

This document explains why the two learned models were added the way they
were, the mathematics behind them, how they meet the sub-10 ms edge budget,
and what they can and cannot be trusted for.

## 1. Architecture decision: models run alongside the rules, not instead of them

```
                      +-- Cyber branch ----------------------------------+
SCADA command ------> |  Cyber Agent rules (HMAC, whitelist, rate,      | -- gate --+
(signed FC16 frame)   |  replay)      +  CyberModel anomaly score       | -- info   |
                      +--------------------------------------------------+           v
                      +-- Physical branch -------------------------------+     Orchestrator
PLC telemetry ------> |  Physical Agent rules (bounds, rate-of-change,  | --> PASS / DROP
(10 machines, 5 Hz)   |  cross-register) + PhysicalModel health / RUL   | -- info
                      +--------------------------------------------------+
                         both branches run concurrently in MultiModelPipeline
```

The deterministic agents remain the hard gate. Reasons:

* **Guarantees.** "A command whose HMAC does not verify never reaches the
  PLC" and "a value outside 0-100 PSI is always dropped" are proofs, not
  probabilities. A learned model can only make them probabilistic.
* **No attack corpus.** There is no labelled history of real attacks on this
  plant. A supervised attack classifier would learn our synthetic attacks,
  not the next real one.
* **Safety-of-life.** For a PLC, a model false negative is a physical event.
  Learned scores are therefore advisory by default (MONITOR mode).
  `IM_CYBER_MODEL_ENFORCE=1` lets a CyberModel threat flag additionally DROP
  commands the rules allowed (`ML_ANOMALY`); it can never PASS what the rules
  dropped.

The checklist's "rename agents to models" was deliberately not applied:
`CyberModel` and `PhysicalModel` are new classes next to the existing agents.

## 2. CyberModel - Isolation Forest (unsupervised)

**Why Isolation Forest and not XGBoost.** XGBoost is supervised and needs
labelled attack traffic. Isolation Forest learns only what normal operator
traffic looks like and scores everything else by how easy it is to isolate,
which is the right fit when attacks are rare, unlabelled and novel.

**Features (13 per command).** Function code one-hot, register known,
value position in range, distance outside range, |requested - current| / span,
signature present, signature age / freshness window, log inter-arrival time
from the same source, requests in the last 1 s and 10 s from the source, and
whether the same (register, value) was sent by the source in the last 2 s.
The HMAC secret is never a feature.

**Mathematics.** Each isolation tree recursively splits on a random feature
at a random threshold. An anomaly is isolated in few splits. For a sample x
with average path length E[h(x)] over T trees grown on psi = 256 samples:

    c(n)  = 2 (ln(n-1) + 0.5772) - 2 (n-1)/n          (expected BST search path)
    s(x)  = 2 ^ ( - E[h(x)] / c(psi) )                 s in (0, 1]

s near 1 means anomalous; s well below 0.5 means normal. The threat threshold
is the 99.5th percentile of s on training traffic (0.6485 for the shipped
weights), so the expected false-positive rate on normal traffic is about 0.5%.

**Measured (held-out normal traffic, different seed):** false-positive rate
0.6% on 4,000 commands. A 12-command unsigned burst scores 0.75 (flagged).
In ENFORCE mode a fast signed burst that stays under the 5 req/s hard limit
is flagged at 0.67 and dropped as `ML_ANOMALY`.

## 3. PhysicalModel - sliding-window Random Forest for RUL and health

**Window.** A ring buffer shaped `[window_size=60, 10 machines, 3 features]`
(60 samples x 0.2 s poll = 12 s). Per sample and machine:

    v_t   = (x_t - min) / span                        normalised value
    d1_t  = v_t - v_{t-1}                             first difference
    d2_t  = v_t - 2 v_{t-1} + v_{t-2}                 second difference

**Why second differences handle drift and non-stationarity.** Calibration
drift adds a + b*t to the signal; a setpoint ramp adds a linear segment.
The second difference of any linear function is exactly zero, so both vanish,
while vibration noise and impulsive spikes (the wear signature) pass through
(amplified by sqrt(6) for white noise). Remaining features are robust
statistics so a single outlier cannot move them:

* scale = 1.4826 * MAD(d2) (consistent estimator of sigma under Gaussian noise)
* std(d2), 99th percentile |d2|, fraction |d2| > 2% and > 5% of span
* noise growth = std(d2 second half) / std(d2 first half)
* kurtosis(d2) (spikiness), log10 of the robust scale
* mean |d1 - median(d1)| (deviation from the window's own slope, so a steady
  ramp contributes zero)

**Why Random Forest and not LSTM.** The project chose scikit-learn only.
Beyond that: there are ~23k training windows, too few for a sequence model to
beat engineered robust features; a forest is deterministic for a fixed seed;
it captures the non-linear, threshold-like relation between noise growth,
spike rate and remaining life without feature scaling; and it predicts all
10 machines in well under a millisecond on CPU.

**Outputs.** RUL in hours (0-500 h horizon) and a normalised health index:

    HI = clip(RUL / 500, 0, 1)      1.0 = as new, 0.0 = failure imminent

Health states in the pipeline report: HEALTHY (min HI >= 0.6), DEGRADING
(>= 0.3), CRITICAL (< 0.3).

**Measured (held-out trajectories, different seed, 6,960 windows):**

| Metric | Value |
|---|---|
| Health-index MAE | 0.12 |
| Health-index R² | 0.71 |
| RUL MAE | 59.8 h (of 500 h) |
| Mean HI, healthy machines | 0.92 (5th percentile 0.78) |
| Mean HI, near failure (true HI < 0.1) | 0.23 |

Robustness tests (`tests/test_models.py`): strong calibration drift ->
HI 0.96, non-stationary noise -> 0.91, continuous setpoint ramps -> 0.98,
near-failure channel -> 0.20, and the single failing machine among 10 is
ranked lowest.

## 4. Determinism

All data is generated by `models/telemetry_generator.py` from fixed seeds
(training 11 and 101, validation 12 and 202) and both estimators use
`random_state=42`. `python -m models.train_models` reproduces the same
weights and the same `models/weights/training_report.json`.

## 5. Latency (edge budget < 10 ms per message)

scikit-learn's `predict()`/`score_samples()` carry 4-6 ms of fixed overhead
per call; scoring one command that way would use most of the budget. Both
models are therefore evaluated through `models/tree_inference.py`, which packs
the fitted trees into NumPy arrays and walks all trees at once. Output
equality with sklearn is asserted (max difference 2e-16 for Isolation Forest,
2e-13 for the forest).

| Path | sklearn | packed |
|---|---|---|
| Isolation Forest, 1 command | 6.3 ms | 0.11-0.15 ms |
| Random Forest, 10 machines | 3.8 ms | 0.45 ms |

Health is recomputed at most once per second (`IM_HEALTH_REFRESH_SECONDS`),
because RUL changes over hours, not milliseconds.

Middleware stress test (`tests/test_middleware_efficiency.py`, 40,000
messages at 400 msg/s, 2-core VM): mean 0.88 ms, p95 1.51 ms, p99 2.36 ms,
capacity 1,125 msg/s, end-to-end p99 3.8 ms, memory growth 0.13 MB per 1,000
messages after warm-up, all attack payloads dropped, all legitimate payloads
passed.

## 6. Limitations

* Both models are trained on **synthetic** data. Before trusting the health
  index on a real plant, retrain `PhysicalModel` on that plant's telemetry and
  failure history, and recalibrate the CyberModel threshold on its traffic.
* The PLC simulation has no wear model, so live health stays near 1.0; the
  degradation path is exercised by tests and the stress test's synthetic
  telemetry.
* RUL hours are a relative scale from the synthetic run-to-failure horizon,
  not calibrated engineering hours.
* There is no OPC-UA server in this project; the Modbus holding-register map
  (addresses 0-9 plus the signed-frame window at 100) is the only address
  space.
