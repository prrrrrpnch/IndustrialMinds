# Twin domain-gap report

> **TWIN MEASUREMENT (synthetic plant calibrated to SWaT) - NOT SWaT detection performance**

Weights `ea1d9ee6-physical_model.joblib` (variant `drift_robust`).

## Nominal operation, 4.0 simulated hours, sensor noise on

* plant_state seconds: {'WARMING_UP': 29, 'NORMAL': 14355, 'ALERT': 16}
* learned-model flag: 16 s (0.11%), 1 alarm episodes = **0.25 per hour**
* measured-envelope rule: 0 violating seconds, **0.0 episodes per hour**
* Isolation Forest anomaly score p50/p95/p99/max: [0.5315, 0.5537, 0.5653, 0.6385] against threshold 0.6108
* UF backwashes: 1

## Synthetic actuator attacks (10 min settle, then the change, 15 min observed)

| scenario | alarm s before attack | first model flag (s after) | first envelope violation (s after) |
|---|---|---|---|
| p101_stop (raw pump stops) | 0 | 3 | 4 |
| acid_overdose (HCl max, raw pump low) | 0 | 2 | 2 |
| chlorine_breakthrough (NaOCl max, UV off) | 0 | 3 | 8 |
| ro_deadhead (RO pump max, reject valve shut) | 0 | 1 | 1 |
| uf_valve_shut (UF feed valve closes) | 0 | 4 | 17 |

A value of `None` means no alarm within the observation window.
