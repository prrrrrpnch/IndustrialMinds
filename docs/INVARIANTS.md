# Physical-invariant rules

An **invariant** is a relationship between the plant's own signals that holds in normal operation because of physics or of the control
logic. When one breaks, the readings cannot all be true at once: a spoofed or frozen sensor, a pump that does not do what its state says, a
tank that gains water nobody pumped. The rules are **learned from normal data only** (no attack labels, no classifier), are **deterministic**,
and are **advisory**: a violation raises an ALERT (the command is still forwarded), it never blocks. The rule layers still decide DROP.

Code: `swat/invariants.py` (engine, shared by evaluation and live), `models/invariant_monitor.py` (live side), `tools/fit_invariants.py`
(learn and measure), `tools/live_invariants_check.py` (prove the wiring on the real stack). Tests: `tests/test_invariants.py`.

## The three families (all over the 18 signals the model already reads)

| family | rule | example |
|---|---|---|
| **rate** | a sensor cannot move faster than it ever did in normal operation (10 s and 60 s horizons) | `LIT101 never changed by more than X mm in 10 s` |
| **state** | while an actuator has held one state for at least 30 s, a sensor stays inside the band it always had in that state | `while P101 is steadily ON, FIT201 stays within 2.43 to 2.57 m3/h` |
| **balance** | a tank's level change over 60 s is explained by the flows and pump states around it (mass balance) | `the change of LIT101 over 60 s is explained by FIT101, FIT201, P101 (within +-X mm)` |

Every invariant yields an **excess** `e(t)`: at most 1 inside the range normal data showed, above 1 outside. The same scale for all families.
The excess must persist (rate 2 s, state 10 s, balance 20 s) so one noisy second is not a violation. The score is `V(t)` = the largest
persistent excess; the rule fires when `V(t) > theta`. `theta = 1` means "beyond everything normal training ever showed".

## How the rules are kept honest

- Proposals are fitted on the first 75 % of the normal rows and **validated on the last 25 %, held out in time**. An invariant that already
  misfires on unseen normal rows is dropped, and the reason is written to the report. Survivors are refitted on all normal rows.
- A state band is kept only if it is materially **tighter than the sensor's marginal range** (otherwise it is just the envelope). A balance
  is kept only if it explains the level change **and** is tighter than the plain 60 s rate cap. A driver that never varied is left out.
- Tolerances are the **worst per-block quantile** (blocks = contiguous slices of the normal data), so one quiet day cannot set them.
- Nothing is invented: for the synthetic test plant the fit finds the tank balance and the pump-to-flow coupling and **no** relation for the
  independent signals (`tests/test_invariants.py`).

## What they can and cannot see

They target **sensor spoofing, frozen or tampered readings, impossible jumps, and broken couplings**. An attack that only changes an actuator and
whose consequences are internally consistent (a pump set to a different but plausible speed) leaves the plant consistent: consistency rules
do not see it. That is why they are evaluated next to the model, and why the interesting number is "model OR invariants", not either alone.

## Evidence, and what is still open

| claim | evidence | status |
|---|---|---|
| the code finds known physics, detects each tampering type, stays silent on a healthy run, never invents a relation | `tests/test_invariants.py` on a synthetic plant with exact physics (68 checks) | proven (synthetic) |
| live monitor = offline score, second by second | parity check in the same test (963 flagged seconds, 0 mismatches) | proven |
| works on the real running stack | `python -m tools.live_invariants_check`: healthy plant silent for 100 s, an attack raised an upstream ALERT in 4 s and the dashboard showed it | proven (twin) |
| behaviour on the twin | `docs/reports/twin_invariants_report.md` (twin measurement, **not** SWaT) | measured |
| **detection and false alarms on real SWaT** | `python -m tools.fit_invariants --data-dir <SWaT>` and the invariants section of `python -m benchmark.swat_protocol --data-dir <SWaT>` | **NOT RUN yet: needs the archive. Do not quote a SWaT number until it has run.** |

Twin result in one line: the twin-fitted rules found only the rate family (the twin's tank dynamics are compressed in time, so its balances
fail validation), the healthy fresh run is silent at the file's calibrated `theta` (1.5), and four of five synthetic actuator attacks raise a
violation within 2 to 8 s; the chlorine-breakthrough scenario (a slow, consistent drift) does not. Read the report, not this sentence.

## Turning it on

Off by default. A fitted file describes one plant, so it must come from the plant being protected.

```
python -m tools.fit_invariants --twin                 # writes config/invariants_twin.json (the demo plant)
set IM_INVARIANTS=1                                   # PowerShell: $env:IM_INVARIANTS="1"   (Mac/Linux: export IM_INVARIANTS=1)
python -m middleware.middleware_server                # or scripts/run.sh middleware
```

| variable | meaning | default |
|---|---|---|
| `IM_INVARIANTS` | `1` enables the monitor | off |
| `IM_INVARIANTS_FILE` | invariant file | `config/invariants_twin.json` |
| `IM_INVARIANT_THETA` | violation threshold, overrides the file's calibrated value | the file's `theta` |
| `IM_INVARIANT_ALERT_SECONDS` | minimum seconds between upstream alerts for the same invariant | 30 |

The monitor needs about 85 s of telemetry before it speaks (status `WARMING_UP`). With no file, a bad file or any error it reports `NO_MODEL` /
`ERROR` and flags nothing; the rules keep enforcing. When it flags, the decision reason reads `PHYSICAL_MODEL:invariant:<id> S<stage>`, the
packet trace's physical-model hop lists the violated invariants, and an upstream ALERT is published even when no command is flowing.

## Fitting on SWaT

`python -m tools.fit_invariants --data-dir "<SWaT archive>"` fits on the **pre-attack 22-28 Dec normal period only** and tests on the whole attack
period, so every attack and every attack-period benign second is out of sample and out of time. It writes `docs/swat_invariants.json` (the
fitted rules: aggregate statistics, no raw rows), `benchmarks/swat_invariants.json` and `docs/reports/swat_invariants_report.md` (what was kept
and dropped, attacks detected and false-alarm episodes per hour at theta 1 / 1.5 / 2 / 3, attack by attack with the first invariant to fire).
SWaT-fitted rules do **not** describe the twin; use them for evaluation only, not with `IM_INVARIANTS=1` on the demo plant.

## Limits

- Fitted tolerances describe the normal data they saw: a plant regime never seen in training (a new operating point) can violate them.
  `theta` above 1 trades sensitivity for fewer such alarms; the report shows the trade on SWaT once it has run.
- Long-lived slow drifts that stay consistent (chlorine breakthrough on the twin) are not caught.
- The twin is a simulation: its numbers are never SWaT performance.
