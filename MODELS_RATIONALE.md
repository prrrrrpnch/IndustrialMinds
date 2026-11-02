# Model rationale

Why the learned parts of IndustrialMind are shaped the way they are, what was tried and rejected, and what each piece may and may not
be trusted for. Numbers here are quoted from generated artefacts; the authoritative, regenerable list is `CHECKLIST_VERIFICATION.txt`
(`python -m tools.verification_record`), and the full reports are under `docs/reports/`.

The short version: **the system blocks with deterministic rules and learns only to raise alerts.** Three learned components were
built and measured; one was promoted as advisory, two were rejected on their own evidence and kept as documented negative results.

---

## 1. The architectural decision: learning never holds the gate

```
SCADA ──signed Modbus write──►  CYBER RULES  ─┬─►  PHYSICAL RULES  ─┬─►  ORCHESTRATOR ──►  PLC
                                 (block)      │     (block)         │     (rule table)
                                              │                     │
                                   advisory:  └──  physical model ──┤  invariant rules  ──► ALERT only
```

A command is refused only by a deterministic check whose reason can be named: source whitelist, function code, register allow-list,
rate limit, HMAC, replay window, authorization policy; then bounds, rate of change and cross-register safety. Every learned component
is **advisory**: it can turn a forwarded command into an `ALERT`, never into a `DROP`.

Three reasons, in order of weight:

1. **The measured precision does not support blocking.** The live model's held-out precision on SWaT is 0.461. Blocking on it would
   refuse roughly one legitimate command in two that it flags. In a water plant a refused legitimate command is itself a safety event.
2. **A refusal has to be explainable to an operator at 3 a.m.** "`CROSS_REGISTER_VIOLATION:RAW_PUMP_DRY_RUN:P101=65>=60 while MV101=5<=10`"
   is actionable. "the classifier scored 0.83" is not. The assurance run confirms every refusal names the exact check that failed.
3. **Fail-closed must mean something specific.** When any stage raises, the command is dropped with `AGENT_ERROR`. That guarantee is
   only meaningful if the blocking stages are small, deterministic and individually testable.

The cost of this choice is real and should be stated: attacks that are physically plausible and individually in-bounds — a slow ramp,
a frozen sensor — are not blocked. They are detected and alerted, and the operator decides.

---

## 2. The physical model (PROMOTED, advisory) — `models/physical_model_v2.py`

**What it is.** A 120-second window of the 10 sensors and 8 actuators the twin exposes, turned into 117 features and scored by a
histogram gradient-boosting classifier. It flags when the attack probability exceeds 0.7880. Trained on SWaT only.

**Why a window and not an instantaneous reading.** Attacks that matter in a water plant are changes in *dynamics*, not in level: a
pump that stops still leaves the tank level in range for minutes. The feature set is therefore slopes, standard deviations, ranges and
actuator toggle counts over 30 s and 120 s, plus cross-sensor consistency residuals.

**Why gradient boosting rather than a deep model.** Cross-validation picked it over a random forest on segment-balanced average
precision. More importantly, three attempts at more capacity all lost on held-out data (section 4). With 35 attack events in the entire
dataset, capacity is not the binding constraint — data is.

**Why "drift-robust" features.** SWaT's absolute sensor levels drift across days (PIT502 and AIT202 noticeably). A model using absolute
levels can learn *which day a row came from* rather than whether it is an attack. The shipped feature set drops absolute levels and
keeps dynamics.

**Why the threshold is a false-alarm budget, not an F1 optimum.** The operating point is chosen on validation data as the most sensitive
threshold that stays within 0.5 false-alarm episodes per benign hour, then frozen before the test block is scored. Optimising F1 on the
test set is the single most common way these numbers get inflated.

**Measured, held-out SWaT:** precision 0.461, recall 0.513, F1 0.485, ROC-AUC 0.836, 8 of 10 attack segments detected, 1.17 false-alarm
episodes per hour, median detection 57.5 s. Accuracy is 0.959 against a never-alarm baseline of 0.962 — which is exactly why accuracy
is not the headline.

---

## 3. The physical invariants (advisory, opt-in) — `swat/invariants.py`

**Why add rules when a model already exists.** The model is trained on attack labels and is locked to its 18 tags. The invariants learn
from **normal data only**, so they need no attacks to be fitted, and they are plant-agnostic: the learner discovers the rules from
whatever plant it is given. They answer a different question — not "does this look like a known attack?" but "can these readings all
be true at once?"

**The four families.** Rate (a sensor cannot move faster than it ever did), state (while an actuator holds a state, a sensor stays in
the band it always had), balance (a tank's level change is explained by the flows around it), and flat (a sensor carrying measurement
noise cannot go perfectly flat). Each produces an excess that is at most 1 inside the normal range; it must persist to count.

**Why validation is part of the method, not an afterthought.** Rules are proposed on the first 75 % of the normal data and checked on
the last 25 %, held out in time. Anything that already misfires on unseen normal data is dropped with its reason recorded. On a synthetic
plant with known physics the learner recovers the tank balance and the pump-to-flow coupling and invents no relation between independent
signals.

**What they cannot see, by construction.** An attack that changes an actuator and leaves the plant internally consistent. On the twin,
the chlorine-breakthrough scenario is missed for exactly this reason. This is a property of consistency checking, not a bug.

**Measured on the twin:** adding them took sensor-tampering detection from 10/25 to 25/25 runs with no change in false alarms
(0 episodes per hour over 9 healthy hours) and no measurable decision-latency cost. **Their real-SWaT detection and false-alarm rates
are not measured yet** (`python -m tools.fit_invariants --data-dir <archive>`), and no SWaT claim should be made for them until that runs.

One disclosure that belongs in any write-up: the flat family was added *after* a before/after run showed a frozen level sensor being
missed by every layer. That scenario is therefore not independent evidence for the flat rule.

---

## 4. What was built, measured and rejected

Each of these is reproducible and kept in `research/` precisely so the negative result can be checked rather than taken on trust.

| Attempt | Why it was tried | Measured on real SWaT | Decision |
|---|---|---|---|
| **Cyber ML** (`research/train_cyber_swat.py`) | to score command *payloads* for anomaly, alongside the cyber rules | ROC-AUC 0.631, F1 0.126 on held-out actuator state-change events | **Rejected.** The cyber branch is deterministic rules only. The synthetic weights were deleted, so the model reports `NO_MODEL`. |
| **Learned fusion** (`research/train_fusion_swat.py`) | to replace the hand-written orchestrator table with a trained combiner | validation AUC 0.93 but **test AUC 0.68**, below the physical model alone (0.83); 4 of 10 segments versus 6 | **Rejected.** The gap between validation and test is the whole lesson: the combiner learned the validation block. |
| **Physical v3** (`research/physical_model_v3.py`) | multi-scale features, normal-only ridge/PCA heads, stacking | F1 0.352 against the v2 baseline's 0.432; 6 of 10 segments versus 8 | **Not promoted.** Kept opt-in behind `IM_PHYSICAL_MODEL=v3`. |
| **k-of-m alarm persistence** | to suppress isolated blips | helped on validation, **hurt on the test block** (F1 0.416 versus 0.485) | **Not shipped.** The shipped alarm rule is a single window over the threshold. |

A fourth idea, replacing the model with a pre-trained or deep time-series detector, was analysed and not pursued: published SWaT
scores of 0.8–0.9 mostly rely on point-adjust scoring and test-set thresholds, and three in-house attempts at more capacity had
already lost on held-out data. The honest expectation was a small, uncertain change at a large cost in dependencies.

---

## 5. Why the cyber branch has no model at all

SWaT contains **no network fields**: no addresses, no function codes, no timing, no packet captures. The only cyber-shaped signal
derivable from it is actuator state-change events, and a model over those scored ROC-AUC 0.631. Meanwhile the properties the cyber
layer actually enforces — a valid HMAC, a fresh nonce, a known source, a rate under the limit — are *decidable*, not statistical. A
learned approximation of a decidable property is strictly worse than the property.

So the cyber layer is rules, and its evidence is conformance to a specification: 4,400 of 4,400 violating scenarios refused with the
expected reason, 0 false positives on legitimate traffic, and 24 of 24 malformed or tampered commands refused in the assurance fuzzing
(including a truncated, emptied, zeroed or removed signature, a zeroed nonce, a stale timestamp, and a tampered register or raw value
with the signature kept). That is conformance, not detection skill on real attacks, and it must not be quoted as the latter.

---

## 6. Cost

The decision path is in-process and bounded: p50 0.501 ms, mean 0.801 ms, p95 1.972 ms, p99 2.797 ms per command, of which the cyber
rules take about 0.06 ms and the physical rules about 0.03 ms. The model dominates the tail (p95 about 1.4 ms) but not the median,
because its assessment is cached per telemetry sample rather than recomputed per command. The invariant monitor costs about 1.5 ms per
telemetry sample at 1 Hz, off the decision path, and about 0.5 µs per decision to merge its cached verdict.

---

## 7. What these models may not be trusted for

* **Blocking.** Neither the model nor the invariants may refuse a command, and the code enforces it: a forced advisory flag yields
  `ALERT` in every test.
* **Unattended operation.** Alarm counts rise over a long healthy twin run (18 alarm seconds in the first half of four hours, 695 in the
  second) as the twin's fouling cycle develops and the model's 95th-percentile probability sits on its threshold. Stage coverage is also
  uneven: at a 1 σ perturbation, detection is 100 % in stages 1 and 4 but 33 % in stages 2, 3 and 5, with pH the weakest because its
  measured spread is close to the Modbus wire's 0.1 resolution.
* **Generalisation to attacks nobody designed.** Every twin and constructed attack is one we wrote.
* **Any plant but this one.** The model is locked to its 18 SWaT tags and cannot run elsewhere without retraining. The invariant learner
  is plant-agnostic by design, and validating it on a second real plant (WADI is the natural candidate) is the obvious next step.
* **Degradation versus attack.** A slowly drifting sensor is reported as an anomaly; the system cannot tell a failing instrument from a
  slow attack, and an operator must.
