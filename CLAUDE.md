# IndustrialMind — CLAUDE.md (index only; open referenced files on demand)

Inline security middleware between a SCADA simulator and a PLC digital twin:
SCADA -> [Cyber Agent | Physical Agent -> Orchestrator] -> PLC. Python 3.13.
Reference files are listed by path below; none are auto-loaded.

## Hard boundaries (hook-enforced by `.claude/hooks/guard.py`, wired in `.claude/settings.json`)
1. **No deletions** (rm, git rm/clean, find -delete, inline python rmtree/unlink) unless the exact
   path was confirmed by the user this session. After the user approves, record it:
   `python3 .claude/hooks/confirm.py delete <path>`. Globs/variables are refused; list exact paths.
   Exempt: `__pycache__`, scratchpad/tmp dirs.
2. **No overwriting existing weight files** in `models/weights/` unless retraining of THAT model
   was confirmed: `python3 .claude/hooks/confirm.py retrain <cyber|physical|orchestrator>`.
   Training commands must use `--candidate` (writes `models/candidates/`) until promotion is approved.
3. **No IPs other than loopback/0.0.0.0** in shell commands or written project files, except laptop
   IPs the user confirmed in Phase 10: `python3 .claude/hooks/confirm.py ips <ip> ...`.
   Use env vars / CLI args instead of literals.
4. `.claude/state/confirmations.json` is written only by `confirm.py` (session-scoped, git-ignored).
   Never run `confirm.py` without an explicit user approval in chat.
5. The guard is a guardrail for the agent, not a security boundary against a human with shell access.

## Working rules for this rework (source: user prompt, 12 phases + PART 0 issue list)
- **DECISION (user, after the P6 gate): NO CYBER ML MODEL. The cyber branch is RULE-BASED ONLY** (whitelist, function code, register allow-list,
  rate limit, HMAC, nonce/replay). A user-proposed external traffic dataset was inspected and dropped; the SWaT-only dataset policy is
  therefore UNCHANGED and no external dataset is used. The SWaT cyber candidate (weak) and its code stay as a documented negative result.
- **Dataset policy: SWaT (iTrust, SUTD) is the ONLY external dataset.** Anything SWaT can't supply is
  (a) derived from SWaT columns/labels or (b) labeled synthetic/rule-tested and listed in known
  limitations. Never present self-generated data as real-data performance. No Morris et al.
- Approval gates (stop and wait): P1 deletions, P3 twin table, P4 data in hand, P5/P6 weight
  replacement, P7 sample rows, P10 laptop topology. Do not pre-plan in documents; execute, self-check
  against the phase's Definition of Done, show evidence.
- Sub-agents: max 4 concurrent per phase, only for genuinely parallel work.
- Each phase end: report which PART 0 items it closed (tracker below).
- Do not create PRs unless asked. Branch: `claude/serene-feynman-or6ieo`.

## Commands you can't guess
- Deps (not preinstalled here): `pip install -r requirements.txt` (pymodbus must stay ==3.6.9, see plc/plc.py header).
- Run from repo root, one process each: `python -m plc.plc`, `python dashboard/app.py`,
  `python -m middleware.middleware_server`, `python -m scada.scada`.
- Ports: PLC 5020, middleware 5021, dashboard 5050.
- Unit tests are plain scripts: `python -m tests.test_cyber_agent` (also test_physical_agent,
  test_orchestrator, test_models, test_pipeline). `tests/pipeline_test.py` needs a running PLC.
- HMAC secret: env `IM_HMAC_SECRET` in BOTH SCADA and middleware, else `config/hmac_secret.key` auto-generated.

## Known gotchas
- `docs/` holds code (`interfaces.py`, `hmac_auth.py`, `attack_log.py`), not only docs.
  `docs/interfaces.py: MACHINES` is the single source of truth for registers/bounds (sensor ranges/nominals are
  MEASURED from SWaT: docs/swat_bounds.json). plc/twin.py derives ALL its physics constants from MACHINES `initial`.
- `check_feedback()` returns `tx_id=""` by design; caller must set it (docs/register_map.md).
- `models/telemetry_generator.py` is synthetic data: never cite its metrics as real-data results.
- Orchestrator forwards decisions to the dashboard via HTTP in a fire-and-forget thread.
- Models are advisory (MONITOR) unless `IM_CYBER_MODEL_ENFORCE=1`.
- `docs/netconfig.py` is the ONLY place host/port defaults live (env vars documented in its header).
- Weights were pickled with scikit-learn 1.8.0; env has 1.9.1 -> InconsistentVersionWarning (harmless; retrain in P5/P6 fixes).
- Pre-existing lab IPs remain only in synthetic-data files (telemetry_generator, train_models, evaluation, some tests); replaced when data is replaced in P5-P7/P11.
- Plant = 5 stages x 4 points = 20 registers (10 actuators writable, 10 sensors read-only); register constants are SWaT tags (MV101, LIT101...). Old names (TANK_PRESSURE...) are gone.
- Wire scale is x10 (0.1 resolution): pH/permeate flow are coarse; max representable 6553.5.
- models/weights: physical_model.joblib is the PROMOTED SWaT-trained model (advisory; operating point 0.5 false alarms/h, clf thr 0.601, variant drift_robust). cyber_model.joblib and training_report.json are OLD SYNTHETIC leftovers: the cyber model refuses them (NO_MODEL = cyber branch is rules-only); delete them only with a user-confirmed delete.
- `evaluation/` (xlsx, generate_test_data, evaluate_system) targets the OLD register names and is non-functional until replaced in P11.
- SWaT archive facts (from tools/swat_inspect.py reports; data lives ONLY on the user's Windows machine, never in this container):
  attack.csv = 54,621 attack-only rows in 35 time-gap segments; normal.csv = 1,387,098 rows; merged.csv = their concatenation; 51 tags + Timestamp + `Normal/Attack`;
  timestamps `%d/%m/%Y %I:%M:%S %p`, 1 Hz, files NOT chronological. NO network fields, NO attack list, NO pcaps.
  CONFIRMED by the real run: normal.csv holds the 22-28 Dec normal period (496,800 rows) + an exact duplicate copy (495,000 rows, 0 conflicts) + the attack period's normal rows;
  after de-duplication the stream is 946,719 rows = 496,800 + 449,919, 35 attack segments (17/8/10 across train/val/test), only 2 chunks (gaps > 5 s).
  MV101/AIT201/MV201/P201/P202/P204/MV303 are NaN for the 991,800 normal-period rows (present only in the 449,919 attack-period rows).
  Segment 22 (35,900 rows, ~10 h) is 66% of all attack rows: always evaluate PER SEGMENT, split by calendar time blocks, never random rows. PIT502/AIT202 drift by day (leakage tell).
  SWaT actuators are discrete (pumps 1/2, valves 0/1/2); P401/P404/P502/P601/P603 constant, P402/P501/UV401 ~always on. MV503 does not exist in SWaT.
- Phases 5-7 need the data on the machine that RUNS training: run the session locally (recommended) or have the user run `--candidate` training and paste reports.
- DECISION (P6 gate): physical candidate promoted as advisory at the 0.5/h budget (threshold edited from the trained 0.558 to 0.601, recorded in metadata). Physical ML never blocks; the envelope rule is alert-only.
- DECISION (P5 gate): cyber ML candidate NOT promoted. models/weights/cyber_model.joblib is the OLD synthetic file, refused by the schema check; never promote it; remove only with a confirmed delete.
- Cyber ML = actuator STATE-CHANGE events (1/2 -> 0/100 %); it abstains on writes that don't flip on/off. Old 13-feature weights in models/weights are refused (schema mismatch -> NO_MODEL) until the SWaT candidate is promoted.
- Guard hook only fires on EXECUTING a training script (python ... train*), not on reads; avoid heredocs whose text mentions weights paths / training commands (false positives) - write scripts with the Write tool.
- `docs/wireshark_setup.md` is currently an empty file (filled in Phase 10).

## File index (open only when relevant)
| Path | Open when |
|---|---|
| `README.md` | user-facing setup/usage; rewritten in Phase 12 |
| `MODELS_RATIONALE.md` | changing/justifying the cyber or physical model design |
| `CHECKLIST_VERIFICATION.txt` | legacy self-verification claims (numbers must match repo benchmarks — PART 0 item) |
| `docs/swat_bounds.json` | MEASURED SWaT normal-operation statistics + envelope per sensor (aggregate; source of the twin calibration) |
| `docs/reports/physical_training_report_swat_run1.md` | physical candidate run 1 (pristine test; weak: ROC-AUC 0.66, train 1.0 = overfit, 2.8 alarm episodes/h) |
| `docs/reports/physical_training_report_swat_run2.md` | physical candidate run 2 (REVISED protocol, test not pristine): classifier test ROC-AUC 0.83, F1 0.26-0.37 depending on false-alarm budget |
| `docs/reports/twin_domain_gap_report.md` | SWaT-model on the healthy calibrated twin: 0.25 alarm episodes/h, attacks flagged in 1-4 s (TWIN measurement, not SWaT performance) |
| `tools/twin_domain_gap.py` | measure a PhysicalModel on the calibrated twin (nominal false alarms + synthetic attack latency) |
| `tests/test_bounds_alignment.py` | PART 0 #2 evidence: config/twin vs measured bounds (35 checks) |
| `docs/netconfig.py` | any host/port/env-var question (single source for addresses) |
| `docs/interfaces.py` | machines/registers/bounds, verdict/decision dict shapes, cross-register rules |
| `docs/hmac_auth.py` | signed frame format, HMAC build/verify |
| `docs/attack_log.py` | blocked-attack JSONL logging |
| `docs/register_map.md` | register table, ports, contract notes |
| `middleware/middleware_server.py` | Modbus proxy, downstream/upstream handling, poll loop |
| `middleware/cyber_agent.py` | rule checks: whitelist, FC, register, rate, HMAC, replay |
| `middleware/physical_agent.py` | rule checks: bounds, rate-of-change, cross-register, feedback |
| `middleware/orchestrator.py` | fusion of verdicts (currently AND-gate) + dashboard forwarding |
| `pipeline/multi_model_pipeline.py` | concurrent cyber/physical branches (rules + models) |
| `models/cyber_model.py` | SWaT-trained CyberModel: Isolation Forest + supervised head over 8 actuator-event features (abstains on non-flip commands) |
| `models/physical_model.py` | SWaT-trained PhysicalModel: 30 s windows (1 Hz), 87 features, Isolation Forest + supervised head + measured envelope; abstains on NO_MODEL/WARMING_UP/ERROR; RUL removed |
| `swat/physical_features.py` | physical window features + measured-bounds computation = THE feature implementation shared by training and live |
| `models/train_physical_swat.py` | Phase 6 trainer (`--data-dir <archive> --candidate` or `--fixture`): bounds + model + report; candidates only |
| `tests/test_swat_physical.py` | Phase 6 checks on the synthetic fixture (code paths, live==training scores) |
| `docs/reports/cyber_training_report_swat.md/.json` | REAL SWaT held-out results of the cyber candidate (aggregate only): weak - test ROC-AUC 0.63, F1 0.137 |
| `models/train_cyber_swat.py` | Phase 5 trainer (`--data-dir <archive> --candidate`, or `--fixture`); writes models/candidates/ + report + provenance |
| `models/promote_candidate.py` | copy an approved candidate into models/weights/ (refuses without `confirm.py retrain <model>`) |
| `swat/loader.py`, `swat/cyber_events.py` | chronological de-duplicated SWaT stream + segments + calendar blocks / actuator events + THE feature implementation shared by training and live |
| `tests/test_swat_cyber.py`, `tests/swat_fixture.py` | Phase 5 checks on a synthetic SWaT-SHAPED fixture (code paths only, never real metrics) |
| `models/train_models.py`, `models/telemetry_generator.py` | train_models is RETIRED (stub); telemetry_generator is synthetic, tests/benchmarks only |
| `models/tree_inference.py` | packed fast tree inference |
| `models/weights/` | physical_model.joblib (PROMOTED, SWaT-only) + its report; stale synthetic cyber_model.joblib/training_report.json (guarded) |
| `plc/plc.py` | PLC: Modbus server around the twin (actuator writes -> targets; sensors read-only) |
| `plc/twin.py` | staged SWaT-style physics (5 stages, 20 points, inter-stage coupling); env IM_TWIN_TIME_SCALE / IM_TWIN_NOISE |
| `tests/test_twin_propagation.py` | Phase 3 check: perturb S1, assert S2..S5 respond in order (`--live` over Modbus) |
| `scada/scada.py` | operator simulator (`--host` pattern to copy) |
| `attacker/attacker.py` | attack scripts (rebuilt in Phase 8) |
| `dashboard/app.py`, `dashboard/static/`, `dashboard/templates/` | Flask dashboard + UI |
| `evaluation/` | legacy synthetic xlsx evaluation (superseded in Phase 11) |
| `tests/` | unit/pipeline/stress tests |
| `tools/traffic_inspect.py` | UNUSED since the no-cyber-ML decision (inspected one traffic dataset: mostly non-Modbus, 1.2% Modbus rows); candidate for removal |
| `tools/swat_inspect.py` | Phase 4: run locally on the SWaT folder; prints aggregate-only report + JSON manifest (no raw rows) |
| `.claude/hooks/guard.py`, `.claude/hooks/confirm.py`, `.claude/settings.json` | hook logic / confirmation helper / wiring |

## PART 0 tracker (update at the end of each phase)
| # | Issue | Closed by | Status |
|---|---|---|---|
| 1 | Models trained only on synthetic data | P5 (cyber), P6 (physical) | cyber: trained on real SWaT, result WEAK (docs/reports); user DROPPED cyber ML entirely -> cyber branch is RULES-ONLY by design (negative result = documented limitation); physical: run 2 on real SWaT (test AUC 0.83, F1 ~0.3), PROMOTED as ADVISORY at the 0.5 false-alarm/h operating point (user decision, P6 gate) -> NO synthetic-trained model is active any more |
| 2 | Guessed physical bounds | P6 | CLOSED (docs/swat_bounds.json measured on real SWaT train-normal rows; MACHINES + twin calibrated to it; tests/test_bounds_alignment.py enforces) |
| 3 | Hardcoded 127.0.0.1 | P2 | CLOSED (docs/netconfig.py; env+CLI; grep clean) |
| 4 | Orchestrator is AND-gate | P7 | open |
| 5 | No orchestrator model | P7 | open |
| 6 | Attacker deterministic | P8 | open |
| 7 | Twin is flat list, not SWaT-like | P3 | CLOSED (5 stages x 4 pts, coupled physics, propagation check passes) |
| 8 | No per-layer journey visibility | P9 | open |
| 9 | No live network proof | P10 | open |
| 10 | No reproducible verification | P11 | open |
| 11 | README is setup only | P12 | open |
| 12 | Junk files | P1 | CLOSED (2 stray scripts deleted; venv/.DS_Store/__MACOSX never in repo, now git-ignored) |
| 13 | PPT/report numbers != repo benchmark | P11, P12 | open |
