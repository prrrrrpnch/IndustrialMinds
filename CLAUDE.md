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
  `docs/interfaces.py: MACHINES` is the single source of truth for registers/bounds (bounds are
  currently GUESSED — PART 0 item; replaced in Phase 3/6).
- `check_feedback()` returns `tx_id=""` by design; caller must set it (docs/register_map.md).
- `models/telemetry_generator.py` is synthetic data: never cite its metrics as real-data results.
- Orchestrator forwards decisions to the dashboard via HTTP in a fire-and-forget thread.
- Models are advisory (MONITOR) unless `IM_CYBER_MODEL_ENFORCE=1`.
- `docs/netconfig.py` is the ONLY place host/port defaults live (env vars documented in its header).
- Weights were pickled with scikit-learn 1.8.0; env has 1.9.1 -> InconsistentVersionWarning (harmless; retrain in P5/P6 fixes).
- Pre-existing lab IPs remain only in synthetic-data files (telemetry_generator, train_models, evaluation, some tests); replaced when data is replaced in P5-P7/P11.
- Plant = 5 stages x 4 points = 20 registers (10 actuators writable, 10 sensors read-only); register constants are SWaT tags (MV101, LIT101...). Old names (TANK_PRESSURE...) are gone.
- Wire scale is x10 (0.1 resolution): pH/permeate flow are coarse; max representable 6553.5.
- Model weights in models/weights are STALE (trained on the old 10 synthetic machines); they still load (per-channel features) but their scores mean nothing until P5/P6. Advisory only.
- `evaluation/` (xlsx, generate_test_data, evaluate_system) targets the OLD register names and is non-functional until replaced in P11.
- `docs/wireshark_setup.md` is currently an empty file (filled in Phase 10).

## File index (open only when relevant)
| Path | Open when |
|---|---|
| `README.md` | user-facing setup/usage; rewritten in Phase 12 |
| `MODELS_RATIONALE.md` | changing/justifying the cyber or physical model design |
| `CHECKLIST_VERIFICATION.txt` | legacy self-verification claims (numbers must match repo benchmarks — PART 0 item) |
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
| `models/cyber_model.py`, `models/physical_model.py` | Isolation Forest (13 features) / RF health+RUL |
| `models/train_models.py`, `models/telemetry_generator.py` | training (currently synthetic) |
| `models/tree_inference.py` | packed fast tree inference |
| `models/weights/` | trained artifacts + `training_report.json` (guarded) |
| `plc/plc.py` | PLC: Modbus server around the twin (actuator writes -> targets; sensors read-only) |
| `plc/twin.py` | staged SWaT-style physics (5 stages, 20 points, inter-stage coupling); env IM_TWIN_TIME_SCALE / IM_TWIN_NOISE |
| `tests/test_twin_propagation.py` | Phase 3 check: perturb S1, assert S2..S5 respond in order (`--live` over Modbus) |
| `scada/scada.py` | operator simulator (`--host` pattern to copy) |
| `attacker/attacker.py` | attack scripts (rebuilt in Phase 8) |
| `dashboard/app.py`, `dashboard/static/`, `dashboard/templates/` | Flask dashboard + UI |
| `evaluation/` | legacy synthetic xlsx evaluation (superseded in Phase 11) |
| `tests/` | unit/pipeline/stress tests |
| `.claude/hooks/guard.py`, `.claude/hooks/confirm.py`, `.claude/settings.json` | hook logic / confirmation helper / wiring |

## PART 0 tracker (update at the end of each phase)
| # | Issue | Closed by | Status |
|---|---|---|---|
| 1 | Models trained only on synthetic data | P5, P6 (SWaT) | open |
| 2 | Guessed physical bounds | P6 (P3 only installs SWaT-style PLACEHOLDERS) | open |
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
