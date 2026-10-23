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
- AUDIT FIXES (final-results/AUDIT.md, verified by tests/test_audit_fixes.py + final-results/_verify_fixes.py):
  (C1) a command the PLC never accepted is NO LONGER reported as PASS - `_forward_to_plc`'s return value is used, the
  middleware logs `UNDELIVERED`, and `orchestrator.forward_delivery_failure()` -> dashboard `POST /api/delivery` rewrites the
  already-published event to verdict `UNDELIVERED` and moves it out of the pass count.
  (C2) the PLC client is built with `timeout=IM_PLC_TIMEOUT_S` (0.5) and `retries=IM_PLC_RETRIES` (1); the library defaults
  (3 s x 3 retries) made a black-hole PLC stall EVERY client at 2,002 ms/command. Now ~504 ms. The forward still runs on the
  asyncio event loop - moving it off is the remaining structural fix (AUDIT C2, 'this sprint').
  (A5) `/api/health` reports `degraded` with a reason when commands went undelivered or the model is unhealthy.
  (N2) NO CDN assets: `dashboard/static/vendor/microchart.js` (one canvas line chart, replaces Chart.js) and
  `vendor/icons.css` (Unicode glyphs, replaces Font Awesome); fonts are the system stack. The lab is air-gapped, so a CDN
  asset is a guaranteed failure - the CPU panel used to render as a blank box and said so only in the browser console.
- SPRINT AUDIT FIXES (final-results/AUDIT.md, verified by tests/test_sprint_fixes.py, 43 checks):
  (C5) `cyber_agent._state_lock` (RLock) now guards `_check_nonce`/`_check_rate`/`_check_replay`/`_sweep_idle_sources`/`reset_state`.
  `_check_nonce` was a read-then-write TOCTOU, safe ONLY because setValues ran on one asyncio thread - which C2's fix changed. Done FIRST.
  (C2 structural) the PLC forward no longer runs on the event loop: the handler puts the job on a bounded FIFO `_forward_queue`
  (IM_FORWARD_QUEUE, 200) drained by ONE `plc-forwarder` thread (one, not a pool: same-register writes must keep their order);
  `_forward_job`/`_report_undelivered` publish the trace and the UNDELIVERED correction. `_plc_io_lock` serialises every call on the
  shared client instead of relying on a pymodbus internal RLock. Black-hole PLC: 2,002 ms -> 504 ms (timeout) -> 1.9 ms (structural).
  A full queue is reported UNDELIVERED `FORWARD_QUEUE_FULL` and counted in `dropped_forwards` - never silent.
  (C4) `_poll_delay()`: 0.2 s for the first IM_POLL_BACKOFF_AFTER (3) failures, then doubling to IM_POLL_BACKOFF_MAX_S (5 s), reset by
  the first good read. ~18,000 -> 720 attempts/hour against a dead PLC.
  (S3) `dashboard.check_bind_is_safe()` ABORTS startup (exit 2) if the bind host is not provably loopback and IM_DASHBOARD_TOKEN is
  unset - an open /api/reset on a lab network lets anyone erase the attack record. run.sh/run.ps1 pass DASHBOARD_TOKEN from lab.env.
  (A6/N6) middleware `health_snapshot()` -> `orchestrator.forward_middleware_health()` -> dashboard `POST /api/middleware-health`
  every 5 s; GET /api/health reports the PLC leg (connected/unreachable/unknown/not reported) and degrades on dropped forwards or a
  heartbeat older than 20 s. The header badge was the hardcoded word ONLINE; `refreshHealth()` in script.js now drives it.
- MIDDLEWARE IS NOW FIVE MODULES (AUDIT A1/A2, pinned by tests/test_sprint_fixes.py):
  `middleware/runtime.py` (config + shared state + raw conversion + _dashboard_headers; the BOTTOM layer, imports no sibling),
  `middleware/forwarding.py` (PLC client, _plc_io_lock, forward queue/worker), `middleware/ingest.py` (decision queue/worker,
  _process_write, _handle_downstream_write, _log_blocked, _publish_trace/_publish_model_card),
  `middleware/polling.py` (poll loop, telemetry, PLC->SCADA responses, envelope alerts), `middleware/middleware_server.py`
  (transport + CLI only; 1,478 -> 424 lines).
  (A2) `MiddlewareDataBlock.setValues` now calls `ingest.submit()` and RETURNS - the pipeline no longer runs as a side effect
  of a storage call on the event loop. ONE decision worker (order matters: rate limit, replay window, cross-register), bounded
  IM_DECISION_QUEUE (500), a full queue fails CLOSED and is logged + counted (`ingest.dropped_writes()`).
  The arrival time is captured at submit() and threaded through as `arrival=`, so queueing cannot change what the rate limiter,
  the replay window or the reported latency measure.
  GOTCHAS: `middleware_server` re-exports the old names, but a re-export is a SNAPSHOT of a binding - monkeypatching
  `mw._plc_client` does NOT change what forwarding uses; patch `forwarding._plc_client`. Two late bindings break the import
  cycle: `polling._internal_sync_write` (set by middleware_server) and `forwarding._publish_trace` (set by ingest, with a
  late-import fallback). `runtime.health_snapshot()` imports forwarding lazily for the same reason.
- NEXT-QUARTER AUDIT FIXES (final-results/AUDIT.md, verified by tests/test_quarter_fixes.py):
  (S1) the PLC now applies a write only from an allowed writer: `IM_PLC_ALLOWED_WRITERS` (core/netconfig.PLC_ALLOWED_WRITERS),
  DEFAULT = the middleware's host, so the one-laptop demo is unchanged (everything is 127.0.0.1) but the 4-laptop lab refuses the
  attacker's direct-to-PLC write out of the box. `plc.writer_allowed()` in `SyncedDataBlock.setValues`; a refused write never reaches
  the physics, is logged `REFUSED direct write` (rate limited) and counted in `plc.refused_writes()`. `IM_PLC_ALLOWED_WRITERS=any`
  restores the old bypass for demonstrating it. Peer address captured by `WriteSourceRequestHandler` (same pattern as the middleware).
  Defence in depth, NOT a substitute for segmentation: a spoofed source address still gets through.
  (S4) the quarantine is keyed to AUTHENTICATED identity: `quarantine.record(..., authenticated=)` ignores every pre-auth reason
  (`quarantine.PRE_AUTH_REASONS`/`is_pre_auth()`), and the quarantine CHECK moved in cyber_agent from first to AFTER hmac+replay
  (trace.CYBER_ORDER updated). Before this, spoofing the operator's address with 2 forged frames quarantined the REAL SCADA -
  the response layer was a DoS lever. `quarantine.shared_secret_warning()` says per-device keys are needed to be fully spoof-proof.
  (A4) the forensic record outlives the UI: `core/forensics.py` appends traces/incidents/investigations/events as JSONL under
  IM_LOG_DIR and the dashboard replays them at startup (`_replay_forensics()`, called at the BOTTOM of app.py - it touches state
  defined throughout the module). Append-only, so a PASS later corrected to UNDELIVERED keeps both lines and replays as UNDELIVERED
  in arrival order. `/api/reset` renames the files `.cleared-<unix>` instead of deleting. IM_FORENSICS=0 opts out, IM_FORENSICS_MAX_MB rotates.
  (#11) `docs/` is documentation ONLY - the source moved to `core/` (interfaces, hmac_auth, attack_log, netconfig, forensics);
  `docs/` is no longer a package. Rejected experiments moved to `research/`: physical_model_v3, features_v3, train_physical_v3,
  package_physical_v3, train_fusion_swat, fusion_scenarios, train_cyber_swat. DELIBERATELY NOT moved: `swat/cyber_events.py`
  (models/cyber_model.py imports it live; shared train/serve feature code is the skew defence the audit itself credits).
- THREE-LAPTOP REHEARSAL (`python -m tools.verify_three_laptops`, ~5 min, writes docs/reports/three_laptop_e2e_verification.md, 65 checks):
  runs middleware+dashboard / PLC+SCADA (ONE address) / attacker on distinct loopback addresses THROUGH THE REAL LAUNCHERS, with a real
  tshark capture of both legs and a real browser. `IM_LAB_ENV=<file>` makes run.sh/run.ps1 read that file instead of config/lab.env (the
  launcher sources the file AFTER the environment, so a stale config/lab.env silently overrides exported MW_IP/SCADA_IP - this bit the first
  attempt). One disclosed shim: a sitecustomize in the run dir binds a source address for the one process that sets IM_BIND_SOURCE.
  It found and fixed: (a) the PLC launcher never set IM_MIDDLEWARE_HOST so the PLC refused the real middleware (S1 default); `check plc --multi`
  now FAILs it; (b) the Network Flow view showed an undelivered command as a plain PASS/ALERT - `_flow_summary` now reports UNDELIVERED for an
  approved downstream command whose trace has forwarded=False (flow.js turns the PLC node red/dashed + ":5020 unreachable"); (c) /api/health stayed
  DEGRADED for ever after one undelivered command - it now degrades only for IM_UNDELIVERED_RECENT_S (60 s), the COUNT stays on the overview;
  (d) the UNDELIVERED badge overflowed its ticker column; (e) the dashboard launcher never set IM_HOST_LABELS so hosts read "host";
  (f) a red /favicon.ico 404 on every load. Expect on a rehearsal: after attacks the advisory model turns SCADA's own commands ALERT (no cyber drops);
  rarely a legitimate SCADA command is refused by RATE_OF_CHANGE when an insider ramp just moved the same register (rule compares with the last
  ACCEPTED value regardless of sender). Not provable on one host: real Wi-Fi/firewalls/NICs/clock skew; the stand-in Laptop 1 is 127.0.0.1 so
  `--multi` preflight rightly flags it (the tool whitelists exactly that).
- `docs/` holds DOCUMENTATION ONLY now (the code moved to `core/`; see the next-quarter fixes above).
  `core/interfaces.py: MACHINES` is the single source of truth for registers/bounds (sensor ranges/nominals are
  MEASURED from SWaT: docs/swat_bounds.json). plc/twin.py derives ALL its physics constants from MACHINES `initial`.
- `check_feedback()` returns `tx_id=""` by design; caller must set it (docs/register_map.md).
- `models/telemetry_generator.py` is synthetic data: never cite its metrics as real-data results.
- Orchestrator forwards decisions to the dashboard via HTTP in a fire-and-forget thread.
- Models are advisory (MONITOR) unless `IM_CYBER_MODEL_ENFORCE=1`.
- `core/netconfig.py` is the ONLY place host/port defaults live (env vars documented in its header).
- requirements.txt pins scikit-learn==1.9.1: physical_model.joblib was last saved by this container (1.9.1); other versions warn. tests/test_environment.py enforces pin + clean load. The user's machine had 1.8.0: they must `pip install scikit-learn==1.9.1`.
- Pre-existing lab IPs remain only in synthetic-data files (telemetry_generator, train_models, evaluation, some tests); replaced when data is replaced in P5-P7/P11.
- Plant = 5 stages x 4 points = 20 registers (10 actuators writable, 10 sensors read-only); register constants are SWaT tags (MV101, LIT101...). Old names (TANK_PRESSURE...) are gone.
- Wire scale is x10 (0.1 resolution): pH/permeate flow are coarse; max representable 6553.5.
- SECURITY HARDENING (all opt-in, default = unchanged demo): (1) PER-DEVICE KEYS: IM_HMAC_KEYS="<addr>=<key>,..." (or IM_HMAC_KEYS_FILE json) on the middleware -> each source verified with its own key (hmac_auth.key_for_source/has_key_registry, verify(key=)); unregistered source -> cyber UNKNOWN_DEVICE; a stolen key is useless from another addr; signers hold only their own IM_HMAC_SECRET; no registry -> shared-secret mode (unchanged). tests/test_per_device_keys.py. (2) DASHBOARD TOKEN: IM_DASHBOARD_TOKEN on dashboard+middleware -> before_request rejects unauthenticated POST /api/* (401); GET + /api/health stay open; forwarders send X-IM-Token. tests/test_dashboard_auth.py. (3) FAIL-CLOSED: already default (agent/orchestrator exception -> DROP AGENT_ERROR; tests/test_pipeline.py). Model real-data accuracy still needs the SWaT archive (not in container).
- RESPONSE LAYER (rule-based, default off/unchanged): `middleware/policy.py` (config/policy.json via IM_POLICY_FILE: source->role->writable registers+limits, UNAUTHORIZED_REGISTER/VALUE/SOURCE, malformed file -> POLICY_ERROR fails closed for writes, reads never restricted, runs AFTER hmac/replay in cyber_agent); `middleware/quarantine.py` (opt-in IM_QUARANTINE=1|auto|force: AUTO-OFF on a one-laptop demo (all trusted sources loopback; `force` overrides), launcher sets `auto` for the middleware; weighted strikes in a sliding window -> SOURCE_QUARANTINED checked right after the whitelist, auto-expiring, doubling, IM_QUARANTINE_* env); `middleware/incidents.py` (groups non-PASS decisions per source into incidents with severity; pipeline `_respond` feeds quarantine+incidents, report['incident']; dashboard POST /api/incident, GET /api/incidents, panel `dashboard/static/incidents.js`). Tests: tests/test_response_layer.py. No ML involved (cyber branch stays rules-only).
- LLM INVESTIGATOR (opt-in IM_INVESTIGATOR=1, OUT OF BAND - this does NOT reverse the 'no cyber ML in the decision path' decision): `middleware/investigator.py`. Enforcement stays deterministic; the LLM only runs the INVESTIGATION workflow over an incident after the decision is published. Read-only evidence tools (get_incident/get_command_trace/get_plant_state/get_rule_catalogue/get_protection_settings/get_model_card/get_blocked_attack_log) + `submit_finding` (strict schema, action enum = ACTIONS allow-list). Manual agent loop (not the SDK tool runner) so every turn is capped and audited; model `claude-opus-5-5`, adaptive thinking, server-side fallbacks (the prompt is about cyberattacks and can trip a classifier). Guarantees enforced in code: cannot change a verdict, cannot act (invented actions dropped -> `rejected_actions`), cannot reach the plant, cannot block (worker thread + MAX_TURNS/MAX_TOOL_CALLS), cannot be required (no SDK/key/failure -> `offline_finding` deterministic engine, engine='rules'), tool results wrapped as `untrusted_evidence`. Triggered from pipeline `_respond` via `investigate_async` at >= high severity, re-investigated on growth (2x events) or escalation behind a 20 s cooldown; pipeline keeps a 60-entry trace ring (`_remember`/`_investigation_context`). Dashboard POST/GET /api/investigation(s) + `dashboard/static/investigations.js` (read-only panel, no Apply button). CLI `python -m tools.investigate [--list|--incident ID|--offline|--publish]`. `anthropic` is an OPTIONAL dep (commented in requirements.txt). Tests: tests/test_investigator.py (stub client exercises the real loop offline).
- V2 LEGIBILITY (no retraining, live model unchanged): `models/explain.py` (stage attribution by swapping RAW CHANNELS of one stage for those of the last window the model called normal, then recomputing ALL features - column-level occlusion does NOT work because the envelope/residual aggregates stay stale; + z-score deviations, confidence, sentence). v2 `assess()` now also returns explanation/suspect_stage/stage_contributions/top_deviations/confidence/reference_age_s/warmup_remaining_s; `_features`/`_score`/`_score_windows` split out of `_probability`; reference window captured whenever a window is normal AND has no bounds violation. `models/operating_points.py` = named presets DERIVED from docs/reports/physical_training_report_v2_swat.json (balanced=shipped 0.5/h, sensitive=1.0/h; nothing invented) via IM_PHYSICAL_SENSITIVITY; IM_PHYSICAL_THRESHOLD still wins. `model_card()` + docs/MODEL_CARD.md, published by the middleware at startup -> dashboard POST/GET /api/model + `dashboard/static/model_card.js` panel. Orchestrator ALERT reason is now `PHYSICAL_MODEL:classifier S3`. Tests: tests/test_physical_explain.py.
- HARDENING: a PASSed command the PLC never settles to is expired after IM_PENDING_TIMEOUT_S (default 15) so its value stops being projected into the cross-register setpoints (middleware_server._expire_pending_if_stale; tests/test_pending_expiry.py). 'cannot reach the PLC' poll error is rate-limited to 1 line/5s - AND SO IS pymodbus's own ERROR line, which used to bypass it entirely (99 library lines vs our 2 in a 30 s outage; AUDIT C3). The rate limit is a logging.Filter on the ROOT HANDLER, not on the 'pymodbus' logger: logger filters are NOT inherited by child loggers and 'pymodbus.logging' is where the records actually originate.
- PHYSICAL INVARIANTS (opt-in `IM_INVARIANTS=1`, ADVISORY: ALERT, never DROP; docs/INVARIANTS.md): deterministic consistency rules learned from NORMAL data only. `swat/invariants.py` (pure NumPy engine, ONE implementation for evaluation and live): three families - rate (sensor speed cap, 10/60 s), state (steady actuator state -> sensor band), balance (tank level change over 60 s vs flows/pumps) - each yields an excess e(t) (<=1 inside the normal range), persistence-filtered, V(t)=max, fires at V>theta. `InvariantSet.fit` proposes on the first 75% of the normal rows and VALIDATES on the last 25% held out in time (misfiring invariants dropped with the reason), then refits survivors; state bands must be tighter than the marginal range, balances must explain the level and beat the rate cap, constant drivers are left out. Live: `models/invariant_monitor.py` (1 Hz buffer, gap reset, rescored once per sample, `merge_into()` adds flag/flagged_by `invariant:<id>`/suspect_stage to the physical advisory; wired in `MultiModelPipeline` + `polling._check_upstream_invariants` rate-limited ALERT + trace hop). Needs ~85 s of telemetry (WARMING_UP). A fitted file describes ONE plant: SWaT-fitted rules do NOT describe the twin (its tank dynamics are compressed in time), so the demo uses `config/invariants_twin.json` (`python -m tools.fit_invariants --twin`, calibrated theta 1.5 on a fresh healthy run; twin report = TWIN measurement, never SWaT). `python -m tools.fit_invariants --data-dir <SWaT>` fits on the pre-attack normal period ONLY and tests on the whole attack period (writes docs/swat_invariants.json etc.). `benchmark/swat_protocol.py` scores them on the same windows next to v2 (section 'Physical-invariant rules': per-theta rows + 'v2 OR invariants'); `build_windows_v2` meta now carries `row`. `python -m tools.live_invariants_check` (~2 min) proves telemetry -> monitor -> upstream ALERT -> dashboard on the real stack (passed: healthy silent 100 s, attack alerted in 4 s). REAL-SWaT DETECTION/FALSE ALARMS ARE NOT MEASURED YET (needs the archive): do not quote a SWaT number for them. They cannot see an actuator-only attack whose consequences are consistent (twin: chlorine breakthrough undetected). Tests: tests/test_invariants.py (68 checks, synthetic plant with exact physics in tests/invariant_plant.py).
- IM_PHYSICAL_THRESHOLD (prob in [0,1]) overrides the v2 model's live operating point WITHOUT retraining (lower = more recall/more alerts; default ~0.788 = 0.5 FA/h). Invalid values ignored. Model stays advisory. train_physical_v2 BUDGETS sweep widened to (0.25,0.5,1,2,4) for the re-run report; package_physical_v2 --budget picks one.
- LIVE PHYSICAL MODEL = v2 (user approved promotion): `models/weights/physical_model_v2.joblib` via `models/package_physical_v2.py`, class `models/physical_model_v2.py` (120 s window, 117 features, HGB prob > 0.7880, advisory, 120 s warm-up, packed inference). `load_physical_model()` selects it; `IM_PHYSICAL_MODEL=v1` or unusable v2 weights -> v1. Held-out test (budget 0.5/h): P .461 R .513 F1 .485 8/10 segs AUC .836 1.17 ep/h. PLC twin runs WITH sensor noise by default (noiseless plant = out-of-distribution -> constant ALERT). Tests: tests/test_physical_v2_live.py.
- PHYSICAL v3 (candidate, NOT promoted, opt-in `IM_PHYSICAL_MODEL=v3`): `research/features_v3.py` (multi-scale + normal-only ridge/PCA features, cross-fitted), `research/train_physical_v3.py` (`--data-dir <archive> --candidate`, event + window metrics, bootstrap CIs, confusion/PR/segment PNGs -> models/candidates/physical_v3/), `research/physical_model_v3.py` (live, same API as v2, adds head_scores/stage_spe/suspect_stage), `research/package_physical_v3.py` (needs `confirm.py retrain physical`, refuses fixture). Tests: tests/test_physical_v3.py, tests/test_physical_v3_live.py. Real-data accuracy UNMEASURED until the user runs the trainer on the SWaT machine; HGB sample_weight is ~70x slow here so the trainer replicates rows instead.
- models/weights (v1 fallback): physical_model.joblib is the previous SWaT-trained model (advisory; operating point 0.5 false alarms/h, clf thr 0.601, variant drift_robust). The old synthetic cyber_model.joblib/training_report.json were deleted (user-confirmed); with no cyber weights the CyberModel reports NO_MODEL = cyber branch is rules-only.
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
- DECISION (P7 gate): learned fusion NOT promoted (docs/reports/fusion_training_report_swat.md); orchestrator = deterministic four-branch rules. `research/train_fusion_swat.py --candidate` stays as the reproducible negative result.
- DECISION (P5 gate): cyber ML candidate NOT promoted. the old synthetic cyber weights were deleted; there are no cyber weights in models/weights.
- Cyber ML = actuator STATE-CHANGE events (1/2 -> 0/100 %); it abstains on writes that don't flip on/off. Old 13-feature weights in models/weights are refused (schema mismatch -> NO_MODEL) until the SWaT candidate is promoted.
- Guard hook only fires on EXECUTING a training script (python ... train*), not on reads; avoid heredocs whose text mentions weights paths / training commands (false positives) - write scripts with the Write tool.
- Wireshark decodes Modbus only on port 502: use the PORT PREFERENCE (`-o mbtcp.tcp.port:5021`), NOT Decode As (it cannot classify requests/responses). To watch BOTH legs in one capture pass ONE RANGE `-o mbtcp.tcp.port:5020,5021`: passing the flag twice makes the second value REPLACE the first and the other leg shows 'Unable to classify as query or response' with no modbus.reference_num (verified, tshark 4.2.2). tx_id is not on the wire; the frame nonce words are (shown in the tracer Arrival hop).
- Laptop topology (user, P10): 4 laptops = Mac A middleware+dashboard+Wireshark, Windows A PLC+tshark, Mac B SCADA, Windows B attacker. IPs are NOT chosen yet (user sets them later; laptops unavailable): docs/topology.md uses placeholders; do NOT run `confirm.py ips` until the user gives addresses.

## File index (open only when relevant)
| Path | Open when |
|---|---|
| `README.md` | user-facing setup/usage; rewritten in Phase 12 |
| `GETTING_STARTED.md`, `scripts/run.sh`, `scripts/run.ps1`, `config/lab.env.example` | first-time 4-laptop setup + one-command launcher per role (reads git-ignored `config/lab.env`; blank -> loopback). `run.sh/ps1 <plc|dashboard|middleware|scada|attacker|check> [args]` |
| `docs/PROJECT_DETAILS.md` (+ `.docx`) | COMPLETE technical description of every component, algorithm, parameter, result (for PPT / report / IEEE paper); numbers copied from benchmarks/ and docs/reports/ - update when they change |
| `MODELS_RATIONALE.md` | changing/justifying the cyber or physical model design |
| `CHECKLIST_VERIFICATION.txt` | legacy self-verification claims (numbers must match repo benchmarks — PART 0 item) |
| `docs/swat_bounds.json` | MEASURED SWaT normal-operation statistics + envelope per sensor (aggregate; source of the twin calibration) |
| `docs/reports/physical_training_report_swat_run1.md` | physical candidate run 1 (pristine test; weak: ROC-AUC 0.66, train 1.0 = overfit, 2.8 alarm episodes/h) |
| `docs/reports/physical_training_report_swat_run2.md` | physical candidate run 2 (REVISED protocol, test not pristine): classifier test ROC-AUC 0.83, F1 0.26-0.37 depending on false-alarm budget |
| `docs/reports/twin_domain_gap_report.md` | SWaT-model on the healthy calibrated twin: 0.25 alarm episodes/h, attacks flagged in 1-4 s (TWIN measurement, not SWaT performance) |
| `tools/twin_domain_gap.py` | measure a PhysicalModel on the calibrated twin (nominal false alarms + synthetic attack latency) |
| `tests/test_bounds_alignment.py` | PART 0 #2 evidence: config/twin vs measured bounds (34 checks) |
| `tests/run_all.py` | `python -m tests.run_all`: runs every test script, saves benchmarks/test_results.json (status, per-script check counts, env, commit); `--with-stress`/`--with-plc` for the 2 that need extras; tests/test_test_runner.py covers its parsing |
| `benchmark/` (`run_all.py`, `latency.py`, `rules_accuracy.py`, `swat_accuracy.py`, `render.py`, `plots.py` -> docs/reports/figures/*.png: SWaT confusion matrices, latency, rule checks, attacker plans, twin; drawn from latest.json by run_all/--render-only) | Phase 11: ONE command `python -m benchmark.run_all [--data-dir <SWaT>]` regenerates benchmarks/latest.json + docs/reports/benchmark_report.md + the README BENCHMARK block (generated, never hand-typed; tests/test_benchmark.py fails on drift). Sections kept apart: latency / held-out SWaT (needs the archive; `benchmarks/swat_accuracy.json` is reused if present) / rule-based constructed scenarios / twin |
| `benchmark/swat_protocol.py`, `swat/scoring.py`, `docs/reports/swat_scoring_comparison.md`, `tests/test_swat_protocol.py` | EVALUATION PROTOCOL for the physical model's numbers. `python -m benchmark.swat_protocol --data-dir <SWaT>` (~20-40 min, needs the archive): rolling blocked cross-validation over ALL 35 attacks (contiguous attack groups, 300 s embargo, thresholds from inner out-of-fold scores so the test fold never sets them, realised false-alarm rate reported next to the budget), five scoring schemes on the same alarms (strict / composite / PA%K 20-50-80 / point-adjust / event level), cluster-bootstrap 95% CIs (attacks and benign hours are the unit), baselines on the same folds (never alarm, CHANCE alarms matched to v2's rate+length = the point-adjust proof, envelope rule, PCA, Isolation Forest, refit rf6), with/without the 10 h segment, per-attack table with a HEURISTIC tag description (SWaT has no attack list; 'visible' = one of the 18 live tags moved, bounds recall). Writes benchmarks/swat_protocol.json + docs/reports/swat_evaluation_protocol.md + figures/protocol_*.png (aggregate only). `--fixture --quick` = code path (writes to a temp dir, never the repo reports); `--fast-hgb` = row replication instead of sample_weight (HGB sample_weight is 15-70x slower on some machines). `--from-report docs/reports/physical_training_report_v2_swat.json` re-scores the SAVED v2 test result under every scheme with NO data (already run: docs/reports/swat_scoring_comparison.md: strict F1 0.485, composite 0.585, PA%K50 0.618, point-adjust 0.685; same alarms, only counting changes; attack-side-only CI). A real-data run has NOT happened yet: do not quote protocol numbers until it has |
| `swat/invariants.py`, `models/invariant_monitor.py`, `tools/fit_invariants.py`, `tools/live_invariants_check.py`, `config/invariants_twin.json`, `docs/INVARIANTS.md`, `docs/reports/twin_invariants_report.md`, `tests/test_invariants.py`, `tests/invariant_plant.py` | the physical-invariant rules (see the PHYSICAL INVARIANTS gotcha): engine, live monitor, fit/measure tool (`--twin` or `--data-dir <SWaT>`), live smoke test, the twin-fitted demo file, the explanation, the twin report, tests |
| `benchmark/evidence_pack.py` | `python -m benchmark.evidence_pack [--no-live]`: panel proof set -> docs/reports/evidence_pack.md + benchmarks/evidence_pack.json + figures/evidence_*.png. Live campaign (spawns PLC/dashboard/middleware on free loopback ports, runs every attacker attack + labelled legit traffic, reads outcomes from /api/flow) + response-layer demo + recorded SWaT/rules results, kept in separate sections. Do NOT run --no-live last: it overwrites the live section. tests/test_evidence_pack.py |
| `core/netconfig.py` | any host/port/env-var question (single source for addresses) |
| `docs/demo_workflow.md` | end-to-end roles/start order/attack/aftermath/recovery (`python -m scada.scada --restore`); dashboard has NO attack controls, Live Network Flow = `/api/flow` + `dashboard/static/flow.js` |
| `docs/topology.md`, `docs/wireshark_setup.md` | Phase 10: 4-laptop roles, env vars, firewall rules, preflight; capture filters, field names, side-by-side demo (verified on loopback with tshark 4.2.2) |
| `tools/sim_four_laptops.py`, `docs/reports/system_flow_verification.md` | ONE command (`python -m tools.sim_four_laptops [--no-capture] [--out <dir>]`) runs the whole 4-role demo on loopback (127.0.0.1 mw+dash / .2 PLC / .3 SCADA / .4 attacker / .9 rogue), captures BOTH legs with tshark + a pcapng, runs 9 phases, then cross-checks capture vs tracer (by nonce) vs blocked log vs dashboard flow and writes the verification report. ~6 min (120 s model warm-up). tests/test_sim_four_laptops.py |
| `tools/verify_three_laptops.py`, `docs/three_laptop_demo.md`, `docs/reports/three_laptop_e2e_verification.md` | the three-laptop layout (middleware+dashboard / PLC+SCADA / attacker): the guide to set it up and present it, the one-machine rehearsal through the real launchers, and its generated evidence report; tests/test_verify_three_laptops.py |
| `tools/check_topology.py`, `tools/wire_correlate.py` | per-laptop preflight (`--role ... --multi`, HMAC fingerprint); match tshark frames to tracer entries by nonce and cross-check PLC leg (tests: test_check_topology, test_wire_correlate) |
| `core/interfaces.py` | machines/registers/bounds, verdict/decision dict shapes, cross-register rules |
| `core/hmac_auth.py` | signed frame format, HMAC build/verify |
| `core/attack_log.py` | blocked-attack JSONL logging |
| `core/forensics.py` | AUDIT A4: append-only JSONL store (traces/incidents/investigations/events) under IM_LOG_DIR, replayed by the dashboard at startup so the record outlives the Flask process |
| `research/__init__.py` | what each rejected experiment was, what it measured, and why it is NOT on the live import path |
| `docs/register_map.md` | register table, ports, contract notes |
| `middleware/middleware_server.py` | SCADA-facing Modbus transport + CLI entry point ONLY (AUDIT A1 split); the datastore hook enqueues, it does not decide |
| `middleware/runtime.py` | config, shared plant state, health snapshot, raw<->engineering conversion (the bottom layer) |
| `middleware/ingest.py` | the decision path: queue + worker, routing a write, building the command, running the pipeline, blocked-attack log, trace publishing |
| `middleware/forwarding.py` | the PLC write path: client, I/O lock, bounded forward queue + single worker, UNDELIVERED reporting |
| `middleware/polling.py` | the PLC read path: poll loop with backoff, pending-command settling, telemetry, upstream envelope alerts |
| `middleware/cyber_agent.py` | rule checks: whitelist, quarantine, FC, register, rate, HMAC, replay, authorization (policy) |
| `middleware/physical_agent.py` | rule checks: bounds, rate-of-change, cross-register, feedback |
| `middleware/trace.py` | Phase 9 packet-tracer: builds the per-tx hop-by-hop trace from the REAL verdicts/model reports/decision (checks after the first failure = NOT_RUN); dashboard `/api/trace(s)`; panel at the bottom of the dashboard; tests/test_trace.py |
| `middleware/investigator.py`, `tools/investigate.py` | the opt-in LLM investigation layer (see gotchas): evidence tools, agent loop, allow-listed proposals, deterministic fallback; CLI to run it by hand |
| `middleware/orchestrator.py` | RULE-BASED four-branch fusion: cyber/physical rule fail -> DROP; rules pass + advisory physical-model flag -> ALERT (forwarded); else PASS; + dashboard forwarding |
| `pipeline/multi_model_pipeline.py` | concurrent cyber/physical branches (rules + models) |
| `models/cyber_model.py` | SWaT-trained CyberModel: Isolation Forest + supervised head over 8 actuator-event features (abstains on non-flip commands) |
| `models/explain.py`, `models/operating_points.py`, `docs/MODEL_CARD.md` | why a flag happened (stage attribution, deviations, confidence), measured operating-point presets, the model card |
| `models/physical_model_v2.py`, `models/package_physical_v2.py` | LIVE physical model v2 (see gotchas), packager (needs `confirm.py retrain physical`), `PackedHistGB` in tree_inference |
| `models/physical_model.py` | v1 (fallback) SWaT-trained PhysicalModel: 30 s windows (1 Hz), 87 features, Isolation Forest + supervised head + measured envelope; abstains on NO_MODEL/WARMING_UP/ERROR; RUL removed |
| `swat/physical_features.py` | physical window features + measured-bounds computation = THE feature implementation shared by training and live |
| `models/train_physical_swat.py` | Phase 6 trainer (`--data-dir <archive> --candidate` or `--fixture`): bounds + model + report; candidates only |
| `tests/test_swat_physical.py` | Phase 6 checks on the synthetic fixture (code paths, live==training scores) |
| `docs/reports/cyber_training_report_swat.md/.json` | REAL SWaT held-out results of the cyber candidate (aggregate only): weak - test ROC-AUC 0.63, F1 0.137 |
| `research/train_cyber_swat.py` | Phase 5 trainer (`--data-dir <archive> --candidate`, or `--fixture`); writes models/candidates/ + report + provenance |
| `research/fusion_scenarios.py`, `research/train_fusion_swat.py` | Phase 7 fusion: ground-truth-labelled scenario set (real SWaT physical rows + constructed cyber-rule failures), cross-fitted train-block physical outputs; `--candidate` trains HistGradientBoosting, threshold by false-alarm budget on val, test once; candidate only |
| `swat/features_v2.py`, `swat/alarm_logic.py`, `models/train_physical_v2.py`, `tests/test_physical_v2.py` | EXPERIMENT to raise F1/recall (research track, live model UNCHANGED): train on train+val, 120 s long-context + cross-sensor residual features, segment-grouped CV with segment-balanced AP, k-of-m persistence + false-alarm-budget thresholds; writes models/candidates/physical_v2/ only; test block used for exactly two refits (disclosed). RAN on real SWaT (docs/reports/physical_training_report_v2_swat.md/.json): selected = long+residual features + HGB, NO persistence at budget 0.5/h -> test precision 0.46, recall 0.51, F1 0.49, 1.17 episodes/h, 8/10 segments, AUC 0.836 (shipped: 0.37/0.26/0.31, 1.79/h, 6/10, 0.8245). Most gain = train+val refit (baseline refit F1 0.47); features add AUC and +1 segment; persistence (3-of-6) HURT on test. NOT live: needs a 120 s live buffer + approval to promote |
| `models/promote_candidate.py` | copy an approved candidate into models/weights/ (refuses without `confirm.py retrain <model>`) |
| `swat/loader.py`, `swat/cyber_events.py` | chronological de-duplicated SWaT stream + segments + calendar blocks / actuator events + THE feature implementation shared by training and live |
| `tests/test_swat_cyber.py`, `tests/swat_fixture.py` | Phase 5 checks on a synthetic SWaT-SHAPED fixture (code paths only, never real metrics) |
| `models/train_models.py`, `models/telemetry_generator.py` | train_models is RETIRED (stub); telemetry_generator is synthetic, tests/benchmarks only |
| `models/tree_inference.py` | packed fast tree inference |
| `models/weights/` | physical_model.joblib (PROMOTED, SWaT-only) + its report (no cyber weights: cyber is rules-only) |
| `plc/plc.py` | PLC: Modbus server around the twin (actuator writes -> targets; sensors read-only) |
| `plc/twin.py` | staged SWaT-style physics (5 stages, 20 points, inter-stage coupling); env IM_TWIN_TIME_SCALE / IM_TWIN_NOISE |
| `tests/test_twin_propagation.py` | Phase 3 check: perturb S1, assert S2..S5 respond in order (`--live` over Modbus) |
| `scada/scada.py` | operator simulator (`--host` pattern to copy) |
| `attacker/attacker.py`, `attacker/scenarios.py` | FIXED scripted attacks (3 DEMO: flood, impossible-command, cross-register) + `random` mode: seeded randomised plans (freeze/ramp/cross-register = SWaT-derived behaviours; impossible-command/flood/replay = SYNTHETIC EXTENSION); `--dry-run`, `--seed`, `--log-file` |
| `tools/swat_attack_profile.py`, `tests/test_attacker_randomization.py` | run locally on SWaT -> docs/swat_attack_profile.json (aggregate; only the ramp range is calibrated, rest design defaults); the test is the P8 distribution check |
| `dashboard/app.py`, `dashboard/static/`, `dashboard/templates/` | Flask dashboard + UI |
| `tests/` | unit/pipeline/stress tests |
| `docs/reports/fusion_training_report_swat.md` | Phase 7 fusion candidate, REAL SWaT held-out: val AUC 0.93 but TEST AUC 0.68 < physical alone 0.83; detects 4/10 test segments vs 6/10; NOT promoted (user decision: rule-based fusion instead) |
| `tools/swat_inspect.py` | Phase 4: run locally on the SWaT folder; prints aggregate-only report + JSON manifest (no raw rows) |
| `.claude/hooks/guard.py`, `.claude/hooks/confirm.py`, `.claude/settings.json` | hook logic / confirmation helper / wiring |

## PART 0 tracker (update at the end of each phase)
| # | Issue | Closed by | Status |
|---|---|---|---|
| 1 | Models trained only on synthetic data | P5 (cyber), P6 (physical) | cyber: trained on real SWaT, result WEAK (docs/reports); user DROPPED cyber ML entirely -> cyber branch is RULES-ONLY by design (negative result = documented limitation); physical: run 2 on real SWaT (test AUC 0.83, F1 ~0.3), PROMOTED as ADVISORY at the 0.5 false-alarm/h operating point (user decision, P6 gate) -> NO synthetic-trained model is active any more |
| 2 | Guessed physical bounds | P6 | CLOSED (docs/swat_bounds.json measured on real SWaT train-normal rows; MACHINES + twin calibrated to it; tests/test_bounds_alignment.py enforces) |
| 3 | Hardcoded 127.0.0.1 | P2 | CLOSED (core/netconfig.py; env+CLI; grep clean) |
| 4 | Orchestrator is AND-gate | P7 | CLOSED (rule-based four-branch table with an ALERT class for the advisory physical model; tests/test_orchestrator.py) |
| 5 | No orchestrator model | P7 | CLOSED AS NEGATIVE RESULT (cross-fitted GBM fusion on real SWaT: test AUC 0.68 < physical alone 0.83, 4/10 vs 6/10 segments; user chose NOT to promote; rule-based fusion is the design; documented limitation) |
| 6 | Attacker deterministic | P8 | CLOSED (randomised plans, distribution check in tests/test_attacker_randomization.py; SWaT-derived ranges pending a local run of tools/swat_attack_profile.py) |
| 7 | Twin is flat list, not SWaT-like | P3 | CLOSED (5 stages x 4 pts, coupled physics, propagation check passes) |
| 8 | No per-layer journey visibility | P9 | CLOSED (decision carries `fusion`; middleware/trace.py; dashboard Packet Tracer panel; live-verified against logs/blocked_attacks.jsonl) |
| 9 | No live network proof | P10 | PARTIAL: docs + tools done, capture/nonce correlation verified on loopback with real tshark; multi-laptop run PENDING hardware + IPs |
| 10 | No reproducible verification | P11 | CLOSED for latency/rules/twin (one command, generated report, drift test); the HELD-OUT SWaT section is recorded (benchmarks/swat_accuracy.json, from the user's console summary: test AUC 0.82, precision 0.37, recall 0.26, 1.79 false-alarm episodes/h, 6/10 segments; per-segment table absent). `run_all --data-dir` re-measures it locally |
| 11 | README is setup only | P12 | open |
| 12 | Junk files | P1 | CLOSED (2 stray scripts deleted; venv/.DS_Store/__MACOSX never in repo, now git-ignored) |
| 13 | PPT/report numbers != repo benchmark | P11, P12 | PARTIAL: README numbers are generated from benchmarks/latest.json; CHECKLIST_VERIFICATION.txt / MODELS_RATIONALE.md flagged STALE, rewritten in P12; the user's PPT must be updated from docs/reports/benchmark_report.md |
