# IndustrialMind — Adversarial End-to-End Audit

Commit `b9fe69f` · branch `claude/serene-feynman-or6ieo` · 2026-10-20
Baseline evidence: `final-results/before-review/` (immutable — not modified after PASS 0)

Every finding below was observed by running the system, not by reading it. Where I could not measure something, I say so.

---

# PASS 1 — Reverse engineering: what it actually is

## Claimed

> "Inline security middleware between a SCADA simulator and a PLC digital twin."

## Actual

```
SCADA ──signed Modbus──> MIDDLEWARE :5021 ──FC6──> PLC :5020
                              │                      ▲
  anyone on the segment ──────┼──────────────────────┘   ← unprotected
                              ▼
                         DASHBOARD :5050  ← holds the ONLY copy of traces/incidents
```

Three mismatches between the stated model and the real one:

**M1 — It protects a *path*, not the *asset*.** The PLC listens on `0.0.0.0:5020` and accepts a write from anyone who can
route to it. This was demonstrated in `docs/reports/system_flow_verification.md`: frame 2018, a direct FC6 write from the
attacker address, reached the PLC and appears in no other record. The project documents this as a limitation, which is honest,
but the name "inline security middleware" invites the reader to believe the plant is protected. It is not; one network path is.

**M2 — `docs/` is a source directory.** 800 LOC across five Python modules (`interfaces.py`, `hmac_auth.py`, `attack_log.py`,
`netconfig.py`, plus `__init__`) imported by every runtime component. `docs/interfaces.py` is the single source of truth for
the register map; `docs/hmac_auth.py` is the cryptographic core. A new engineer greps `docs/` for documentation and finds the
security primitives. The folder name is a lie the whole team has agreed to live with.

**M3 — The dashboard is not a view, it is the database.** Traces (300), incidents (200), investigations (100) and events
(100/direction) exist *only* in the Flask process's memory. Restart the dashboard and the entire forensic record is gone
except `blocked_attacks.jsonl`. A read-only UI that owns the system's only state is an architectural inversion.

## Owns what it shouldn't / depends on what it shouldn't

| Thing | Problem |
|---|---|
| `middleware/middleware_server.py` (1,229 LOC) | owns the Modbus server, the datastore hook, the pipeline call, the PLC client, the poll loop, trace publishing, logging config and the CLI |
| Dashboard | owns durable-ish state it has no business owning |
| Three CDNs | the UI depends on the public internet for an air-gapped lab |
| pymodbus internals | correctness of a shared client depends on an undocumented third-party `RLock` (PASS 2, C2) |

---

# PASS 2 — Logic & correctness

## CRITICAL — C1: the operator is told PASS when the command never reached the PLC

**`middleware/middleware_server.py` → `_handle_downstream_write` → `_forward_to_plc` (line ~600)**

Demonstrated twice, under both realistic failure modes:

| PLC state | Verdict returned | Dashboard shows | Reached PLC | Logged |
|---|---|---|---|---|
| process killed (connection refused) | **PASS** | PASS, forwarded=True | no | `ERROR forwarding to PLC` ×1 |
| black hole (accepts TCP, never answers) | **PASS** | PASS | no | `PLC rejected write` ×2 of 6 |

In the black-hole run the middleware logged `[MIDDLEWARE] PASS src=127.0.0.1 P101=70.00 reason=OK t=3.99ms` — and **zero**
`FORWARDED TO PLC` lines. Only 2 of 6 failed forwards produced any log line at all.

`_forward_to_plc` returns a `bool`. **Nobody checks it.** The verdict was decided and published before the forward was
attempted, and the return value is discarded.

**Failure scenario:** the PLC laptop sleeps mid-demo. The operator raises a pump setpoint, sees green PASS, and believes the
plant responded. It did not. This is the canonical control-room incident — the HMI and physical reality diverge and the
operator trusts the HMI. `_expire_pending_if_stale` cleans internal state after 15 s and changes nothing the operator sees.

**Fix (correct):** a fourth verdict. `PASS_UNCONFIRMED` on forward, resolved to `PASS` by the feedback poll or
`FAILED_DELIVERY` on expiry, surfaced in the dashboard row and the trace outcome hop.
**Fix (minimum, ~20 lines):** check the return value; on false, publish the event with verdict `UNDELIVERED`.

## CRITICAL — C2: an unresponsive PLC collapses the whole middleware to 0.5 commands/second

**Same call path. `_plc_client` is created with no `timeout` → pymodbus default 3 s.**

Measured against a black-hole PLC:

| Metric | Healthy | Black-hole PLC |
|---|---|---|
| Decision latency (internal) | 0.5 ms p50 | 0.7–4.0 ms (unchanged) |
| **Latency seen by SCADA** | **3.1 ms** | **2,002 ms** |
| Throughput | 5/s (rate-limited) | **0.5/s** |
| Second concurrent client | normal | **also 2,002 ms per command** |

The chain: `setValues` (asyncio event loop) → `_process_write` → `process_command` → `.result()` (blocks) → `_forward_to_plc`
→ blocking socket I/O. **The forward happens on the event loop thread.** The Modbus server cannot serve any client while it
waits. A second client's TCP connect succeeds instantly (kernel backlog) and then its commands queue behind the same stall —
textbook head-of-line blocking.

**Failure scenario:** the PLC laptop's Wi-Fi flakes during the demo. Everything grinds to one command every two seconds and
the dashboard stays green. The presenter has no idea why.

**Fix:** move the forward off the event loop (`asyncio.to_thread` or a dedicated forward queue), and set an explicit short
timeout (`ModbusTcpClient(..., timeout=0.5)`). Both are small changes; the timeout alone cuts the damage 6×.

> **RESOLVED (sprint).** Both halves are now done. The timeout/retries fix landed first (`timeout=0.5`, `retries=1`):
> 2,002 ms -> 504 ms. The structural fix followed: the handler now puts the approved command on a bounded FIFO queue
> (`_forward_queue`, 200) drained by **one** dedicated thread (`plc-forwarder`), so the event loop returns as soon as the
> verdict is published. One worker, not a pool, because writes to the same register must keep their order. Every call on
> the shared client is serialised by our own `_plc_io_lock` rather than by a pymodbus internal.
>
> Re-measured against the same black-hole PLC (10 rule-passing commands, `scratchpad/measure_c2.py`):
>
> | | before any fix | after the timeout fix | after the structural fix |
> |---|---|---|---|
> | Latency seen by SCADA | 2,002 ms | 504 ms | **1.9 ms** (median 1.9, max 2.3) |
> | Throughput ceiling | 0.5/s | ~2/s | **~520/s** (the 5/s rate limit binds first) |
>
> All 10 commands were still reported `UNDELIVERED` once the forwarder's own writes timed out, so the C1 guarantee holds
> across the async boundary. A full queue is also reported `UNDELIVERED` (`FORWARD_QUEUE_FULL`) and counted in
> `dropped_forwards`, never dropped in silence. Pinned by `tests/test_sprint_fixes.py`.

## HIGH — C3: the documented log rate-limit does not work

**`middleware_server.py:216-219, 1057-1063` (the project's limiter) vs `:1201`
(`logging.getLogger("pymodbus").setLevel(logging.WARNING)`).**

During a 30 s outage: **99 pymodbus ERROR lines (~5/s)** vs 2 of the project's own rate-limited lines. pymodbus logs at
ERROR; the filter is set to WARNING; ERROR passes straight through. `CLAUDE.md` claims this path is "rate-limited to 1 line/5s".
That is true of the line the project writes and false of what the operator sees. A two-hour flaky demo produces ~36,000 lines
and buries every DROP.

**Fix:** `setLevel(logging.CRITICAL)` on the pymodbus logger, or attach a rate-limiting `logging.Filter`. Then correct the
claim in `CLAUDE.md`.

## HIGH — C4: the PLC poll loop retries 5×/second forever, with no backoff

**`_poll_plc_loop` / `_poll_once`, 0.2 s interval.** 99 connection attempts in 20 s against a dead port, flat rate. Over an
hour: 18,000 attempts. On an OT segment that is scan-like traffic an IDS will flag — the security middleware becomes the
noisiest device on the network.

**Fix:** exponential backoff capped at ~5 s, reset on first success. ~10 lines.

> **RESOLVED (sprint).** `_poll_delay()` keeps the 0.2 s cadence for the first `IM_POLL_BACKOFF_AFTER` (3) consecutive
> failures, then doubles to a ceiling of `IM_POLL_BACKOFF_MAX_S` (5 s), and the first successful read resets it. An hour of
> outage now costs **720 attempts instead of ~18,000**, and recovery is still detected within 5 s - verified live in
> `_verify_fixes.py` ("recovery: commands are PASS again").

## MEDIUM — C5: five unsynchronised globals guard a security control

**`middleware/cyber_agent.py:67-76`** — `_request_timestamps`, `_recent_payloads`, `_seen_nonces`, `_nonce_order`,
`_last_sweep`. No lock. `_check_nonce` does read-then-write:

```python
if nonce in _seen_nonces:   return False
_seen_nonces[nonce] = now   # ← TOCTOU if two threads ever get here
```

Today this is safe **only** because `setValues` is called from the single asyncio event loop. Nothing documents that, no test
asserts it, and the neighbouring modules (`incidents.py:36`, `quarantine.py:44`) *do* take locks — so the codebase is
internally inconsistent about its own threading model. One `asyncio.to_thread` (which C2's fix requires!) silently breaks
replay protection.

**Fix:** add the lock before fixing C2, not after. Five lines.

> **RESOLVED (sprint), and done first as the finding required.** `cyber_agent._state_lock` (an `RLock`, matching
> `incidents.py` / `quarantine.py`) now covers `_check_nonce`, `_check_rate`, `_check_replay`, `_sweep_idle_sources` and
> `reset_state`. It is held only across the table operations - never across the HMAC verification or the policy lookup - so
> the expensive part of a check is still concurrent.
>
> The test is behavioural, not structural: 12 threads replay **one** nonce simultaneously, 25 times over, and exactly one
> acceptance is required each time; 6 threads then hammer the rate/replay tables and the sweep concurrently and must raise
> nothing. `tests/test_sprint_fixes.py`.

## Correct, and worth crediting

- **Replay window arithmetic is right.** Nonce retention is `MAX_CLOCK_SKEW × 2 + 5 = 65 s`, strictly greater than the ±30 s
  freshness window. A frame can never age out of the nonce store while still being accepted as fresh. That is the subtle
  correct choice and most implementations get it wrong.
- **Fail-closed is real.** An agent exception drops the command. Zero tracebacks across the entire audit pass.
- **Check ordering is right.** Cheap checks before cryptography; the rate limiter runs before HMAC so a flood cannot force
  expensive MAC computation.
- **Reconnection works** with no operator action.

---

# PASS 3 — Architecture & design smells

| # | Smell | Location | Verdict |
|---|---|---|---|
| A1 | **God module** — 1,229 LOC owning server, datastore hook, pipeline, PLC client, poll loop, logging, CLI | `middleware_server.py` | split: `transport/`, `forwarding/`, `polling/` |
| A2 | **Business logic in a storage hook** — the entire security pipeline runs as a side effect of `setValues()` | `:260` | the write handler should enqueue, not decide |
| A3 | **Shared mutable client across threads** — one sync `ModbusTcpClient` used by the poll thread and the event loop | `:212, 616, 897` | safe *only* via pymodbus's internal `RLock`. Undocumented dependency on a third-party implementation detail. Give each a client, or own the lock |
| A4 | **State in the view layer** — traces/incidents/investigations exist only in the Flask process | `dashboard/app.py` | restart = total forensic loss |
| A5 | **2¹¹ configurations, 1 tested** — eleven opt-in env flags, all off by default | everywhere | the shipped default has *no* security controls active |
| A6 | **Parallelism that buys nothing** — `ThreadPoolExecutor` then `.result()` immediately | `pipeline:95-99` | two 0.06 ms branches concurrently; the caller blocks anyway. Thread-pool overhead for a measured gain of ~0.03 ms |

**Justified complexity (do not "simplify"):** the packed-tree inference engine (real 10× win), the per-hop packet tracer (the
product's best feature), the `swat/` feature code shared between training and live (prevents train/serve skew — the single
most valuable architectural decision in the repo).

---

# PASS 4 — Dead weight

| Item | Size | Runtime refs | Verdict |
|---|---|---|---|
| `.claude/worktrees/agent-a02b0010b23055660/` — a stale full copy of the repo | **3.2 MB** | 0 | **DELETE.** Git-ignored but on disk and in every grep |
| `models/cyber_model.py` — loaded and called on **every command**, always returns `NO_MODEL` | 0.0136 ms × every command, forever | 4 | **DELETE or gate.** The cyber ML decision was reversed; this is a corpse on the hot path. Keep the trainer as the negative result, delete the runtime class |
| `models/telemetry_generator.py` | synthetic data | 0 | tests/benchmarks only — **move to `tests/fixtures/`** |
| `models/train_models.py` | retired stub | 0 | **DELETE** |
| v3 stack: `features_v3`, `train_physical_v3`, `physical_model_v3`, `package_physical_v3` + 2 test files | **~1,500 LOC** | 0 (env-var only) | **JUSTIFY** — it is a documented negative result with real held-out numbers, which is valuable. But it does not belong in `models/` next to the live model. Move to `research/` |
| `train_fusion_swat`, `fusion_scenarios`, `train_cyber_swat`, `cyber_events` | ~800 LOC | 0 | same: **move to `research/`** |

**The honest total:** roughly **2,300 of ~8,000 product LOC (29%) is experiments that were correctly rejected.** Keeping the
evidence is right. Keeping it on the import path of a control system is not.

**Tests: 4,787 LOC for ~8,000 product LOC.** High, and justified — except that 688 green checks coexist with C1. See PASS 6.

---

# PASS 5 — Security & trust boundaries

Each stated as an exploit, not a category.

**S1 — CRITICAL — Bypass the middleware entirely.** *I am on the OT segment. I open a TCP socket to the PLC on :5020 and write
FC6 register 0 = 0. The inlet valve slams shut.* No signature, no rule, no log, no trace — the middleware never saw it.
Demonstrated: frame 2018 in `system_flow_verification.md`. **Mitigation:** the PLC must refuse writes from anything but the
middleware's address, or sit on a segment only the middleware can route to. Currently neither.

**S2 — HIGH — Impersonate SCADA with the shared secret.** Default mode is one shared HMAC key in `config/lab.env`, copied by
hand to every laptop. *I compromise the attacker laptop — the one deliberately given the key — and now sign commands
indistinguishable from the operator's.* Per-device keys exist (`IM_HMAC_KEYS`) and are **off by default**. No rotation path.
**Mitigation:** make per-device keys the default; ship a rotation procedure.

**S3 — HIGH — Poison the operator's view.** Dashboard POST endpoints (`/api/security-event`, `/api/trace`, `/api/incident`,
`/api/model`, `/api/investigation`, `/api/telemetry`) are **unauthenticated unless `IM_DASHBOARD_TOKEN` is set, which it is not
by default**. *I POST fabricated PASS events and a clean model card while I attack through another path. The operator watches a
fiction.* Worse, `POST /api/reset` is equally open: *one request wipes the entire forensic record.* For a product whose value
proposition is **visibility**, an unauthenticated write channel into the view is the most damaging finding in this pass.
**Mitigation:** make the token mandatory whenever the bind host is not loopback. Refuse to start otherwise.

> **RESOLVED (sprint).** `dashboard.check_bind_is_safe(host)` runs at startup: a bind address that is not provably loopback
> with no `IM_DASHBOARD_TOKEN` aborts the process (exit 2) with a message naming the two ways out. A hostname that cannot be
> resolved to loopback is treated as exposed. Loopback with no token is unchanged, so the one-laptop demo is untouched. The
> launchers (`scripts/run.sh` / `run.ps1`) now pass `DASHBOARD_TOKEN` from `config/lab.env` to both the dashboard and the
> middleware, and `config/lab.env.example` + `GETTING_STARTED.md` say the token is required, not optional, off loopback.
> Pinned by `tests/test_sprint_fixes.py`.

**S4 — MEDIUM — Spoof your way past the whitelist, then weaponise the response.** Trust is source-IP based. On a flat L2 lab,
ARP spoofing gets me SCADA's address. Worse: *with `IM_QUARANTINE` on, I spoof the operator's address, send six forged
frames, and the middleware quarantines **the real SCADA** for 60 s — doubling on repeat.* The response mechanism becomes a
denial-of-service lever against the legitimate operator. **Mitigation:** quarantine on authenticated identity (per-device key),
never on source address alone. This is a design error, not a parameter.

**S5 — MEDIUM — Flask development server.** `dashboard/app.py` runs Werkzeug's dev server. Single-threaded, no hardening, not
intended for exposure. It is bound to loopback by default — but `IM_DASHBOARD_BIND_HOST=0.0.0.0` is documented in
`GETTING_STARTED.md` as the way to let other laptops view it.

**Correct and worth crediting:** no secret is committed; both secret files are 0600 and git-ignored; the signed-frame design
(nonce + timestamp + HMAC-SHA256 over register and value) is sound; checks are ordered cheap-before-expensive; a DROP leaks
nothing useful to the sender.

---

# PASS 6 — Naivety audit

**N1 — "The PLC always answers."** The entire C1/C2 family. The code treats a forward as fire-and-forget while reporting it as
success, and performs blocking I/O on the event loop. **Correct mental model:** in a distributed system every remote call has
three outcomes — success, failure, and *unknown*. This code has no representation for "unknown", which is precisely the state
a hung PLC puts it in.

**N2 — "The internet exists."** Three CDN dependencies in a dashboard built for an air-gapped four-laptop lab. Confirmed in a
real browser: `Chart.js is not loaded.` ×5, and the CPU panel renders as a blank bordered box
(`screenshots/happy-path-dashboard-full.png`). **Correct mental model:** an offline deployment has no runtime dependency it
did not bring with it.

**N3 — "One process, one thread, one world."** Module-level mutable globals as the store for rate limiting, replay and nonce
state, with no lock, in a process that already runs an event loop plus a poll thread plus a forwarding worker plus a
thread pool. It works today by coincidence of scheduling, not by design.

**N4 — "Logging is configured because I configured my logger."** Setting your own logger's level says nothing about the
libraries doing the I/O. 99 lines vs the 2 the design intended.

**N5 — "Green tests mean a working system."** 688 checks pass on a system that tells the operator a command succeeded when it
did not. Every test asserts a component against its own specification; none asserts an operator-level requirement. **Correct
mental model:** tests encode requirements, and "the operator must never see PASS for an undelivered command" is a requirement
nobody wrote down.

**N6 — "Silent degradation is graceful degradation."** Six paths fail silently (queue full, dashboard down, trace build,
investigation, Chart.js, undelivered PASS). Each is individually defensible. Together they mean the dashboard can be
arbitrarily wrong with no indicator. **Correct mental model:** graceful degradation requires *announcing* the degradation.
One `dropped_forwards` counter on `/api/health` fixes most of this.

> **RESOLVED (sprint).** The middleware keeps a health snapshot (`plc_connected`, `consecutive_poll_failures`,
> `dropped_forwards`, `undelivered`, `forward_backlog`) and posts it to `POST /api/middleware-health` every 5 s. `GET
> /api/health` reports the PLC leg from it - `connected` / `unreachable` / `unknown` / `not reported` - degrades on an
> unreachable PLC, on dropped forwards, and on a middleware that has stopped reporting at all (a missing heartbeat is
> itself a degraded state, not silence).
>
> The header badge was the literal string `<strong>ONLINE</strong>` in the markup; it is now driven by `/api/health` every
> 3 s, renders DEGRADED in amber with the reason on the page (not only in a tooltip), and reads UNREACHABLE if the
> dashboard itself stops answering. Pinned by `tests/test_sprint_fixes.py`.

---

# PASS 7 — Officer-level verdict

## 1. System health: **6 / 10**

Unusually disciplined engineering — shared train/serve feature code, generated-not-typed benchmarks, a drift test on its own
numbers, three ML models trained and *rejected* on recorded evidence — undermined by one operator-facing correctness bug and a
demonstrated availability collapse, both on the single most important path in the system. The quality of the surrounding work
makes C1 and C2 more surprising, not less serious: this team clearly can build carefully, and did not apply that care to the
forward path.

## 2. Model health: **4 / 10**

Measurement methodology: **8/10** (per-segment, calendar-block splits, no point-adjust inflation, limitations disclosed).
Model performance: **3/10** (attack-class F1 0.49, misses 48.7% of attack windows, 54% of alarms are false).
Verifiability: **2/10** (reproducible on exactly one laptop in the world).

## 3. Top 3 things that will break in production

| # | What | When |
|---|---|---|
| 1 | **A flaky PLC link stalls the proxy to 0.5 cmd/s while showing green** (C1+C2) | **First demo on real hardware.** Wi-Fi between four laptops is exactly this failure mode |
| 2 | **The dashboard renders with no charts and no icons** (N2) | **The moment it runs on an isolated network** — i.e. the demo as designed |
| 3 | **Log flood buries the evidence** (C3) | Any session longer than ~20 minutes with an imperfect link |

## 4. Top 3 deletions

1. **`models/cyber_model.py` from the runtime path** — a class loaded and invoked on every single command to return `NO_MODEL`,
   for a feature whose decision was reversed.
2. **`.claude/worktrees/` (3.2 MB stale repo copy)** — pollutes every grep.
3. **`models/train_models.py`** (retired stub) and **`telemetry_generator.py`** out of `models/` — synthetic-data generators
   living next to the real model is how synthetic numbers end up in a report.

## 5. What this system gets right

- **The packet tracer.** A per-command, hop-by-hop record showing which checks ran, which failed, and which were `NOT_RUN`. I
  have audited commercial products with worse explainability.
- **Negative results kept with their evidence.** Cyber ML, learned fusion, physical v3 — all built, measured, rejected,
  documented. This is the rarest thing in the repository and the most valuable.
- **Shared feature code between training and inference** (`swat/physical_features.py`), eliminating train/serve skew by
  construction rather than by discipline.
- **Fail-closed by default**, and honest about which controls are advisory.
- **Generated benchmarks with a drift test** — the README numbers cannot silently diverge from the measurements.
- **Replay/freshness arithmetic is correct**, which most implementations get wrong.

## 6. Refactor roadmap

**Do immediately (fires):** — **ALL FOUR DONE**, verified by `final-results/_verify_fixes.py` (14/14) and pinned by
`tests/test_audit_fixes.py`. Measured after: UNDELIVERED now reported instead of PASS; black-hole stall 2,002 ms -> 504 ms;
pymodbus log flood 99 lines -> 1 in a 30 s outage; dashboard renders with every external host blocked, zero console errors,
CPU chart drawing 6,108 pixels where it used to draw none. C2 is MITIGATED, not eliminated: the forward still runs on the
event loop, which is item 6 below.

1. C1 — check `_forward_to_plc`'s return value; publish `UNDELIVERED`. *(~20 lines, 1 hour)*
2. C2 — set `timeout=0.5` on the PLC client. *(1 line, cuts the stall 6×)*
3. C3 — pymodbus logger to CRITICAL or a rate-limiting filter; correct the claim in `CLAUDE.md`. *(2 lines)*
4. N2 — vendor Chart.js, Font Awesome and the fonts into `dashboard/static/`. *(~600 KB, 1 hour, removes a demo-day failure)*

**Do this sprint (structural):** — **all five DONE**, see the RESOLVED notes on each finding above.
5. ~~C5 — add the lock to `cyber_agent` *before* touching threading anywhere else.~~ **DONE, first, as the finding required.**
6. ~~C2 proper — move the forward off the event loop.~~ **DONE** — black-hole PLC: 504 ms -> **1.9 ms** per command.
7. ~~S3 — require `IM_DASHBOARD_TOKEN` whenever the bind host is not loopback; refuse to start otherwise.~~ **DONE** — refuses to start.
8. ~~C4 — exponential backoff in the poll loop.~~ **DONE** — ~18,000 -> **720** attempts/hour against a dead PLC.
9. ~~A6/N6 — a `dropped_forwards` counter and a degradation badge; make `/api/health` report PLC reachability and model status.~~
   **DONE** — `/api/health` reports the PLC leg from a 5 s middleware heartbeat; the header badge is no longer hardcoded.

Evidence: `tests/test_sprint_fixes.py` (40 operator-level checks), `final-results/_verify_fixes.py` (14/14 live, including
the new "the middleware cannot reach the PLC" signal and recovery), and the re-measured C2 table above.

**Do next quarter (architectural):**
10. Split `middleware_server.py`; move the pipeline out of the datastore hook.
11. Move `research/` out of `models/` and `swat/`; rename `docs/` to `core/` (it is source).
12. S1 — bind the PLC to accept writes only from the middleware.
13. S4 — key quarantine to authenticated identity, not source address.
14. Persist traces and incidents outside the UI process.

## 7. Metrics verdict

**Measured correctly. Presented misleadingly. Verifiable by one person on Earth.**

- The protocol is better than most published SWaT work: per-segment evaluation, calendar-block splits, no point-adjust
  inflation, and the non-blind test block disclosed by the project itself.
- **The headline is indefensible.** 95.89% accuracy is *below* the 96.22% a detector that flags nothing would score. Weighted
  F1 0.96 is the benign class (25.5× larger) wearing the model's coat. The only honest figures are **macro F1 0.73**,
  **balanced accuracy 0.74**, and **attack-class F1 0.4853**.
- **Hiding something?** Not deliberately — the per-segment table, the two entirely-missed segments and the protocol caveat are
  all published. But segment 28 is counted as "detected" on **1 flagged window out of 20**, and ten test segments cannot
  support any claim of superiority over anything.
- **CRITICAL:** no one but the user can reproduce any of it. The tooling is correct; the dataset is on one Windows machine.

**Instruction:** never show accuracy without the majority-class baseline beside it. Lead with 8/10 segments detected at 57.5 s
median — that figure is true, operationally meaningful, and defensible.

## 8. The honest one-liner

> A carefully engineered, unusually well-evidenced security proxy that will cheerfully tell the operator a command succeeded
> while the PLC is unreachable, and whose headline accuracy is worse than doing nothing — both fixable in a day, and neither
> caught by 688 green tests.
