# 05 - Anomalies found

Everything here was observed in this pass, not inferred from reading code. Each item cites where it lives and what it would
cost in the real world.

---

## A1 — CRITICAL — a command is reported PASS to the operator when the PLC is unreachable

**Where:** `middleware/middleware_server.py`, `_handle_downstream_write` (the DROP branch returns early; the PASS branch
registers the command in `_pending_commands` and *then* calls `_forward_to_plc`).

**Observed:** PLC killed. A correctly signed, in-bounds command sent. Dashboard and middleware both recorded
`verdict=PASS, forwarded=True`. No PLC existed. The middleware logged `ERROR forwarding to PLC` — into a terminal nobody in the
demo is watching — and the operator's view stayed green.

**Exploit / failure scenario:** During the 4-laptop demo the PLC laptop sleeps, its firewall drops, or someone trips the
Ethernet cable. The SCADA operator raises the pump setpoint, sees PASS, and believes the plant is responding. It is not. On a
real plant this is the archetypal control-system incident: the HMI and reality disagree and the operator trusts the HMI. The
existing `_expire_pending_if_stale` (15 s) cleans up internal state but **changes nothing the operator sees**.

**Why it is not caught by the tests:** every pipeline test asserts the decision; none asserts that the decision was *delivered*.

**Fix:** a PASS must be provisional until the PLC acknowledges. Either (a) introduce a fourth verdict — `PASS_UNCONFIRMED` —
surfaced in the dashboard row and the trace outcome hop, resolved to `PASS` on the feedback poll and to `FAILED_DELIVERY` on
expiry; or (b) at minimum, make `_forward_to_plc` failure set the dashboard event's verdict to `UNDELIVERED` rather than
leaving it PASS. Option (a) is correct; option (b) is 20 lines.

---

## A2 — HIGH — the documented log rate-limit does not work; a PLC outage emits ~5 error lines per second

**Where:** `middleware/middleware_server.py:216-219, 1057-1063` (the project's own rate limit) and
`middleware/middleware_server.py:1201` (`logging.getLogger("pymodbus").setLevel(logging.WARNING)`).

**Observed:** during a ~30 s PLC outage the middleware log received **103 ERROR lines**:

| Source | Count | Rate |
|---|---|---|
| `pymodbus.logging` — `Connection to (127.0.0.1, 5020) failed` | **99** | ~5/s |
| `industrialmind.middleware` — the project's own rate-limited line | 2 | 1 per 5 s, as designed |
| `industrialmind.middleware` — forward failure | 1 | once |

**The claim in `CLAUDE.md` — "'cannot reach the PLC' poll error is rate-limited to 1 line/5s" — is true of the line the project
writes and false of what an operator actually sees.** pymodbus logs at ERROR, the filter is set to WARNING, so ERROR passes
straight through. Timestamps confirm bursts of three lines every 0.2 s.

**Failure scenario:** a flaky lab link during a 2-hour demo produces ~36,000 log lines and buries every DROP, every ALERT and
every line the panel might ask about. Log volume is a denial of service against the operator.

**Fix:** `logging.getLogger("pymodbus").setLevel(logging.CRITICAL)` while the PLC is known-down, or attach a rate-limiting
`logging.Filter` to the pymodbus logger. Two lines. Then correct the claim in `CLAUDE.md`.

---

## A3 — HIGH — the PLC poll loop retries 5x/second forever with no backoff

**Where:** `middleware/middleware_server.py`, `_poll_plc_loop` / `_poll_once`, 0.2 s interval.

**Observed:** 99 connection attempts in ~20 s against a dead port, flat rate, no decay.

**Failure scenario:** the PLC is down for an hour. The middleware makes 18,000 connection attempts. On a real OT network that
is scan-like traffic that an IDS will flag, and on a constrained PLC it is a load source. The irony of a security middleware
generating the noisiest traffic on the segment should not be lost.

**Fix:** exponential backoff capped at ~5 s, reset on first success. ~10 lines in the poll loop.

---

## A4 — HIGH — the dashboard depends on three internet CDNs and fails silently without them

**Where:** `dashboard/templates/index.html:14-24`.

**Observed:** in a real headless browser against the running dashboard, the console reported
`ERR_TUNNEL_CONNECTION_FAILED` x2 and **`Chart.js is not loaded.` x5**. In the captured screenshot
(`screenshots/happy-path-dashboard-full.png`) the **"PLC CPU LOAD OVER TIME" panel is visibly empty** — a titled, bordered,
blank box.

| Asset | Host | Effect when unreachable |
|---|---|---|
| Chart.js 4.4.0 | cdn.jsdelivr.net | CPU chart never renders; panel is blank |
| Font Awesome 6.4.0 | cdnjs.cloudflare.com | every icon disappears |
| Inter / JetBrains Mono | fonts.googleapis.com | fallback fonts; layout shifts |

**Failure scenario:** the demo is four laptops on an isolated network — the exact condition under which all three fail. The
project ships `GETTING_STARTED.md`, a launcher and a preflight tool, and none of them checks this. The presenter discovers it
in front of the panel.

**Fix:** vendor all three into `dashboard/static/`. ~600 KB, one-time, removes an entire class of demo-day failure. There is no
argument for a CDN in an air-gapped lab.

---

## A5 — MEDIUM — `/api/health` reports the dashboard's own liveness and nothing else

**Where:** `dashboard/app.py`, `health()`.

**Observed:** with the PLC dead and commands silently failing to deliver, `/api/health` returned
`{"status": "ok", "auth": "open", "traces": 4, "uptime_seconds": 22.9}`.

**Failure scenario:** anyone — a person, a preflight script, a future monitor — who treats this endpoint as "is the system
healthy" gets a green light on a broken plant. An endpoint named `health` that cannot report ill health is worse than no
endpoint, because it manufactures false confidence.

**Fix:** either rename it `/api/alive`, or make it report what it claims: PLC reachability (from the middleware's last poll
result), model status, last telemetry age, and degrade `status` accordingly.

---

## A6 — MEDIUM — dashboard latency was measured nearly empty and will degrade with occupancy

**Where:** `dashboard/app.py` — `_traces` (300), `_incidents` (200), `_investigations` (100), `_scada_to_plc` /
`_plc_to_scada` (100 each).

**Observed:** all endpoints 1.2–1.5 ms p50 — with ~20 traces and 1 incident held. `/api/traces` serialises the newest 60
traces on every poll; `/api/flow` up to 200 events. Every open browser tab polls `/api/traces`, `/api/flow`, `/api/dashboard`
at 1 s and three more panels at 2–10 s.

**Failure scenario:** after an hour of demo traffic with two tabs open, the dashboard is re-serialising several hundred nested
dicts per second under a single-threaded Flask dev server. Not a crash — a slow creep nobody measured.

**Fix:** measure at full occupancy before claiming the numbers. Then either add an `If-None-Match`/seq short-circuit (the flow
endpoint already has `since=`; the others do not) or cache the serialised payload per sequence number.

---

## A7 — MEDIUM — six silent-degradation paths; the dashboard can be arbitrarily wrong without saying so

| Path | Code | Operator sees |
|---|---|---|
| Forward queue full (1000) | `orchestrator._enqueue`, `except queue.Full: pass` | nothing |
| Dashboard unreachable | `orchestrator._forward_loop:59`, `except Exception: pass` | nothing |
| Trace build fails | `pipeline`, `hop_trace = None` | a missing tracer entry |
| Investigation fails | `investigator.investigate_async` | nothing |
| Chart.js missing | browser | an empty panel |
| PASS never delivered | `_expire_pending_if_stale` | nothing (A1) |

Each is individually justified — the control path must never block on the UI, and that is the right priority. But the system's
stated purpose is *visibility*, and there is no indicator anywhere that the view is incomplete.

**Fix:** one counter — `dropped_forwards` — exposed on `/api/health` and rendered as a warning badge when non-zero. The
control path stays non-blocking; the operator stops being lied to by omission.

---

## A8 — MEDIUM — a dropped command is acknowledged at the Modbus layer

**Where:** the frame registers are an ordinary pymodbus datastore; validation happens after the write lands.

**Observed:** `short frame accepted`, `all zeros accepted`, `max ints accepted` — all three garbage writes returned Modbus
success, and all three were then correctly DROPped by the agents. The same is true of every blocked attack.

**Assessment:** **defensible, and worth stating explicitly rather than discovering.** The attacker learns nothing from the
response, which is good. But a *legitimate* SCADA client also cannot tell from Modbus whether its command was applied — the
only feedback channel is the telemetry it reads back. Combined with A1, SCADA has no reliable way to know a command took
effect. Document it, and make the SCADA simulator verify the readback.

---

## A9 — LOW — the default demo runs with every security control switched off

**Observed:** eleven opt-in switches, all off by default. The demo therefore runs with no authorization policy, no per-device
keys, no dashboard token and no quarantine.

**Assessment:** correct for a first-run demo, and the project is explicit about it. The risk is presentational: the README and
`PROJECT_DETAILS` describe these as system capabilities, and a reviewer who runs the default and reads the docs will believe
they are active. **Fix:** the dashboard should show which controls are active — the data is already in
`policy.status()` and `quarantine.status()`, and neither reaches the UI.

---

## A10 — LOW — a 688-check test suite that is green on a system with an A1

**Observed:** 30 scripts, 688 checks, 0 failures.

**Assessment:** the suite is unusually thorough for a project this size and genuinely catches regressions. But it tests
**components against their own specifications**. There is no test that says "when the PLC is down, the operator must not be
told PASS", because nobody wrote that requirement down. A green suite here means "the code does what it was written to do",
not "the system does what it needs to do".

**Fix:** add the handful of tests that encode operator-level requirements rather than component behaviour. A1, A2 and A5 are
all one test each.

---

## What was checked and found clean

Stated for balance; each was actively probed, not assumed.

- Fail-closed: an agent exception drops the command (`AGENT_ERROR`). Zero tracebacks in the middleware across the whole pass.
- Every malformed and hostile input was dropped with the correct reason code; the process never crashed.
- The middleware reconnects to a returning PLC with no operator action.
- The control path does not stall when the dashboard dies (2 commands in 1.4 s with it killed).
- No secret is committed; both secret files are 0600 and git-ignored.
- No SQL, no ORM, no N+1 — every store is a bounded in-memory structure with an explicit cap.
- Latency has three orders of magnitude of headroom; nothing here needs optimising for speed.
- Three ML models were trained, measured and **rejected** on recorded held-out evidence. That is the strongest methodological
  signal in the repository.
