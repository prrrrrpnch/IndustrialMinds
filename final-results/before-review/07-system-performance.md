# 07 - System performance

Measured in this environment: Python 3.13.16, Linux, 4 CPU. Two sources — the in-process benchmark (3,000 commands x 3
repeats) and live measurement over real sockets during this audit pass.

## Decision latency per hop (in-process, 9,000 commands)

| Hop | p50 (ms) | mean (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|
| cyber_rules | 0.0611 | 0.0655 | 0.1024 | 0.2082 |
| cyber_model | 0.0122 | 0.0136 | 0.0205 | 0.0513 |
| physical_rules | 0.0334 | 0.0371 | 0.0581 | 0.1086 |
| physical_model | 0.0065 | 0.3283 | 1.3771 | 1.9165 |
| orchestrator | 0.0160 | 0.0193 | 0.0317 | 0.0602 |
| trace_build | 0.0579 | 0.0630 | 0.0988 | 0.1539 |
| branches (concurrent) | 0.3972 | 0.7022 | 1.7721 | 2.5993 |
| **total** | **0.5042** | **0.8088** | **1.9020** | **2.8407** |

The physical model's p50 of 0.0065 ms against a mean of 0.33 ms is the warm-up: most windows abstain instantly, and the ones
that actually score cost ~1–2 ms. The tail (p99 2.84 ms) is dominated by it.

**Verdict: latency is a non-issue.** A 2.8 ms p99 on a 1 Hz control loop is three orders of magnitude of headroom. Nothing in
this system needs optimising for speed, and any effort spent there is misdirected.

## Full socket round trip (measured live, under sustained load)

48 signed commands over 12.2 s through the real middleware to the real PLC:
**p50 3.09 ms, p95 5.71 ms, max 9.04 ms.**

The ~2.5 ms over the in-process figure is Modbus framing plus two TCP hops. Still trivial.

## Throughput and its real ceiling

| Measure | Value |
|---|---|
| Model assessments | 863 /s single-threaded |
| Decision pipeline | ~1,200 /s implied by p50 |
| **Cyber-agent rate limit** | **5 commands/s per source — the real ceiling** |

Throughput is capped by policy, not by capability, by a factor of ~240. That is the correct design for a control network and
worth stating plainly: this system is not throughput-constrained and never will be.

## Dashboard endpoint latency (30 requests each, live)

| Endpoint | p50 (ms) | p95 (ms) | max (ms) | errors |
|---|---|---|---|---|
| /api/health | 1.3 | 1.9 | 2.1 | 0 |
| /api/dashboard | 1.3 | 1.7 | 1.8 | 0 |
| /api/traces | 1.3 | 1.5 | 1.6 | 0 |
| /api/flow | 1.2 | 1.7 | 1.8 | 0 |
| /api/incidents | 1.2 | 1.6 | 1.7 | 0 |
| /api/model | 1.2 | 1.9 | 2.3 | 0 |
| /api/blocked-ips | 1.5 | 1.9 | 3.2 | 0 |
| / (full page) | 2.6 | 3.2 | 22.3 | 0 |

Zero 4xx, zero 5xx across 240 requests. All state is in bounded in-memory structures, so these are dictionary reads.

**But:** these timings were taken with ~20 traces and 1 incident held. The dashboard retains up to 300 traces, 200 incidents,
100 investigations and 100 events per direction. `/api/traces` serialises the newest 60 traces on **every** 1 s poll from every
open browser tab, and `/api/flow` serialises up to 200. Latency will grow with occupancy and was not measured at full
occupancy. See `05` item A6.

## Database

**None.** No SQL, no ORM, no query plan, no N+1. Every store is an in-memory `deque` or `OrderedDict` with an explicit cap,
plus one append-only JSONL file. For a demo rig this is the right call and removes an entire class of failure. It also means
**every record is lost on restart** except the blocked-attack log.

## Process footprint (steady state, idle-ish)

| Process | RSS | CPU (2 s) | Threads | Open FDs |
|---|---|---|---|---|
| PLC twin | 31.0 MB | 0.5% | 4 | 8 |
| Dashboard | 37.9 MB | 0.0% | 2 | 4 |
| **Middleware** | **169.2 MB** | 0.5% | 11 | 8 |

The middleware's 169 MB is scikit-learn, numpy and the packed trees. Fine on a laptop; it is the number to quote if anyone asks
about an embedded target, where it would be disqualifying.

Cold start, measured directly: PLC listening in **0.10 s**; middleware listening in **1.31 s**, of which ~1.0 s is importing
scikit-learn/numpy/joblib and **0.12 s is loading the model itself**. The middleware does not accept traffic until the model is
loaded, but that cost is import time, not model time.

*(Correction made during this pass: an earlier measurement reported a 4.56 s model load. That figure was taken with
`tracemalloc` active, which instruments every allocation and inflated it by ~38x. The number above is the clean one. Recorded
here rather than quietly replaced, because a baseline that hides its own corrections is not a baseline.)*

## Retries and timeouts

| Path | Timeout | Retry | Backoff |
|---|---|---|---|
| Middleware -> PLC poll | pymodbus default | every **0.2 s**, forever | **none** |
| Middleware -> PLC forward | pymodbus default | none (fails the command) | — |
| Middleware -> dashboard | 1.0 s | none (dropped) | — |
| Dashboard queue | — | drops when full (1000) | — |
| Investigator -> API | SDK default | SDK (2) | SDK exponential |

The PLC poll loop retries **5 times a second indefinitely with no backoff**. During the 30 s PLC outage in this audit it
produced **99 pymodbus ERROR lines**, ~5 per second. See `05` item A2 — this is a real defect, not a cosmetic one.

## Silent background behaviour found

| Behaviour | Where | Visible to an operator? |
|---|---|---|
| Dashboard forward dropped when the queue is full | `orchestrator._enqueue`, `except queue.Full: pass` | **No** |
| Dashboard forward fails (dashboard down) | `orchestrator._forward_loop`, bare `except: pass` | **No** |
| Trace build failure | `pipeline`, logged then `hop_trace = None` | Log only |
| Investigator failure | `investigate_async`, caught | Log only |
| Chart.js fails to load | browser console | **No** — the panel is just empty |
| A PASS that never reached the PLC | `_expire_pending_if_stale` after 15 s | Log only |

Six silent-degradation paths. Each is individually defensible (the control path must not block on the UI) and collectively
they mean **the dashboard can be arbitrarily wrong without saying so**. For a system whose entire value proposition is
visibility, that is the structural weakness of the design.
