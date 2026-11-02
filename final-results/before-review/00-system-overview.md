# 00 - System overview and audit scope

Audited 2026-10-20 14:40 at commit `50f1e49`, branch `claude/serene-feynman-or6ieo`. This folder is the immutable baseline: it records what
the system did BEFORE any audit-driven change. Everything here was produced by running the real system, not by reading it.

## What the system is

An inline security middleware for an industrial control network. A SCADA operator writes setpoints; the middleware sits in the
path, decides, and only then forwards to the PLC.

```
SCADA (Modbus/TCP :5021) -> MIDDLEWARE -> PLC digital twin (Modbus/TCP :5020)
                               |            5 stages, 20 registers
                               |-- Cyber Agent    deterministic rules
                               |-- Physical Agent deterministic rules + ONE advisory ML model
                               |-- Orchestrator   four-branch fusion -> PASS / ALERT / DROP
                               +-> Dashboard (HTTP :5050), blocked-attack log, packet tracer
```

## Entry points

| Surface | Component | What it accepts | Note |
|---|---|---|---|
| Modbus/TCP :5021 | middleware | the only path a control command can take | primary |
| Modbus/TCP :5020 | PLC twin | accepts writes from anyone who can reach it | **not protected by the middleware** |
| HTTP :5050 | dashboard | 19 routes; 11 GET, 7 POST, 1 static | read UI + ingest from middleware |
| CLI | scada / attacker / tools | operator sim, attack client, 9 tools | operator + lab |

## What was exercised in this pass

- a full happy path over real sockets, SCADA -> middleware -> PLC -> response
- 7 failure and abuse paths: PLC killed mid-run, PLC restored, unsigned write, tampered frame, out-of-bounds value,
  write to a read-only sensor, raw garbage at the frame registers, dashboard killed
- every integration point, reached and checked rather than assumed
- dependency, config and secret presence
- the live model's runtime behaviour (size, load, latency, throughput, memory)
- dashboard endpoint latency and process footprint under sustained command load
- the dashboard rendered in a real browser, with console errors captured

## What could NOT be exercised, and why

- **A fresh held-out model evaluation.** The SWaT archive is not in this environment and by project policy never has been. All
  classification metrics in `06-model-metrics.md` are arithmetic on a confusion matrix recorded from a run the user executed on
  their own machine. This is a CRITICAL finding and is written up as one.
- **The 4-laptop deployment.** No hardware and no addresses assigned. A loopback simulation of it exists and was run previously.
- **The LLM investigator's model path.** No SDK and no API key here; only its deterministic fallback ran.

## Verdict of this pass in one line

The system runs, the happy path works end to end, and every attack thrown at it was stopped - but it tells the operator a
command succeeded when the PLC is unreachable, its headline accuracy is below the do-nothing baseline, and its most important
numbers cannot be reproduced in any environment but the user's laptop.
