# 01 - Happy path

Real processes, real Modbus/TCP, real HMAC-signed frames. Cold start to first accepted command: **2.1 s**.

## Result

| Flow | Status | Evidence |
|---|---|---|
| happy path: SCADA -> middleware -> PLC -> response | **PASS** | 3 commands seen, 3 PASS, 3 forwarded |
| packet tracer records all seven hops | **PASS** | hops=['arrival', 'cyber_rules', 'cyber_model', 'physical_rules', 'physical_model', 'orchestrator', 'outcome'] |
| PLC confirms the forwarded write (feedback loop closes) | **PASS** | 3 PLC RESPONSE line(s) in the middleware log |

## The path a command actually takes

1. SCADA builds a 27-word frame (version, register, value, 64-bit nonce, 64-bit timestamp, 32-byte HMAC-SHA256) and writes it
   with Modbus FC16 to register 100 on :5021.
2. Cyber Agent, 8 checks in order: source whitelist, quarantine, function code, register allow-list, rate limit, HMAC,
   replay, authorization. Measured p50 **0.0611 ms**.
3. Physical Agent, 5 checks: register known, actuator only, bounds, rate of change, cross-register.
   p50 **0.0334 ms**.
4. Both branches run concurrently; the advisory model scores the 120 s window. p50 **0.0065 ms**,
   p99 **1.9165 ms**.
5. Orchestrator fuses them into PASS / ALERT / DROP. p50 **0.016 ms**.
6. On PASS the middleware opens its own connection to the PLC and writes FC6. The PLC applies it and the poll loop confirms.
7. Decision, trace and telemetry are pushed to the dashboard on a non-blocking worker.

End-to-end in-process decision latency, 3000 commands x 3 repeats:
**p50 0.5042 ms, p95 1.902 ms,
p99 2.8407 ms**.

Full socket round trip measured in this pass under sustained load: {"n": 48, "seconds": 12.2, "p50": 3.09, "p95": 5.71, "max": 9.04}.

## Counts from this run

| Middleware log line | Count |
|---|---|
| PASS | 12 |
| DROP | 50 |
| ALERT | 0 |
| FORWARDED TO PLC | 11 |
| PLC RESPONSE | 9 |
| Traceback | 0 |
| ERROR | 103 |
| WARNING | 3 |

Screenshot: `screenshots/happy-path-dashboard-full.png`, `screenshots/happy-path-packet-tracer.png`.

## Honest note

The happy path is the best-tested part of this system and it behaves correctly. Everything interesting in this audit is in
`02` and `05`.
