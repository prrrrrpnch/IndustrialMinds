# 02 - Edge cases and error paths

| Case | Status | Observed |
|---|---|---|
| command sent while the PLC is down | **PARTIAL** | verdicts=['PASS']; middleware logged a reachability error 101 time(s) |
| middleware reconnects to the PLC by itself | **PASS** | verdicts=['PASS'] forwarded=[True] |
| unsigned write | **PASS** | 1/1 dropped; reasons=['HMAC_MISSING'] |
| tampered frame | **PASS** | 1/1 dropped; reasons=['HMAC_INVALID'] |
| out of bounds | **PASS** | 1/1 dropped; reasons=['OUT_OF_BOUNDS'] |
| write to a read-only sensor | **PASS** | 1/1 dropped; reasons=['WRITE_TO_SENSOR_REGISTER'] |
| raw garbage written to the frame registers | **PASS** | middleware still listening=True; verdicts=['DROP', 'DROP', 'DROP']; client saw: connected True
short frame accepted
all zeros accepted
max ints accepted |
| commands keep flowing with the dashboard dead | **PASS** | sender rc=0, 1.4s for 2 commands (no stall = forwarding is non-blocking) |

## The one that matters: a command "succeeds" while the PLC is dead

The PLC was killed, then a correctly signed, in-bounds command was sent.

- The middleware returned **PASS** to SCADA.
- The dashboard recorded it as PASS.
- The write never reached a PLC, because there wasn't one.
- The middleware logged a reachability error 101 time(s).

An operator watching the dashboard sees a green PASS and has no reason to think the setpoint was not applied. The only signal
is telemetry going stale, which on a slow-moving plant can take minutes. This is the single most dangerous behaviour found in
this pass and is written up in `05-anomalies-found.md`.

## Recovery

When the PLC came back the middleware reconnected by itself with no operator action - verdicts and forwarding resumed. That
part is correct and is worth keeping.

## Abuse input

Every malformed and hostile input was dropped with the correct reason code, and the middleware stayed up:

- unsigned write -> `HMAC_MISSING`
- tampered value with the original tag -> `HMAC_INVALID`
- out-of-range value -> `OUT_OF_BOUNDS`
- write to a read-only sensor -> `WRITE_TO_SENSOR_REGISTER`
- a 3-word frame, 27 zero words, and 27 max-int words -> all dropped; the process did not crash or leak a traceback

Note the Modbus layer **accepts** all three garbage writes (`short frame accepted`, `all zeros accepted`, `max ints accepted`)
and the command is rejected afterwards by the agents. That is by design - the frame registers are a datastore - but it means a
sender cannot tell from the Modbus response whether its command was applied. See `05`.

## Dashboard outage

With the dashboard killed, two commands completed in 1.4 s and the sender saw no error: the forwarding worker is genuinely
non-blocking and the control path does not depend on the UI. Correct.
