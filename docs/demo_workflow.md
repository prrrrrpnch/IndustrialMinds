# End-to-end demo workflow: components, attack, aftermath, recovery

This is the operating story of the whole system. Commands are per machine; on one laptop run all of them in separate terminals from the repo root.
Attacks are launched **only from the attacker system**; the dashboard has no attack controls.

## 1. Who runs what

| Role | Machine (4-laptop plan) | Command | Talks to |
|---|---|---|---|
| PLC (digital twin) | Windows A | `python -m plc.plc` | listens :5020 |
| Middleware (Cyber Agent, Physical Agent, Orchestrator) | Mac A | `python -m middleware.middleware_server` | listens :5021, forwards to PLC :5020, posts to dashboard :5050 |
| Dashboard (Live Network Flow, tables, Packet Tracer) | Mac A | `python dashboard/app.py` | browser at :5050 |
| SCADA operator | Mac B | `python -m scada.scada` | middleware :5021 |
| Attacker | Windows B | `python -m attacker.attacker <attack>` | middleware :5021 (and PLC :5020 for `false-injection` only) |
| Observers | Mac A / Windows A | Wireshark or tshark (`docs/wireshark_setup.md`) | passive |

Start order: PLC, dashboard, middleware, SCADA (wait about 40 s for the model window; with the v1 model 30 s). Set `IM_HOST_LABELS="<scada_ip>=SCADA operator,<attacker_ip>=Attacker laptop"` on the dashboard so hosts have names. Addresses come from env vars (`docs/netconfig.py`), never literals.

## 2. Normal operation (what a healthy system looks like)
1. SCADA signs one command every 2 s (FC16 frame with nonce, timestamp, HMAC) and sends it to the middleware.
2. Cyber Agent: whitelist, function code, register allow-list, rate limit, HMAC, replay. Physical Agent: bounds, rate of change, cross-register rules, plus the advisory model. Orchestrator: fusion table.
3. `PASS`: the middleware re-issues the write to the PLC (FC6); the twin moves its actuator target; the middleware polls the sensors and feeds the Physical Agent state.
4. Dashboard: green dots from the SCADA host to the PLC in Live Network Flow; green PASS rows; telemetry near nominal.

## 3. The attack hits
From the attacker laptop, e.g. `python -m attacker.attacker hmac-tamper` (or `random --type ramp`). Where it can be observed, all at once:

| Place | What you see |
|---|---|
| Live Network Flow | a new host (red border, "untrusted") appears; red dots travel to the middleware and **stop at the layer that caught them** (Cyber Agent for source/HMAC/replay/rate, Physical Agent for bounds/rate-of-change/cross-register); per-host counters; ticker with the reason |
| Packet Tracer | click the command: seven hops, first failing check red, the rest `NOT_RUN`, outcome "dropped", log file named |
| Middleware terminal | `[MIDDLEWARE] DROP src=<attacker_ip> ... reason=...` and the logging line |
| Log | `logs/blocked_attacks.jsonl` (one JSON line per DROP; attack type derived from the reason code) and the dashboard Blocked sources table |
| Wireshark (Mac A) | the frame **is on the middleware wire**; on the PLC leg (Windows A) it is **absent**; `python -m tools.wire_correlate` shows both |

## 4. What happens afterwards
* **Dropped commands never reach the PLC**, so the plant does not change and SCADA keeps running normally (its own commands still PASS in the same panel). Nothing needs recovery.
* **Stealthy attacks that stay in bounds** (`ramp`, `freeze`) may be partly forwarded: their early steps can pass with an advisory `ALERT` (yellow). The plant then really drifts. An unsafe combination (e.g. inlet valve closed while the pump runs fast) is stopped at the step that completes it.
* **`false-injection` bypasses the middleware** (a direct PLC write). The middleware cannot see the command; the effect appears as yellow `ALERT` rows on later SCADA commands, a `SENSOR_ENVELOPE_VIOLATION` warning, and on the PLC-leg capture. This is the honest limit of an inline design: it protects only paths that go through it.
* Alerts keep appearing while the plant is displaced (ALERT rows are the advisory model seeing a state it did not train on). That is expected and stops after recovery.

## 5. Recovery and return to normal
1. Stop the attacker. Blocked attempts need no action.
2. If the plant was displaced (ALERT rows persist, telemetry far from nominal), **bring the actuators back through the middleware**: `python -m scada.scada --restore`. It reads the plant, then sends signed half-step commands (never repeating a payload inside the replay window, at most 2 per second) until every actuator is at its operator target, then exits. Everything it sends is judged by the same rules and appears in the flow panel.
3. Sensors (tank levels, pressures) recover physically over a few minutes; the model's alerts stop once the window is healthy again.
4. Resume the operator loop: `python -m scada.scada`. For a fully clean start (e.g. after `false-injection`), restart the PLC.
5. The dashboard **Reset** clears only the tables, not the plant.

## 6. Is the terminal enough for watching packets?
The middleware terminal shows every verdict but one line at a time and without the journey. Use, in this order of usefulness: the **Live Network Flow** panel (who sent it, where it stopped), the **Packet Tracer** (check-by-check detail), and **Wireshark/tshark** (proof on the wire, both legs). A heavier stack (Grafana, ELK, Zeek) would only add infrastructure; the three above already cover what a demo or report needs.

## 7. Single-laptop variant
Run all five processes on loopback. The attacker uses `--source-ip 127.0.0.2` (a different loopback address) so the flow panel shows a distinct untrusted host; set `IM_HOST_LABELS="127.0.0.1=SCADA operator,127.0.0.2=Attacker"`. Without `--source-ip` the attacker shares the SCADA address, which is trusted at the whitelist level, so only the HMAC/replay/physical layers stop it (which is itself a useful demonstration).
