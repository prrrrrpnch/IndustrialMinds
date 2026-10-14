# Register Map (Modbus holding registers, unit id 1, addresses 0-9)

Source of truth: `docs/interfaces.py` -> `MACHINES`. Edit there, not here.

| Register # | Name            | Machine                  | Safe Range   | Ramp rate  |
|------------|-----------------|--------------------------|--------------|------------|
| 0          | TANK_PRESSURE   | M1 Pressure Tank         | 0 – 100 PSI  | 2 PSI/s    |
| 1          | CONVEYOR_SPEED  | M2 Conveyor Drive        | 0 – 120 RPM  | 10 RPM/s   |
| 2          | COOLING_VALVE   | M3 Cooling Valve         | 0° – 90°     | 5 °/s      |
| 3          | HEATER_TEMP     | M4 Reactor Heater        | 0 – 150 °C   | 5 °C/s     |
| 4          | FEED_PUMP       | M5 Feed Pump             | 0 – 100 %    | 5 %/s      |
| 5          | RELIEF_VALVE    | M6 Pressure Relief Valve | 0° – 90°     | 5 °/s      |
| 6          | AIR_COMPRESSOR  | M7 Air Compressor        | 0 – 3600 RPM | 200 RPM/s  |
| 7          | MIXER_SPEED     | M8 Mixer Agitator        | 0 – 300 RPM  | 15 RPM/s   |
| 8          | COOLANT_FLOW    | M9 Coolant Circulation Pump | 0 – 200 L/min | 10 L/min/s |
| 9          | EXHAUST_FAN     | M10 Exhaust Fan          | 0 – 100 %    | 8 %/s      |

## Cross-register correlation rules (Physical Agent)

| Rule                    | Unsafe when                                   |
|-------------------------|-----------------------------------------------|
| THERMAL_RUNAWAY         | HEATER_TEMP >= 110 AND COOLING_VALVE <= 25    |
| OVERPRESSURE            | FEED_PUMP >= 70 AND RELIEF_VALVE <= 15        |
| COOLANT_STARVATION      | HEATER_TEMP >= 100 AND COOLANT_FLOW <= 20     |
| HOT_PRESSURIZED_VESSEL  | TANK_PRESSURE >= 85 AND HEATER_TEMP >= 125    |
| VALVE_CLOSING_LOW_PRESSURE (original) | cooling valve closes >= 15° while tank < 15 PSI |
| CONVEYOR_PRESSURE_OVERLOAD (original) | conveyor > 108 RPM while tank > 90 PSI |

## Signed command frame (SCADA -> middleware)

FC16 write of 27 registers at address 100: version, register, raw value,
64-bit nonce, 64-bit timestamp (ms), 32-byte HMAC-SHA256 tag. See `docs/hmac_auth.py`.

## Ports (settled convention — use these everywhere)

| Component  | Port | Notes                                      |
|------------|------|---------------------------------------------|
| PLC        | 5020 | `plc.py` — Modbus TCP server                |
| Middleware | 5021 | `middleware_server.py` — Modbus TCP server, faces SCADA/attacker |

`scada.py`, `attacker.py`, and `docs/wireshark_setup.md` must all point at 5021 for the middleware and 5020 for the PLC. If you're building against a different port, stop and check with the team first — mismatched ports are the #1 cause of "can't connect" during integration.

## Interface contract notes

- **`physical_agent.check_feedback()` returns `tx_id=""` by design.** It has no way to know which command it's confirming — that's the caller's context, not its own. Whoever calls it (currently: `middleware_server.py`) must set the real `tx_id` on the returned verdict *before* passing it into `orchestrator.decide()`, e.g. `verdict["tx_id"] = original_tx_id`. Skipping this means every upstream decision in the log has a blank `tx_id`.