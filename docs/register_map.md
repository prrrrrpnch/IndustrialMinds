# Register Map (Modbus holding registers, unit id 1, addresses 0-19)

Source of truth: `docs/interfaces.py` -> `MACHINES`. Edit there, not here (this table is generated from it).

The plant is a 5-stage water-treatment train modeled on iTrust SWaT (P1 raw water, P2 chemical
dosing, P3 ultrafiltration (+P6 backwash folded in), P4 dechlorination, P5 reverse osmosis). Point
names are SWaT tags. **Actuators** accept SCADA commands; **sensors** are read-only and produced by
the physics in `plc/twin.py` (a write to a sensor register is dropped: `WRITE_TO_SENSOR_REGISTER`).

> Ranges/initial values are SWaT-style nominal PLACEHOLDERS until Phase 6 replaces them with
> bounds measured from SWaT normal-operation data. Wire format: raw = value x 10 (one decimal).

| Reg | Tag | Stage | Kind | Label | Range | Initial | Max slew |
|---|---|---|---|---|---|---|---|
| 0 | MV101 | S1 Raw Water | actuator | Inlet Valve | 0 – 100 % | 32 | 10/s |
| 1 | P101 | S1 Raw Water | actuator | Raw Water Pump | 0 – 100 % | 50 | 8/s |
| 2 | LIT101 | S1 Raw Water | sensor | Raw Tank Level | 0 – 1000 mm | 667 | 200/s |
| 3 | FIT101 | S1 Raw Water | sensor | Inlet Flow | 0 – 40 m3/h | 6.4 | 20/s |
| 4 | P203 | S2 Chemical Dosing | actuator | HCl Dosing Pump | 0 – 100 % | 40 | 8/s |
| 5 | P205 | S2 Chemical Dosing | actuator | NaOCl Dosing Pump | 0 – 100 % | 30 | 8/s |
| 6 | AIT202 | S2 Chemical Dosing | sensor | Dosed-Water pH | 4 – 10 pH | 7.2 | 2/s |
| 7 | FIT201 | S2 Chemical Dosing | sensor | Stage 2 Flow | 0 – 40 m3/h | 8 | 20/s |
| 8 | MV302 | S3 Ultrafiltration | actuator | UF Feed Valve | 0 – 100 % | 80 | 10/s |
| 9 | P302 | S3 Ultrafiltration | actuator | UF Feed Pump | 0 – 100 % | 40 | 8/s |
| 10 | LIT301 | S3 Ultrafiltration | sensor | UF Tank Level | 0 – 1000 mm | 667 | 200/s |
| 11 | DPIT301 | S3 Ultrafiltration | sensor | Membrane dP | 0 – 60 kPa | 13.2 | 10/s |
| 12 | P402 | S4 Dechlorination | actuator | Dechlor Feed Pump | 0 – 100 % | 40 | 8/s |
| 13 | UV401 | S4 Dechlorination | actuator | UV Lamp | 0 – 100 % | 60 | 10/s |
| 14 | LIT401 | S4 Dechlorination | sensor | Dechlor Tank Level | 0 – 1000 mm | 667 | 200/s |
| 15 | AIT402 | S4 Dechlorination | sensor | ORP | 0 – 800 mV | 290 | 150/s |
| 16 | P501 | S5 Reverse Osmosis | actuator | RO High-Pressure Pump | 0 – 100 % | 60 | 8/s |
| 17 | MV503 | S5 Reverse Osmosis | actuator | RO Reject Valve | 0 – 100 % | 30 | 10/s |
| 18 | PIT501 | S5 Reverse Osmosis | sensor | RO Feed Pressure | 0 – 2000 kPa | 1020 | 500/s |
| 19 | FIT501 | S5 Reverse Osmosis | sensor | Permeate Flow | 0 – 10 m3/h | 3.72 | 5/s |

## Inter-stage coupling (plc/twin.py)

S1 pump outflow = S2 flow (FIT201); MV302 splits it between the UF tank (S3) and a return to the raw
tank (S1); S3 pump outflow fills the S4 tank; the S4 pump outflow feeds the RO pump (starved below
about 5 m3/h); dosing pumps act on pH (AIT202) and chlorine, which is carried to S4 and removed by UV401
(ORP, AIT402). UF fouling raises DPIT301 and triggers an automatic backwash that briefly cuts S3 output.
Verified by `python -m tests.test_twin_propagation` (S1 pump change -> S2 ~1.4 s, S3 ~5 s, S4 ~25 s, S5 ~100 s).

## Cross-register correlation rules (Physical Agent, evaluated on projected actuator setpoints)

| Rule | Unsafe when | Why |
|---|---|---|
| RAW_PUMP_DRY_RUN | P101 >= 60 AND MV101 <= 10 | raw-water pump driven hard while the inlet valve is nearly shut - tank drains empty (S1) |
| RAW_TANK_OVERFLOW | MV101 >= 80 AND P101 <= 10 | inlet valve wide open while the transfer pump is nearly stopped - tank overflows (S1) |
| ACID_OVERDOSE_LOW_FLOW | P203 >= 80 AND P101 <= 20 | HCl dosing at high rate while raw-water pump flow is low - pH crash (S2 <- S1) |
| UF_PUMP_DEADHEAD | P302 >= 60 AND MV302 <= 10 | UF feed pump driven hard against a nearly closed feed valve (S3) |
| UF_TANK_OVERFLOW | MV302 >= 80 AND P302 <= 10 | UF feed valve wide open while the UF feed pump is nearly stopped - UF tank overflows (S3) |
| CHLORINE_BREAKTHROUGH | P205 >= 80 AND UV401 <= 10 | heavy hypochlorite dosing while the dechlorination UV lamp is nearly off (S2 -> S4) |
| RO_PUMP_DEADHEAD | P501 >= 70 AND MV503 <= 10 | RO high-pressure pump driven hard against a nearly closed reject valve (S5) |
| RO_FEED_STARVATION | P501 >= 60 AND P402 <= 10 | RO high-pressure pump at high speed while the dechlorination feed pump is nearly off (S5 <- S4) |

Plus two state-dependent rules in `middleware/physical_agent.py`: VALVE_CLOSING_LOW_LEVEL (MV101 closes
>= 25 points while LIT101 is in its bottom 20 %) and RO_PRESSURE_OVERLOAD (P501 > 90 % of max while
PIT501 > 90 % of its range).

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