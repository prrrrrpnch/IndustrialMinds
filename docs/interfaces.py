# docs/interfaces.py

from __future__ import annotations

from typing import Any, Dict, Optional
#
# Shared contract for every component (PLC, middleware, agents, SCADA,
# attacker, dashboard, evaluation).
#
# MACHINES is the SINGLE source of truth for the plant. Every other module
# derives its registers, bounds, ramp rates, telemetry fields and operator
# profiles from this list, so adding/removing a machine is a one-place edit.

# ---------------------------------------------------------------------------
# Register numbers (kept as named constants for backwards compatibility)
# ---------------------------------------------------------------------------

TANK_PRESSURE = 0
CONVEYOR_SPEED = 1
COOLING_VALVE = 2
HEATER_TEMP = 3
FEED_PUMP = 4
RELIEF_VALVE = 5
AIR_COMPRESSOR = 6
MIXER_SPEED = 7
COOLANT_FLOW = 8
EXHAUST_FAN = 9

# Registers travel on the wire as unsigned 16-bit ints with one decimal of
# precision: raw = round(value * SCALE).
SCALE = 10

# ---------------------------------------------------------------------------
# Machine configuration
#
#   register        Modbus holding-register address
#   name            register / telemetry key
#   machine         human-readable machine name (dashboard + logs)
#   label           short telemetry label
#   min, max, unit  physical safe range
#   initial         start value in the PLC simulation
#   rate_per_sec    how fast the real actuator can move (PLC physics)
#   sig_move        "significant move" threshold used by cross-register rules
#   operator        SCADA operator profile: target setpoint and step size
#   bar_class       existing dashboard progress-bar colour class
# ---------------------------------------------------------------------------

MACHINES = [
    {
        "register": TANK_PRESSURE, "name": "TANK_PRESSURE",
        "machine": "M1 Pressure Tank", "label": "Tank Pressure",
        "min": 0, "max": 100, "unit": "PSI",
        "initial": 50.0, "rate_per_sec": 2.0, "sig_move": 10.0,
        "operator": {"target": 60.0, "step": 1.0},
        "bar_class": "",
    },
    {
        "register": CONVEYOR_SPEED, "name": "CONVEYOR_SPEED",
        "machine": "M2 Conveyor Drive", "label": "Conveyor Speed",
        "min": 0, "max": 120, "unit": "RPM",
        "initial": 0.0, "rate_per_sec": 10.0, "sig_move": 20.0,
        "operator": {"target": 80.0, "step": 2.0},
        "bar_class": "warning",
    },
    {
        "register": COOLING_VALVE, "name": "COOLING_VALVE",
        "machine": "M3 Cooling Valve", "label": "Cooling Valve",
        "min": 0, "max": 90, "unit": "deg",
        "initial": 45.0, "rate_per_sec": 5.0, "sig_move": 15.0,
        "operator": {"target": 60.0, "step": 1.0},
        "bar_class": "info",
    },
    {
        "register": HEATER_TEMP, "name": "HEATER_TEMP",
        "machine": "M4 Reactor Heater", "label": "Heater Temperature",
        "min": 0, "max": 150, "unit": "C",
        "initial": 60.0, "rate_per_sec": 5.0, "sig_move": 20.0,
        "operator": {"target": 80.0, "step": 1.0},
        "bar_class": "warning",
    },
    {
        "register": FEED_PUMP, "name": "FEED_PUMP",
        "machine": "M5 Feed Pump", "label": "Feed Pump Rate",
        "min": 0, "max": 100, "unit": "%",
        "initial": 40.0, "rate_per_sec": 5.0, "sig_move": 15.0,
        "operator": {"target": 55.0, "step": 1.0},
        "bar_class": "",
    },
    {
        "register": RELIEF_VALVE, "name": "RELIEF_VALVE",
        "machine": "M6 Pressure Relief Valve", "label": "Relief Valve",
        "min": 0, "max": 90, "unit": "deg",
        "initial": 45.0, "rate_per_sec": 5.0, "sig_move": 15.0,
        "operator": {"target": 50.0, "step": 1.0},
        "bar_class": "info",
    },
    {
        "register": AIR_COMPRESSOR, "name": "AIR_COMPRESSOR",
        "machine": "M7 Air Compressor", "label": "Air Compressor Speed",
        "min": 0, "max": 3600, "unit": "RPM",
        "initial": 1500.0, "rate_per_sec": 200.0, "sig_move": 300.0,
        "operator": {"target": 1800.0, "step": 20.0},
        "bar_class": "",
    },
    {
        "register": MIXER_SPEED, "name": "MIXER_SPEED",
        "machine": "M8 Mixer Agitator", "label": "Mixer Speed",
        "min": 0, "max": 300, "unit": "RPM",
        "initial": 100.0, "rate_per_sec": 15.0, "sig_move": 30.0,
        "operator": {"target": 120.0, "step": 2.0},
        "bar_class": "warning",
    },
    {
        "register": COOLANT_FLOW, "name": "COOLANT_FLOW",
        "machine": "M9 Coolant Circulation Pump", "label": "Coolant Flow",
        "min": 0, "max": 200, "unit": "L/min",
        "initial": 80.0, "rate_per_sec": 10.0, "sig_move": 20.0,
        "operator": {"target": 100.0, "step": 2.0},
        "bar_class": "info",
    },
    {
        "register": EXHAUST_FAN, "name": "EXHAUST_FAN",
        "machine": "M10 Exhaust Fan", "label": "Exhaust Fan",
        "min": 0, "max": 100, "unit": "%",
        "initial": 50.0, "rate_per_sec": 8.0, "sig_move": 15.0,
        "operator": {"target": 60.0, "step": 1.0},
        "bar_class": "",
    },
]

MACHINE_BY_REGISTER = {m["register"]: m for m in MACHINES}
MACHINE_BY_NAME = {m["name"]: m for m in MACHINES}

ALL_REGISTERS = tuple(m["register"] for m in MACHINES)
NUM_REGISTERS = len(MACHINES)

# Backwards-compatible view used throughout the original code base.
REGISTER_MAP = {
    m["register"]: {"name": m["name"], "min": m["min"], "max": m["max"], "unit": m["unit"]}
    for m in MACHINES
}

# ---------------------------------------------------------------------------
# Cross-register correlation rules (Physical Agent)
#
# Each rule describes a COMBINED plant state that is unsafe even though each
# individual value is inside its own safe range. A command is dropped when
# applying it to the projected plant setpoints makes ALL conditions true.
#   condition = (register, operator, threshold), operator in {">=", "<="}
# ---------------------------------------------------------------------------

CROSS_REGISTER_RULES = [
    {
        "id": "THERMAL_RUNAWAY",
        "description": "heater setpoint high while cooling valve nearly closed - heat cannot be removed",
        "conditions": [(HEATER_TEMP, ">=", 110.0), (COOLING_VALVE, "<=", 25.0)],
    },
    {
        "id": "OVERPRESSURE",
        "description": "feed pump driving flow into tank while relief valve nearly closed - tank cannot vent",
        "conditions": [(FEED_PUMP, ">=", 70.0), (RELIEF_VALVE, "<=", 15.0)],
    },
    {
        "id": "COOLANT_STARVATION",
        "description": "heater setpoint high while coolant circulation nearly stopped",
        "conditions": [(HEATER_TEMP, ">=", 100.0), (COOLANT_FLOW, "<=", 20.0)],
    },
    {
        "id": "HOT_PRESSURIZED_VESSEL",
        "description": "tank pressure and heater temperature both near limits at the same time",
        "conditions": [(TANK_PRESSURE, ">=", 85.0), (HEATER_TEMP, ">=", 125.0)],
    },
]

# ---------------------------------------------------------------------------
# Signed command frame (SCADA -> Middleware, Modbus FC16)
#
# A write-multiple-registers request to FRAME_BASE carrying:
#   [0]      frame version (1)
#   [1]      target machine register
#   [2]      raw value (value * SCALE)
#   [3..6]   64-bit nonce        (4 x 16-bit, big-endian)
#   [7..10]  64-bit timestamp ms (4 x 16-bit, big-endian)
#   [11..26] HMAC-SHA256 tag     (16 x 16-bit = 32 bytes)
# ---------------------------------------------------------------------------

FRAME_BASE = 100
FRAME_VERSION = 1
FRAME_LEN = 27
DATASTORE_SIZE = FRAME_BASE + FRAME_LEN


def make_command(tx_id: str, timestamp: float, source_ip: str, function_code: Optional[int],
                 register: Optional[int], value: float, raw_value: Optional[int] = None,
                 auth: Optional[Dict[str, Any]] = None,
                 source_port: Optional[int] = None) -> Dict[str, Any]:
    """Command dict passed to the agents.

    auth: None when the command arrived without a signed frame, otherwise the
          parsed frame fields (see docs/hmac_auth.parse_frame).
    """
    return {
        "tx_id": tx_id,
        "timestamp": timestamp,
        "source_ip": source_ip,
        "source_port": source_port,
        "function_code": function_code,
        "register": register,
        "value": value,
        "raw_value": raw_value,
        "auth": auth,
    }


def make_verdict(tx_id: str, passed: bool, reason: str, agent: str) -> Dict[str, Any]:
    return {"tx_id": tx_id, "pass": passed, "reason": reason, "agent": agent}


def make_decision(tx_id: str, verdict: str, reason: str, latency_ms: float,
                  direction: str) -> Dict[str, Any]:
    return {
        "tx_id": tx_id,
        "verdict": verdict,      # "PASS" or "DROP"
        "reason": reason,
        "latency_ms": latency_ms,
        "direction": direction,  # "downstream" or "upstream"
    }


def to_raw(value: float) -> int:
    """Engineering value -> 16-bit register value."""
    return max(0, min(65535, int(round(float(value) * SCALE))))


def from_raw(raw: int) -> float:
    """16-bit register value -> engineering value."""
    return raw / SCALE
