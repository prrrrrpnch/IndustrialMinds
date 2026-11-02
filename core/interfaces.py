# core/interfaces.py

from __future__ import annotations

from typing import Any, Dict, Optional
#
# Shared contract for every component (PLC twin, middleware, agents, SCADA,
# attacker, dashboard, evaluation).
#
# MACHINES is the SINGLE source of truth for the plant. Every other module
# derives its registers, bounds, ramp rates, telemetry fields and operator
# profiles from this list, so adding/removing a point is a one-place edit.
#
# The plant is a 5-stage water-treatment train modeled on iTrust's SWaT
# (P1 raw water -> P2 chemical dosing -> P3 ultrafiltration -> P4
# dechlorination -> P5 reverse osmosis; SWaT's P6 backwash is folded into
# stage 3 as an automatic UF-backwash cycle). Point names are SWaT tags.
#
# IMPORTANT (PART 0 / dataset policy): min/max/initial values below are
# MEASURED from SWaT normal-operation data (docs/swat_bounds.json); tests/test_bounds_alignment.py enforces it.
# ---------------------------------------------------------------------------

# Registers travel on the wire as unsigned 16-bit ints with one decimal of
# precision: raw = round(value * SCALE).
SCALE = 10

# kind: "actuator" -> SCADA may write it (a command)
#       "sensor"   -> read-only; produced by the plant physics (plc/twin.py)
# (register, tag, stage, kind, label, description, min, max, unit, initial,
#  rate_per_sec, sig_move, operator_step, bar_class)
_POINTS = [
    # Sensor ranges/initial values are MEASURED (docs/swat_bounds.json, SWaT train-block NORMAL rows):
    #   initial = measured median; min/max = measured min/max widened ~25 % and rounded (physical display range);
    #   the tighter normal envelope used by the envelope rule lives in swat_bounds.json.
    # Actuator initial values are the NOMINAL setpoints (pumps/UV "on" = >= 50 %, like SWaT's state 2).
    # --- Stage 1: raw water (SWaT P1) ---------------------------------------
    (0,  "MV101",  1, "actuator", "Inlet Valve",          "raw-water inlet motorised valve",       0, 100, "%",    55.0, 10.0, 25.0, 2.0, "info"),
    (1,  "P101",   1, "actuator", "Raw Water Pump",       "raw-water transfer pump speed",         0, 100, "%",    70.0,  8.0, 25.0, 2.0, ""),
    (2,  "LIT101", 1, "sensor",   "Raw Tank Level",       "raw water tank level",                  0, 1200, "mm", 526.1, 200.0, 250.0, 0.0, ""),
    (3,  "FIT101", 1, "sensor",   "Inlet Flow",           "inlet flow into raw water tank",        0, 3.5, "m3/h", 2.39,   5.0,   1.0, 0.0, "info"),
    # --- Stage 2: chemical dosing (SWaT P2) ---------------------------------
    (4,  "P203",   2, "actuator", "HCl Dosing Pump",      "hydrochloric acid dosing pump",         0, 100, "%",    60.0,  8.0, 25.0, 2.0, "warning"),
    (5,  "P205",   2, "actuator", "NaOCl Dosing Pump",    "sodium hypochlorite dosing pump",       0, 100, "%",    60.0,  8.0, 25.0, 2.0, "warning"),
    (6,  "AIT202", 2, "sensor",   "Dosed-Water pH",       "pH after chemical dosing",              5, 10,  "pH",   8.37,   1.0,   0.5, 0.0, "warning"),
    (7,  "FIT201", 2, "sensor",   "Stage 2 Flow",         "flow through chemical dosing stage",    0, 3.5, "m3/h", 2.44,   5.0,   1.0, 0.0, "info"),
    # --- Stage 3: ultrafiltration (SWaT P3, backwash folded in from P6) -----
    (8,  "MV302",  3, "actuator", "UF Feed Valve",        "ultrafiltration feed motorised valve",  0, 100, "%",    98.0, 10.0, 25.0, 2.0, "info"),
    (9,  "P302",   3, "actuator", "UF Feed Pump",         "ultrafiltration feed pump speed",       0, 100, "%",    70.0,  8.0, 25.0, 2.0, ""),
    (10, "LIT301", 3, "sensor",   "UF Tank Level",        "ultrafiltration tank level",            0, 1200, "mm", 918.4, 200.0, 250.0, 0.0, ""),
    (11, "DPIT301",3, "sensor",   "Membrane dP",          "UF membrane differential pressure",     0, 60,  "kPa",  19.8,  10.0,  10.0, 0.0, "warning"),
    # --- Stage 4: dechlorination (SWaT P4) ----------------------------------
    (12, "P402",   4, "actuator", "Dechlor Feed Pump",    "dechlorination feed pump speed (SWaT P402 is the running S4 pump; P401 is idle)", 0, 100, "%", 70.0,  8.0, 25.0, 2.0, ""),
    (13, "UV401",  4, "actuator", "UV Lamp",              "UV dechlorinator intensity",            0, 100, "%",    70.0, 10.0, 25.0, 2.0, "warning"),
    (14, "LIT401", 4, "sensor",   "Dechlor Tank Level",   "dechlorination tank level",             0, 1200, "mm", 891.9, 200.0, 250.0, 0.0, ""),
    (15, "AIT402", 4, "sensor",   "ORP",                  "oxidation-reduction potential",         100, 350, "mV", 163.7, 100.0,  60.0, 0.0, "warning"),
    # --- Stage 5: reverse osmosis (SWaT P5) ---------------------------------
    (16, "P501",   5, "actuator", "RO High-Pressure Pump","reverse-osmosis high-pressure pump",    0, 100, "%",    80.0,  8.0, 25.0, 2.0, ""),
    (17, "MV503",  5, "actuator", "RO Reject Valve",      "RO concentrate (reject) valve (twin-only synthetic: no SWaT counterpart)", 0, 100, "%", 30.0, 10.0, 25.0, 2.0, "info"),
    (18, "PIT501", 5, "sensor",   "RO Feed Pressure",     "RO membrane feed pressure",             0, 350, "kPa", 252.0, 200.0, 100.0, 0.0, "warning"),
    (19, "FIT501", 5, "sensor",   "Permeate Flow",        "RO permeate flow",                      0, 2.5, "m3/h", 1.72,   3.0,   1.0, 0.0, "info"),
]

STAGES = {
    1: {"id": "S1", "name": "Raw Water",          "swat": "P1"},
    2: {"id": "S2", "name": "Chemical Dosing",    "swat": "P2"},
    3: {"id": "S3", "name": "Ultrafiltration",    "swat": "P3 (+P6 backwash)"},
    4: {"id": "S4", "name": "Dechlorination",     "swat": "P4"},
    5: {"id": "S5", "name": "Reverse Osmosis",    "swat": "P5"},
}

# Points that exist only in this twin (SWaT's P5 has pumps and sensors but no motorised valve):
# they are covered by the rule-based agents and generic features only, never by SWaT-trained models.
SYNTHETIC_ONLY_TAGS = {"MV503"}

MACHINES = [
    {
        "register": reg, "name": tag, "machine": f"S{stage} {desc}", "label": label,
        "stage": stage, "stage_name": STAGES[stage]["name"], "kind": kind,
        "min": lo, "max": hi, "unit": unit,
        "initial": float(init), "rate_per_sec": float(rate), "sig_move": float(sig),
        # SCADA operator profile (actuators only): hold near the nominal setpoint
        "operator": ({"target": float(init), "step": float(step)} if kind == "actuator" else None),
        "bar_class": bar,
        # False = twin-only SYNTHETIC point with no SWaT counterpart (no SWaT column to learn from)
        "swat_backed": tag not in SYNTHETIC_ONLY_TAGS,
    }
    for (reg, tag, stage, kind, label, desc, lo, hi, unit, init, rate, sig, step, bar) in _POINTS
]

# Register numbers as named constants (SWaT tags).
MV101, P101, LIT101, FIT101 = 0, 1, 2, 3
P203, P205, AIT202, FIT201 = 4, 5, 6, 7
MV302, P302, LIT301, DPIT301 = 8, 9, 10, 11
P402, UV401, LIT401, AIT402 = 12, 13, 14, 15
P501, MV503, PIT501, FIT501 = 16, 17, 18, 19

MACHINE_BY_REGISTER = {m["register"]: m for m in MACHINES}
MACHINE_BY_NAME = {m["name"]: m for m in MACHINES}

ALL_REGISTERS = tuple(m["register"] for m in MACHINES)
NUM_REGISTERS = len(MACHINES)
ACTUATOR_REGISTERS = tuple(m["register"] for m in MACHINES if m["kind"] == "actuator")
SENSOR_REGISTERS = tuple(m["register"] for m in MACHINES if m["kind"] == "sensor")

# Backwards-compatible view used throughout the original code base.
REGISTER_MAP = {
    m["register"]: {"name": m["name"], "min": m["min"], "max": m["max"], "unit": m["unit"]}
    for m in MACHINES
}

# ---------------------------------------------------------------------------
# Cross-register correlation rules (Physical Agent)
#
# Each rule describes a COMBINED ACTUATOR state that is unsafe even though each
# value is inside its own safe range. A command is dropped when applying it to
# the projected actuator setpoints makes ALL conditions true. Several rules span
# stages on purpose: the stages are physically coupled (see plc/twin.py).
#   condition = (register, operator, threshold), operator in {">=", "<="}
# ---------------------------------------------------------------------------

CROSS_REGISTER_RULES = [
    {
        "id": "RAW_PUMP_DRY_RUN",
        "description": "raw-water pump driven hard while the inlet valve is nearly shut - tank drains empty (S1)",
        "conditions": [(P101, ">=", 60.0), (MV101, "<=", 10.0)],
    },
    {
        "id": "RAW_TANK_OVERFLOW",
        "description": "inlet valve wide open while the transfer pump is nearly stopped - tank overflows (S1)",
        "conditions": [(MV101, ">=", 80.0), (P101, "<=", 10.0)],
    },
    {
        "id": "ACID_OVERDOSE_LOW_FLOW",
        "description": "HCl dosing at high rate while raw-water pump flow is low - pH crash (S2 <- S1)",
        "conditions": [(P203, ">=", 80.0), (P101, "<=", 20.0)],
    },
    {
        "id": "UF_PUMP_DEADHEAD",
        "description": "UF feed pump driven hard against a nearly closed feed valve (S3)",
        "conditions": [(P302, ">=", 60.0), (MV302, "<=", 10.0)],
    },
    {
        "id": "UF_TANK_OVERFLOW",
        "description": "UF feed valve wide open while the UF feed pump is nearly stopped - UF tank overflows (S3)",
        "conditions": [(MV302, ">=", 80.0), (P302, "<=", 10.0)],
    },
    {
        "id": "CHLORINE_BREAKTHROUGH",
        "description": "heavy hypochlorite dosing while the dechlorination UV lamp is nearly off (S2 -> S4)",
        "conditions": [(P205, ">=", 80.0), (UV401, "<=", 10.0)],
    },
    {
        "id": "RO_PUMP_DEADHEAD",
        "description": "RO high-pressure pump driven hard against a nearly closed reject valve (S5)",
        "conditions": [(P501, ">=", 70.0), (MV503, "<=", 10.0)],
    },
    {
        "id": "RO_FEED_STARVATION",
        "description": "RO high-pressure pump at high speed while the dechlorination feed pump is nearly off (S5 <- S4)",
        "conditions": [(P501, ">=", 60.0), (P402, "<=", 10.0)],
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
          parsed frame fields (see core/hmac_auth.parse_frame).
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
        "verdict": verdict,      # "PASS", "ALERT" (forwarded, advisory flag) or "DROP"
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
