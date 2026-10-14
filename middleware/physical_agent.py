"""
middleware/physical_agent.py — Physical Agent for the Industrial Mind middleware.

Downstream (SCADA -> PLC):
  check_command(command, current_state) -> verdict
  Four rule layers per command (all deterministic RULES, not models):
    0. Actuator-only      — sensor registers (LIT/FIT/AIT/DPIT/PIT) are produced by
                            the plant physics and can never be commanded
                            -> WRITE_TO_SENSOR_REGISTER.
    1. Hard bounds        — value must be within the REGISTER_MAP safe range.
    2. Rate-of-change     — value must not imply a jump that the physical plant
                            cannot achieve between the last known timestamp and
                            the command timestamp.
    3. Cross-register     — certain combinations of simultaneous requested moves
                            are physically impossible (e.g. valve slamming shut
                            while pressure is already low), plus the
                            config-driven correlation rules in
                            docs/interfaces.CROSS_REGISTER_RULES: each command
                            may be safe on its own, but the COMBINED projected
                            plant state across several machines is unsafe
                            -> CROSS_REGISTER_VIOLATION.

Upstream (PLC -> SCADA):
  check_feedback(commanded_value, reported_value, register) -> verdict
  Compares what was last commanded with what the PLC is now reporting.
  A small lag is expected (physics ramp). A large mismatch is flagged.

current_state contract (passed in by the caller — middleware or test harness):
  {
      "registers": {
          <register>: <float>,   # current PLC value, one entry per machine
          ...                    # (see docs/interfaces.MACHINES)
      },
      "setpoints": {             # OPTIONAL - latest approved target per register
          <register>: <float>,   # (pending setpoints the PLC is still ramping to).
      },                         # Falls back to "registers" when absent.
      "timestamp": <float>   # time.time() when telemetry was captured
  }
  Alternatively, register keys may be the string names — both are tolerated
  (see _get_value helper).
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple

from docs.interfaces import (
    make_verdict,
    REGISTER_MAP,
    MACHINES,
    MACHINE_BY_REGISTER,
    CROSS_REGISTER_RULES,
    ACTUATOR_REGISTERS,
    MV101,
    LIT101,
    P501,
    PIT501,
)

# ── Rate-of-change limits (degrees/sec, RPM/sec, PSI/sec) ──────────────────
# Mirror the PLC's _RATE_PER_SEC so we know what's physically achievable.
# The Physical Agent gives 10 % headroom on top so marginal-but-legitimate
# commands aren't falsely dropped.
_RATE_HEADROOM = 1.10
_RATE_LIMIT_PER_SEC = {
    m["register"]: m["rate_per_sec"] * _RATE_HEADROOM for m in MACHINES
}

# Minimum time window used for rate calculations (avoids division by zero and
# protects against two commands arriving in the same millisecond).
_MIN_DT = 0.05   # seconds

# ── Feedback tolerance ──────────────────────────────────────────────────────
# On the upstream path, the PLC is still ramping toward its target, so some
# lag is expected. We allow up to 20 % of the full safe range as normal lag.
# Beyond that, something is wrong (sensor fault, spoofed telemetry, etc.).
_FEEDBACK_TOLERANCE_FRACTION = 0.20   # 20 % of the register's safe range

# ── Cross-register consistency thresholds ──────────────────────────────────
# How much a value must change (absolute) to count as a "significant move".
_SIG_MOVE = {m["register"]: m["sig_move"] for m in MACHINES}


# ───────────────────────────────────────────────────────────────────────────
# Internal helpers
# ───────────────────────────────────────────────────────────────────────────

def _get_value(current_state: dict, register: int) -> Optional[float]:
    """Return current register value from current_state, tolerating either
    integer keys or string name keys."""
    regs = current_state.get("registers", {})
    if register in regs:
        return regs[register]
    name = REGISTER_MAP[register]["name"]
    if name in regs:
        return regs[name]
    return None


def _safe_range(register: int) -> Tuple[float, float]:
    """Returns (min, max) safe range for a register."""
    info = REGISTER_MAP[register]
    return info["min"], info["max"]


# ───────────────────────────────────────────────────────────────────────────
# Rule 1 — Hard bounds
# ───────────────────────────────────────────────────────────────────────────

def _check_bounds(tx_id: str, register: int, value: float) -> Optional[Dict[str, Any]]:
    """Returns a failed verdict if value is outside the safe range, else None."""
    lo, hi = _safe_range(register)
    if not (lo <= value <= hi):
        name = REGISTER_MAP[register]["name"]
        return make_verdict(
            tx_id, False,
            f"OUT_OF_BOUNDS:{name}={value:.2f} (allowed {lo}–{hi})",
            "physical",
        )
    return None


# ───────────────────────────────────────────────────────────────────────────
# Rule 2 — Rate-of-change
# ───────────────────────────────────────────────────────────────────────────

def _check_rate_of_change(tx_id: str, register: int, value: float,
                           current_state: dict, cmd_timestamp: float) -> Optional[Dict[str, Any]]:
    """Returns a failed verdict if the requested value implies a speed the
    physical plant cannot achieve in the available time window."""
    current_val = _get_value(current_state, register)
    if current_val is None:
        # No baseline to compare against — can't enforce rate; let it through.
        return None

    state_ts = current_state.get("timestamp", cmd_timestamp)
    dt = max(cmd_timestamp - state_ts, _MIN_DT)

    delta = abs(value - current_val)
    max_allowed = _RATE_LIMIT_PER_SEC[register] * dt

    if delta > max_allowed:
        name = REGISTER_MAP[register]["name"]
        return make_verdict(
            tx_id, False,
            f"RATE_OF_CHANGE_EXCEEDED:{name} Δ{delta:.2f} > max {max_allowed:.2f} in {dt:.3f}s",
            "physical",
        )
    return None


# ───────────────────────────────────────────────────────────────────────────
# Rule 3 — Cross-register consistency
# ───────────────────────────────────────────────────────────────────────────

def _check_cross_register(tx_id: str, command: dict, current_state: dict) -> Optional[Dict[str, Any]]:
    """
    Flags physically impossible register combinations.

    Current rules (stage-aware, SWaT-style twin):
      A. VALVE_CLOSING_LOW_LEVEL: the S1 inlet valve MV101 closing sharply
         while the raw tank LIT101 is already low - the tank would run dry.
      B. RO_PRESSURE_OVERLOAD: RO high-pressure pump P501 near max speed while
         the RO feed pressure PIT501 is already near its limit.
    """
    register = command.get("register")
    value    = command.get("value")

    level_101    = _get_value(current_state, LIT101)
    inlet_valve  = _get_value(current_state, MV101)
    ro_pressure  = _get_value(current_state, PIT501)

    # Rule A: inlet valve closing fast while the raw-water tank is already low
    if register == MV101 and level_101 is not None and inlet_valve is not None:
        valve_drop = inlet_valve - value              # positive = closing
        level_lo, level_hi = _safe_range(LIT101)
        low_threshold = level_lo + 0.20 * (level_hi - level_lo)   # "already low" = bottom 20 %

        if valve_drop >= _SIG_MOVE[MV101] and level_101 < low_threshold:
            return make_verdict(
                tx_id, False,
                "CROSS_REGISTER_VIOLATION:VALVE_CLOSING_LOW_LEVEL:inlet valve closing sharply with raw tank level already low",
                "physical",
            )

    # Rule B: RO pump near max while RO feed pressure already near its limit
    if register == P501 and ro_pressure is not None:
        _, pressure_hi = _safe_range(PIT501)
        _, pump_hi     = _safe_range(P501)
        if ro_pressure > pressure_hi * 0.90 and value > pump_hi * 0.90:
            return make_verdict(
                tx_id, False,
                "CROSS_REGISTER_VIOLATION:RO_PRESSURE_OVERLOAD:RO pump near max speed while RO feed pressure near limit",
                "physical",
            )

    # Rules C..: config-driven multi-machine correlation rules
    return _check_correlation_rules(tx_id, command, current_state)


_OPS = {
    ">=": lambda v, t: v >= t,
    "<=": lambda v, t: v <= t,
}


def _baseline_setpoints(current_state: dict) -> dict:
    """Plant state the command will be combined with: approved setpoints the
    PLC is heading to (if the caller supplies them), else live telemetry."""
    base = {}
    setpoints = current_state.get("setpoints") or {}
    for m in MACHINES:
        reg = m["register"]
        val = setpoints.get(reg, setpoints.get(m["name"]))
        if val is None:
            val = _get_value(current_state, reg)
        if val is not None:
            base[reg] = float(val)
    return base


def _rule_holds(rule: Dict[str, Any], state: Dict[int, float]) -> bool:
    for reg, op, threshold in rule["conditions"]:
        if reg not in state or not _OPS[op](state[reg], threshold):
            return False
    return True


def _moves_toward_safety(rule: Dict[str, Any], register: int, old: float, new: float) -> bool:
    for reg, op, _ in rule["conditions"]:
        if reg == register:
            return (op == ">=" and new < old) or (op == "<=" and new > old)
    return False


def _check_correlation_rules(tx_id: str, command: dict, current_state: dict) -> Optional[Dict[str, Any]]:
    """
    Cross-register correlation: apply the requested value to the projected
    plant state and evaluate every rule that involves the commanded register.
    Each command can be individually inside bounds and rate limits, yet the
    combination across machines is unsafe.

    A command that moves an ALREADY-violating state towards safety is allowed,
    so operators can always recover the plant.
    """
    register = command.get("register")
    value = float(command.get("value"))

    baseline = _baseline_setpoints(current_state)
    projected = dict(baseline)
    projected[register] = value

    for rule in CROSS_REGISTER_RULES:
        involved = {reg for reg, _, _ in rule["conditions"]}
        if register not in involved:
            continue
        if not _rule_holds(rule, projected):
            continue
        if _rule_holds(rule, baseline) and register in baseline and \
                _moves_toward_safety(rule, register, baseline[register], value):
            continue

        detail = " & ".join(
            f"{MACHINE_BY_REGISTER[reg]['name']}={projected[reg]:.1f}{op}{threshold:g}"
            for reg, op, threshold in rule["conditions"]
        )
        return make_verdict(
            tx_id, False,
            f"CROSS_REGISTER_VIOLATION:{rule['id']}:{detail} ({rule['description']})",
            "physical",
        )

    return None


# ───────────────────────────────────────────────────────────────────────────
# Public API
# ───────────────────────────────────────────────────────────────────────────

def check_command(command: dict, current_state: dict) -> dict:
    """
    Downstream check: validate a SCADA->PLC command against physical laws.

    Args:
        command:       Command dict (docs/interfaces.make_command shape).
        current_state: Latest plant state from plc.get_telemetry() or a
                       compatible dict (see module docstring for shape).

    Returns:
        Verdict dict (docs/interfaces.make_verdict shape).
        pass=True only if ALL three rule layers pass.
    """
    tx_id    = command.get("tx_id", "")
    register = command.get("register")
    value    = command.get("value")
    cmd_ts   = command.get("timestamp", time.time())

    if register not in REGISTER_MAP:
        return make_verdict(tx_id, False, f"UNKNOWN_REGISTER:{register}", "physical")

    # Layer 0 — only actuators can be commanded
    if register not in ACTUATOR_REGISTERS:
        return make_verdict(
            tx_id, False,
            f"WRITE_TO_SENSOR_REGISTER:{REGISTER_MAP[register]['name']} is a sensor (read-only)",
            "physical",
        )

    # Layer 1 — hard bounds
    verdict = _check_bounds(tx_id, register, value)
    if verdict:
        return verdict

    # Layer 2 — rate of change
    verdict = _check_rate_of_change(tx_id, register, value, current_state, cmd_ts)
    if verdict:
        return verdict

    # Layer 3 — cross-register
    verdict = _check_cross_register(tx_id, command, current_state)
    if verdict:
        return verdict

    return make_verdict(tx_id, True, "OK", "physical")


def check_feedback(commanded_value: float, reported_value: float, register: int) -> dict:
    """
    Upstream check: compare what the PLC reports with what was last commanded.

    A small lag is expected while the physics simulation ramps toward the
    target. A large mismatch suggests sensor spoofing, a stuck actuator,
    or a tampered telemetry frame.

    Args:
        commanded_value: The last value sent to this register by the middleware.
        reported_value:  The value the PLC is currently reporting.
        register:        Register number (see docs/interfaces.MACHINES).

    Returns:
        Verdict dict with agent="physical".
        tx_id is set to "" here — callers should replace it with the real tx_id.
    """
    _, hi = _safe_range(register)
    lo, _ = _safe_range(register)
    full_range = hi - lo if hi != lo else 1.0

    tolerance = full_range * _FEEDBACK_TOLERANCE_FRACTION
    deviation  = abs(reported_value - commanded_value)

    if deviation > tolerance:
        name = REGISTER_MAP[register]["name"]
        return make_verdict(
            "", False,
            (f"TELEMETRY_MISMATCH:{name} commanded={commanded_value:.2f} "
             f"reported={reported_value:.2f} deviation={deviation:.2f} > tol={tolerance:.2f}"),
            "physical",
        )

    return make_verdict("", True, "OK", "physical")

