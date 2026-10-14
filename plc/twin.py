"""
plc/twin.py - physics of the staged water-treatment twin (SWaT-style, 5 stages).

Pure Python, no Modbus: plc/plc.py owns the network side and calls step().
The stages are COUPLED - a change upstream propagates downstream:

  S1 raw water   MV101 -> [LIT101 tank] -> P101 --------------> FIT201 (S2 flow)
                    ^ return of rejected flow (1 - MV302)  <-----------+
  S2 dosing      P203 (HCl) -> AIT202 pH ; P205 (NaOCl) -> chlorine carried on
  S3 UF          MV302 -> [LIT301 tank] -> P302 ; DPIT301 rises with flow + fouling,
                 automatic backwash briefly cuts output when DPIT301 is high
  S4 dechlor     [LIT401 tank] <- S3 filtrate ; P401 draw ; UV401 removes chlorine -> AIT402 ORP
  S5 RO          PIT501 = P501 pressure, starved when the S4 feed (P401 flow) is low,
                 raised by closing the reject valve MV503 ; FIT501 permeate follows PIT501

Actuators ramp toward the commanded target at their configured rate. Sensors are
computed from the physics (first-order lags model transport/dosing delay), never
written directly. Constants are SWaT-style nominal placeholders (see
docs/interfaces.py) - Phase 6 replaces the bounds with SWaT-measured ones.

time_scale > 1 speeds the process up (used by the verification script).
"""

from __future__ import annotations

import math
import random
from typing import Dict, Optional

from docs.interfaces import (
    MACHINES, MACHINE_BY_REGISTER, ACTUATOR_REGISTERS,
    MV101, P101, LIT101, FIT101, P203, P205, AIT202, FIT201,
    MV302, P302, LIT301, DPIT301, P401, UV401, LIT401, AIT402,
    P501, MV503, PIT501, FIT501,
)

CAP = 20.0          # pump capacity, m3/h at 100 %
SUPPLY = 30.0       # raw-water supply flow at MV101 = 100 % and empty tank, m3/h
K_TANK = 2.0        # mm of level per (m3/h * s)
L_MAX = 1000.0      # tank height, mm
BW_DP_HIGH = 35.0   # kPa: start UF backwash above this
BW_SECONDS = 8.0
SENSOR_NOISE_FRAC = 0.002   # sensor noise std as fraction of range (when noise is on)


def _lag(state: float, target: float, dt: float, tau: float) -> float:
    return state + (target - state) * (1.0 - math.exp(-dt / tau))


def _clamp(x: float, lo: float, hi: float) -> float:
    return lo if x < lo else hi if x > hi else x


def _pump_out(speed_frac: float, level: float) -> float:
    """Pump flow out of a tank: weakly head-dependent, starves when nearly empty."""
    return CAP * speed_frac * (0.4 + 0.6 * level / L_MAX) * min(1.0, level / 100.0)


class PlantTwin:
    """Continuous-time plant model stepped with step(dt)."""

    def __init__(self, noise: bool = False, seed: int = 0, time_scale: float = 1.0) -> None:
        self.noise = noise
        self.time_scale = time_scale
        self._rng = random.Random(seed)
        init = {m["register"]: float(m["initial"]) for m in MACHINES}
        # actuators: current position and commanded target
        self.act: Dict[int, float] = {r: init[r] for r in ACTUATOR_REGISTERS}
        self.target: Dict[int, float] = dict(self.act)
        self._rate = {r: MACHINE_BY_REGISTER[r]["rate_per_sec"] for r in ACTUATOR_REGISTERS}
        # physical state (sensor registers are views of these)
        self.l1, self.l3, self.l4 = init[LIT101], init[LIT301], init[LIT401]
        self.fit101, self.q1 = init[FIT101], init[FIT201]       # inlet flow, S1 outflow lagged
        self.ph = init[AIT202]
        self.chlor2 = 1.30          # ppm after dosing (internal; no register)
        self.chlor4 = 0.637         # ppm after UV (internal)
        self.chlor_in4 = 1.30       # chlorine arriving at S4 (transport delay)
        self.q3 = 6.4               # S3 outflow lagged (feeds S4)
        self.dp = init[DPIT301]
        self.fouling = 0.2
        self.backwash_left = 0.0
        self.orp = init[AIT402]
        self.pit501 = init[PIT501]
        self.q4out = 6.4
        self.sim_time = 0.0
        self.backwashes = 0

    # ---- commands ---------------------------------------------------------
    def set_target(self, register: int, value: float) -> None:
        if register not in self.target:
            raise ValueError(f"register {register} is not an actuator")
        m = MACHINE_BY_REGISTER[register]
        self.target[register] = _clamp(float(value), m["min"], m["max"])

    # ---- dynamics ---------------------------------------------------------
    def step(self, dt_wall: float) -> None:
        dt = dt_wall * self.time_scale
        # actuators ramp toward targets (rate is per simulated second)
        for r in self.act:
            max_step = self._rate[r] * dt
            diff = self.target[r] - self.act[r]
            self.act[r] = self.target[r] if abs(diff) <= max_step else self.act[r] + math.copysign(max_step, diff)

        a = {r: v / 100.0 for r, v in self.act.items()}

        # ---- S1 raw water
        q_in1 = SUPPLY * a[MV101] * (1.0 - 0.5 * self.l1 / L_MAX) if self.l1 < L_MAX else 0.0
        q1 = _pump_out(a[P101], self.l1)
        self.fit101 = _lag(self.fit101, q_in1, dt, 1.0)
        self.q1 = _lag(self.q1, q1, dt, 1.0)                    # FIT201: flow leaving S1 into S2

        # ---- S2 dosing (reaction time ~3 s), flow-proportional dose
        flow2 = max(self.q1, 2.0)
        acid = a[P203] * 8.0 / flow2
        self.ph = _lag(self.ph, _clamp(8.4 - 3.0 * acid, 4.0, 10.0), dt, 3.0)
        chl_target = 0.1 + 4.0 * (a[P205] * 8.0 / flow2)
        self.chlor2 = _lag(self.chlor2, chl_target, dt, 3.0)

        # ---- S3 UF: valve splits S2 flow between UF tank and return to S1 tank
        q3in = self.q1 * a[MV302]
        q_ret = self.q1 - q3in
        bw_factor = 0.2 if self.backwash_left > 0 else 1.0
        q3out = _pump_out(a[P302], self.l3) * bw_factor
        self.q3 = _lag(self.q3, q3out, dt, 1.0)
        dp_target = 4.0 + 0.9 * q3out * (1.0 + 3.0 * self.fouling)
        self.dp = _lag(self.dp, dp_target, dt, 1.0)
        if self.backwash_left > 0:
            self.backwash_left = max(0.0, self.backwash_left - dt)
            self.fouling = max(0.0, self.fouling - 0.06 * dt)
        else:
            self.fouling = min(1.0, self.fouling + 0.0008 * (q3out / CAP) * dt)
            if self.dp > BW_DP_HIGH:
                self.backwash_left = BW_SECONDS
                self.backwashes += 1

        # ---- S4 dechlorination
        q4out = _pump_out(a[P401], self.l4)
        self.q4out = _lag(self.q4out, q4out, dt, 1.0)
        self.chlor_in4 = _lag(self.chlor_in4, self.chlor2, dt, 4.0)
        self.chlor4 = _lag(self.chlor4, self.chlor_in4 * (1.0 - 0.85 * a[UV401]), dt, 2.0)
        self.orp = _lag(self.orp, _clamp(150.0 + 220.0 * self.chlor4, 0.0, 800.0), dt, 2.0)

        # ---- S5 reverse osmosis: pressure needs feed (S4 outflow) and a closed-ish reject valve
        starve = min(1.0, self.q4out / 5.0)
        p_target = 2000.0 * a[P501] * starve * (1.0 - 0.5 * a[MV503])
        self.pit501 = _lag(self.pit501, p_target, dt, 1.5)

        # ---- tank balances (integrators), clamped at the physical walls
        self.l1 = _clamp(self.l1 + K_TANK * (q_in1 + q_ret - q1) * dt, 0.0, L_MAX)
        self.l3 = _clamp(self.l3 + K_TANK * (q3in - q3out) * dt, 0.0, L_MAX)
        self.l4 = _clamp(self.l4 + K_TANK * (self.q3 - q4out) * dt, 0.0, L_MAX)
        self.sim_time += dt

    # ---- readout ------------------------------------------------------------
    def _noisy(self, register: int, value: float) -> float:
        m = MACHINE_BY_REGISTER[register]
        if self.noise:
            value += self._rng.gauss(0.0, SENSOR_NOISE_FRAC * (m["max"] - m["min"]))
        return _clamp(value, m["min"], m["max"])

    def values(self) -> Dict[int, float]:
        """Current value of all 20 registers (actuator positions + sensor readings)."""
        out: Dict[int, float] = dict(self.act)
        sensors = {
            LIT101: self.l1, FIT101: self.fit101, AIT202: self.ph, FIT201: self.q1,
            LIT301: self.l3, DPIT301: self.dp, LIT401: self.l4, AIT402: self.orp,
            PIT501: self.pit501, FIT501: max(0.0, (self.pit501 - 400.0) * 0.006),
        }
        for r, v in sensors.items():
            out[r] = self._noisy(r, v)
        return out
