"""
plc/twin.py - physics of the staged water-treatment twin (SWaT-style, 5 stages).

Pure Python, no Modbus: plc/plc.py owns the network side and calls step().
The stages are COUPLED - a change upstream propagates downstream:

  S1 raw water   MV101 -> [LIT101 tank] -> P101 --------------> FIT201 (S2 flow)
                    ^ return of rejected flow (1 - MV302)  <-----------+
  S2 dosing      P203 (HCl) -> AIT202 pH ; P205 (NaOCl) -> chlorine carried on
  S3 UF          MV302 -> [LIT301 tank] -> P302 ; DPIT301 rises with flow + fouling,
                 automatic backwash briefly cuts output when DPIT301 is high
  S4 dechlor     [LIT401 tank] <- S3 filtrate ; P402 draw ; UV401 removes chlorine -> AIT402 ORP
  S5 RO          PIT501 = P501 pressure, starved when the S4 feed (P402 flow) is low,
                 raised by closing the reject valve MV503 ; FIT501 permeate follows PIT501

CALIBRATION: every constant below is DERIVED in _calibrate() from docs/interfaces.MACHINES - the sensors'
`initial` values are the MEASURED SWaT normal-operation medians (docs/swat_bounds.json) and the actuators'
`initial` values are the nominal setpoints - so at nominal setpoints the twin sits at the measured operating
point (checked by tests/test_bounds_alignment.py). Edit the config and the plant recalibrates itself.

Actuators ramp toward the commanded target at their configured rate. Sensors are computed from the physics
(first-order lags model transport/dosing delay), never written directly. time_scale > 1 speeds the process up.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import Dict

from docs.interfaces import (
    MACHINES, MACHINE_BY_REGISTER, MACHINE_BY_NAME, ACTUATOR_REGISTERS,
    MV101, P101, LIT101, FIT101, P203, P205, AIT202, FIT201,
    MV302, P302, LIT301, DPIT301, P402, UV401, LIT401, AIT402,
    P501, MV503, PIT501, FIT501,
)

L_MAX = 1200.0            # tank height, mm (SWaT LIT301 reaches 1200)
K_REF = 2.0               # mm per (flow-unit * s) at the REFERENCE flow below; keeps propagation timing
Q_REF = 8.0               # reference flow the timing was originally tuned for (m3/h)
BW_DP_FACTOR = 1.08       # UF backwash starts when DPIT301 exceeds this multiple of its nominal value
FOULING_PER_S = 1.3e-4    # fouling growth per second at nominal flow (about a 30 min backwash cycle)
BW_SECONDS = 8.0
SENSOR_NOISE_FRAC = 0.002  # sensor noise std as fraction of range (when noise is on)
PH_GAIN, ORP_GAIN, F0 = 1.5, 60.0, 0.2


def _lag(state: float, target: float, dt: float, tau: float) -> float:
    return state + (target - state) * (1.0 - math.exp(-dt / tau))


def _clamp(x: float, lo: float, hi: float) -> float:
    return lo if x < lo else hi if x > hi else x


def _head(level: float) -> float:
    """Weak level (head) dependence of pump / gravity flows."""
    return 0.4 + 0.6 * level / L_MAX


def _pump_out(cap: float, speed_frac: float, level: float) -> float:
    """Pump flow out of a tank: head-dependent, starves when nearly empty."""
    return cap * speed_frac * _head(level) * min(1.0, level / 100.0)


@dataclass
class Cal:
    """Constants derived from the nominal operating point (see _calibrate)."""
    q_star: float; cap1: float; cap3: float; cap4: float; supply: float; k_tank: float
    qin_nom: float; q3_nom: float; floor2: float; dose: float
    ph_base: float; chl_nom: float; c4_nom: float; orp0: float
    dp0: float; g_dp: float; fouling_rate: float; bw_dp_high: float
    pmax: float; starve_q: float; p0: float; k_perm: float


def _calibrate() -> Cal:
    init = {m["name"]: float(m["initial"]) for m in MACHINES}
    a = {n: init[n] / 100.0 for n in ("MV101", "P101", "P203", "P205", "MV302", "P302", "P402", "UV401", "P501", "MV503")}
    q = init["FIT201"]                                           # flow leaving S1 at nominal
    qin = q * a["MV302"]                                         # inlet flow = pumped flow minus the returned share
    cap1 = q / (a["P101"] * _head(init["LIT101"]))
    cap3 = qin / (a["P302"] * _head(init["LIT301"]))
    cap4 = qin / (a["P402"] * _head(init["LIT401"]))
    supply = qin / (a["MV101"] * (1.0 - 0.5 * init["LIT101"] / L_MAX))
    chl = 0.1 + 4.0 * a["P205"]
    c4 = chl * (1.0 - 0.85 * a["UV401"])
    dp0 = 0.2 * init["DPIT301"]
    p0 = 0.4 * init["PIT501"]
    return Cal(
        q_star=q, cap1=cap1, cap3=cap3, cap4=cap4, supply=supply, k_tank=K_REF * Q_REF / q,
        qin_nom=qin, q3_nom=qin, floor2=0.25 * q, dose=q,
        ph_base=init["AIT202"] + PH_GAIN * a["P203"], chl_nom=chl, c4_nom=c4, orp0=init["AIT402"] - ORP_GAIN * c4,
        dp0=dp0, g_dp=(init["DPIT301"] - dp0) / (qin * (1.0 + 3.0 * F0)),
        fouling_rate=FOULING_PER_S / qin, bw_dp_high=BW_DP_FACTOR * init["DPIT301"],
        pmax=init["PIT501"] / (a["P501"] * (1.0 - 0.5 * a["MV503"])), starve_q=0.625 * qin, p0=p0,
        k_perm=init["FIT501"] / (init["PIT501"] - p0),
    )


CAL = _calibrate()


class PlantTwin:
    """Continuous-time plant model stepped with step(dt)."""

    def __init__(self, noise: bool = False, seed: int = 0, time_scale: float = 1.0) -> None:
        self.noise = noise
        self.time_scale = time_scale
        self._rng = random.Random(seed)
        self.cal = CAL
        c = self.cal
        init = {m["register"]: float(m["initial"]) for m in MACHINES}
        self.act: Dict[int, float] = {r: init[r] for r in ACTUATOR_REGISTERS}
        self.target: Dict[int, float] = dict(self.act)
        self._rate = {r: MACHINE_BY_REGISTER[r]["rate_per_sec"] for r in ACTUATOR_REGISTERS}
        self.l1, self.l3, self.l4 = init[LIT101], init[LIT301], init[LIT401]
        self.fit101, self.q1 = c.qin_nom, c.q_star
        self.ph = init[AIT202]
        self.chlor2, self.chlor_in4, self.chlor4 = c.chl_nom, c.chl_nom, c.c4_nom
        self.q3 = c.q3_nom
        self.dp = init[DPIT301]
        self.fouling = F0
        self.backwash_left = 0.0
        self.orp = init[AIT402]
        self.pit501 = init[PIT501]
        self.q4out = c.q3_nom
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
        c = self.cal
        for r in self.act:                                         # actuators ramp toward targets
            max_step = self._rate[r] * dt
            diff = self.target[r] - self.act[r]
            self.act[r] = self.target[r] if abs(diff) <= max_step else self.act[r] + math.copysign(max_step, diff)
        a = {r: v / 100.0 for r, v in self.act.items()}

        # ---- S1 raw water
        q_in1 = c.supply * a[MV101] * (1.0 - 0.5 * self.l1 / L_MAX) if self.l1 < L_MAX else 0.0
        q1 = _pump_out(c.cap1, a[P101], self.l1)
        self.fit101 = _lag(self.fit101, q_in1, dt, 1.0)
        self.q1 = _lag(self.q1, q1, dt, 1.0)                       # FIT201: flow leaving S1 into S2

        # ---- S2 dosing (reaction time ~3 s), flow-proportional dose
        flow2 = max(self.q1, c.floor2)
        acid = a[P203] * c.dose / flow2
        self.ph = _lag(self.ph, _clamp(c.ph_base - PH_GAIN * acid, 4.0, 10.0), dt, 3.0)
        self.chlor2 = _lag(self.chlor2, 0.1 + 4.0 * (a[P205] * c.dose / flow2), dt, 3.0)

        # ---- S3 UF: valve splits S2 flow between UF tank and return to S1 tank
        q3in = self.q1 * a[MV302]
        q_ret = self.q1 - q3in
        bw_factor = 0.2 if self.backwash_left > 0 else 1.0
        q3out = _pump_out(c.cap3, a[P302], self.l3) * bw_factor
        self.q3 = _lag(self.q3, q3out, dt, 1.0)
        self.dp = _lag(self.dp, c.dp0 + c.g_dp * q3out * (1.0 + 3.0 * self.fouling), dt, 1.0)
        if self.backwash_left > 0:
            self.backwash_left = max(0.0, self.backwash_left - dt)
            self.fouling = max(0.0, self.fouling - 0.06 * dt)
        else:
            self.fouling = min(1.0, self.fouling + c.fouling_rate * q3out * dt)
            if self.dp > c.bw_dp_high:
                self.backwash_left = BW_SECONDS
                self.backwashes += 1

        # ---- S4 dechlorination
        q4out = _pump_out(c.cap4, a[P402], self.l4)
        self.q4out = _lag(self.q4out, q4out, dt, 1.0)
        self.chlor_in4 = _lag(self.chlor_in4, self.chlor2, dt, 4.0)
        self.chlor4 = _lag(self.chlor4, self.chlor_in4 * (1.0 - 0.85 * a[UV401]), dt, 2.0)
        self.orp = _lag(self.orp, _clamp(c.orp0 + ORP_GAIN * self.chlor4, 0.0, 800.0), dt, 2.0)

        # ---- S5 reverse osmosis: pressure needs feed (S4 outflow) and a closed-ish reject valve
        starve = min(1.0, self.q4out / c.starve_q)
        self.pit501 = _lag(self.pit501, c.pmax * a[P501] * starve * (1.0 - 0.5 * a[MV503]), dt, 1.5)

        # ---- tank balances (integrators), clamped at the physical walls
        self.l1 = _clamp(self.l1 + c.k_tank * (q_in1 + q_ret - q1) * dt, 0.0, L_MAX)
        self.l3 = _clamp(self.l3 + c.k_tank * (q3in - q3out) * dt, 0.0, L_MAX)
        self.l4 = _clamp(self.l4 + c.k_tank * (self.q3 - q4out) * dt, 0.0, L_MAX)
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
        c = self.cal
        sensors = {
            LIT101: self.l1, FIT101: self.fit101, AIT202: self.ph, FIT201: self.q1,
            LIT301: self.l3, DPIT301: self.dp, LIT401: self.l4, AIT402: self.orp,
            PIT501: self.pit501, FIT501: max(0.0, (self.pit501 - c.p0) * c.k_perm),
        }
        for r, v in sensors.items():
            out[r] = self._noisy(r, v)
        return out
