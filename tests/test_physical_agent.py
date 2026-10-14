"""
tests/test_physical_agent.py - standalone test for the Physical Agent
(5-stage SWaT-style water-treatment twin, 10 actuators + 10 sensors).

Run from the repo root:
    python tests/test_physical_agent.py

Core cases per the PDF spec:
  1. Valid slow-moving value     -> PASS
  2. In-bounds but too fast      -> DROP (RATE_OF_CHANGE_EXCEEDED)
  3. Out-of-bounds value         -> DROP (OUT_OF_BOUNDS)

Additional cases:
  4. Cross-register consistency  -> DROP (VALVE_CLOSING_LOW_LEVEL)
  5. Upstream feedback OK        -> PASS
  6. Upstream telemetry mismatch -> DROP (TELEMETRY_MISMATCH)
  7-11. Config-driven correlation rules, pending setpoints, recovery, bounds
  12. Writes to sensor registers -> DROP (WRITE_TO_SENSOR_REGISTER)
  13. All 8 cross-stage correlation rules DROP, and the recovery move PASSes
  14. RO_PRESSURE_OVERLOAD (rule B)
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from docs.interfaces import (make_command, MACHINES, MACHINE_BY_REGISTER, CROSS_REGISTER_RULES,
                             ACTUATOR_REGISTERS, SENSOR_REGISTERS,
                             MV101, P101, LIT101, FIT101, P203, P205, AIT202, FIT201,
                             MV302, P302, LIT301, DPIT301, P402, UV401, LIT401, AIT402,
                             P501, MV503, PIT501, FIT501)
from docs.netconfig import LOOPBACK
from middleware import physical_agent

SRC = LOOPBACK   # trusted by default (docs/netconfig.py)
NOW = time.time()


def make_state(over=None, ts=None):
    """current_state as the middleware would receive from plc.get_telemetry().
    `over` maps register -> value on top of the nominal initial values."""
    regs = {m["register"]: m["initial"] for m in MACHINES}
    regs.update(over or {})
    return {"registers": regs, "timestamp": ts if ts is not None else NOW}


def cmd(tx, register, value):
    return make_command(tx, NOW, SRC, 16, register, value)


print("=" * 60)
print("Physical Agent - standalone test (water-treatment twin)")
print("=" * 60)

assert len(MACHINES) == 20 and len(ACTUATOR_REGISTERS) == 10 and len(SENSOR_REGISTERS) == 10

# -- Test 1: Valid slow-moving value ------------------------------------------
# Inlet valve MV101 at its nominal setpoint, command +1 % (1 s window) -> within rate
NOM = {m["register"]: m["initial"] for m in MACHINES}
v1 = physical_agent.check_command(cmd("tx-valid", MV101, NOM[MV101] + 1.0), make_state(ts=NOW - 1.0))
print(f"\n1. Valid slow move (MV101 nominal -> +1 % in 1s): {v1}")
assert v1["pass"], "Test 1 failed - expected PASS"

# -- Test 2: In-bounds but too fast --------------------------------------------
# MV101 rate limit 10 * 1.10 = 11 %/s -> max 1.1 % in 0.1 s; 32 -> 70 is far over
v2 = physical_agent.check_command(cmd("tx-fast", MV101, 70.0), make_state(ts=NOW - 0.1))
print(f"\n2. In-bounds but too fast (MV101 32->70 % in 0.1s): {v2}")
assert not v2["pass"] and "RATE_OF_CHANGE_EXCEEDED" in v2["reason"], "Test 2 failed"

# -- Test 3: Out-of-bounds value -----------------------------------------------
# P101 (raw-water pump speed) max is 100 % - command 150 %
v3 = physical_agent.check_command(cmd("tx-oob", P101, 150.0), make_state(ts=NOW - 5.0))
print(f"\n3. Out-of-bounds (P101 150 %, max 100): {v3}")
assert not v3["pass"] and "OUT_OF_BOUNDS" in v3["reason"], "Test 3 failed"

# -- Test 4: Cross-register - inlet valve slamming shut, raw tank already low ---
# MV101 at 60, command 30 (drop 30 >= sig_move 25) while LIT101 is 100 mm (<20 % of 1000)
v4 = physical_agent.check_command(cmd("tx-cross", MV101, 30.0),
                                  make_state({MV101: 60.0, LIT101: 100.0}, ts=NOW - 10.0))
print(f"\n4. Cross-register violation (MV101 closing, LIT101 low): {v4}")
assert not v4["pass"] and "CROSS_REGISTER_VIOLATION:VALVE_CLOSING_LOW_LEVEL" in v4["reason"], "Test 4 failed"

# 4b. same close with a healthy tank level is fine
v4b = physical_agent.check_command(cmd("tx-close-ok", MV101, 30.0),
                                   make_state({MV101: 60.0, LIT101: 600.0}, ts=NOW - 10.0))
print(f"4b. Same close with LIT101 600 mm: {v4b}")
assert v4b["pass"], "Test 4b failed"

# -- Test 5: Upstream feedback - small normal lag (PASS) ------------------------
# Commanded 60 %; PLC reports 57 % (3 % lag; tolerance 20 % of 100 = 20)
v5 = physical_agent.check_feedback(60.0, 57.0, MV101)
v5["tx_id"] = "tx-fb-ok"
print(f"\n5. Upstream feedback - small lag (commanded 60 %, reported 57 %): {v5}")
assert v5["pass"], "Test 5 failed - expected PASS"

# -- Test 6: Upstream feedback - large mismatch (TELEMETRY_MISMATCH) ------------
v6 = physical_agent.check_feedback(60.0, 10.0, MV101)
v6["tx_id"] = "tx-fb-bad"
print(f"\n6. Upstream feedback - large mismatch (commanded 60 %, reported 10 %): {v6}")
assert not v6["pass"] and "TELEMETRY_MISMATCH" in v6["reason"], "Test 6 failed"

# -- Test 7: Cross-stage correlation attack - HCl overdose, raw-water flow low ---
# Each value alone is in range and the P203 move is slow enough, but P203 85 %
# with the raw-water pump P101 at 15 % crashes the pH (S2 <- S1).
state7 = make_state({P203: 75.0, P101: 15.0}, ts=NOW - 10.0)
v7 = physical_agent.check_command(cmd("tx-corr", P203, 85.0), state7)
print(f"\n7. Correlation attack (P203 75->85 with P101 15): {v7}")
assert not v7["pass"] and v7["reason"].startswith("CROSS_REGISTER_VIOLATION:ACID_OVERDOSE_LOW_FLOW"), "Test 7 failed"

# -- Test 8: Same P203 command with the raw pump running -> legitimate, PASS -----
v8 = physical_agent.check_command(cmd("tx-legit", P203, 85.0),
                                  make_state({P203: 75.0, P101: 50.0}, ts=NOW - 10.0))
print(f"\n8. Legit combination (P203 85 with P101 50): {v8}")
assert v8["pass"], "Test 8 failed"

# -- Test 9: Pending setpoint is used, not stale telemetry -----------------------
# P101 telemetry still 50 but an approved setpoint of 10 is ramping down;
# raising P203 to 85 must be judged against the 10.
state9 = make_state({P203: 75.0, P101: 50.0}, ts=NOW - 10.0)
state9["setpoints"] = dict(state9["registers"]); state9["setpoints"][P101] = 10.0
v9 = physical_agent.check_command(cmd("tx-pend", P203, 85.0), state9)
print(f"\n9. Acid overdose via pending setpoint (P203 85, P101 heading to 10): {v9}")
assert not v9["pass"] and "ACID_OVERDOSE_LOW_FLOW" in v9["reason"], "Test 9 failed"

# -- Test 10: Corrective move out of an unsafe state is allowed ------------------
state10 = make_state({P203: 90.0, P101: 10.0}, ts=NOW - 10.0)
v10 = physical_agent.check_command(cmd("tx-fix", P203, 85.0), state10)
print(f"\n10. Corrective move (P203 90->85 while P101 10): {v10}")
assert v10["pass"], "Test 10 failed"

# -- Test 11: Bounds apply to every actuator --------------------------------------
v11 = physical_agent.check_command(cmd("tx-oob2", UV401, 180.0), make_state(ts=NOW - 60.0))
print(f"\n11. UV401 out of bounds (180 %, max 100): {v11}")
assert not v11["pass"] and "OUT_OF_BOUNDS" in v11["reason"], "Test 11 failed"
v11b = physical_agent.check_command(cmd("tx-oob3", P203, -5.0), make_state(ts=NOW - 60.0))
assert not v11b["pass"] and "OUT_OF_BOUNDS" in v11b["reason"], "Test 11b failed"

# -- Test 12: Writes to sensor registers are rejected (new layer 0) ----------------
# Even an in-bounds value at the sensor's own nominal level must be dropped, and
# it must be dropped by layer 0 (before bounds / rate / cross-register).
print("\n12. Write to every sensor register:")
for reg in SENSOR_REGISTERS:
    m = MACHINE_BY_REGISTER[reg]
    v = physical_agent.check_command(cmd(f"tx-sensor-{m['name']}", reg, m["initial"]),
                                     make_state(ts=NOW - 60.0))
    print(f"    {m['name']:8s} -> {v['reason']}")
    assert not v["pass"] and v["reason"].startswith(f"WRITE_TO_SENSOR_REGISTER:{m['name']}"), \
        f"Test 12 failed for {m['name']}"
    assert v["agent"] == "physical"
# a sensor write is dropped even when the value is out of bounds (layer 0 wins)
v12 = physical_agent.check_command(cmd("tx-sensor-oob", LIT101, 5000.0), make_state(ts=NOW - 60.0))
assert v12["reason"].startswith("WRITE_TO_SENSOR_REGISTER"), "Test 12 layer ordering failed"
# unknown register is still rejected as such
v12b = physical_agent.check_command(cmd("tx-unknown", 99, 1.0), make_state())
assert not v12b["pass"] and v12b["reason"].startswith("UNKNOWN_REGISTER"), "Test 12 unknown failed"

# -- Test 12c: every actuator accepts a small nominal move in the nominal plant ----
for reg in ACTUATOR_REGISTERS:
    m = MACHINE_BY_REGISTER[reg]
    v = physical_agent.check_command(cmd(f"tx-nom-{m['name']}", reg, m["initial"] + 1.0),
                                     make_state(ts=NOW - 10.0))
    assert v["pass"], f"Test 12c: nominal +1 on {m['name']} dropped: {v['reason']}"
print("12c. All 10 actuators accept a small nominal move: PASS")

# -- Test 13: every cross-stage correlation rule DROPs and recovery PASSes ---------
# (rule id, base plant overrides, commanded register, new value, previous value)
# Base state has the rule NOT holding; the command makes it hold. Recovery is
# the reverse move from the violating state (towards safety) which must PASS.
RULE_CASES = [
    ("RAW_PUMP_DRY_RUN",       {MV101: 5.0, P101: 55.0},   P101,  65.0),
    ("RAW_TANK_OVERFLOW",      {P101: 8.0, MV101: 70.0} ,  MV101, 85.0),
    ("ACID_OVERDOSE_LOW_FLOW", {P101: 15.0, P203: 70.0},   P203,  85.0),
    ("UF_PUMP_DEADHEAD",       {MV302: 5.0, P302: 50.0},   P302,  65.0),
    ("UF_TANK_OVERFLOW",       {P302: 5.0, MV302: 70.0},   MV302, 85.0),
    ("CHLORINE_BREAKTHROUGH",  {UV401: 5.0, P205: 70.0},   P205,  85.0),
    ("RO_PUMP_DEADHEAD",       {MV503: 5.0, P501: 60.0},   P501,  75.0),
    ("RO_FEED_STARVATION",     {P402: 5.0, P501: 50.0},    P501,  65.0),
]
assert {c[0] for c in RULE_CASES} == {r["id"] for r in CROSS_REGISTER_RULES}, \
    "Test 13 must cover every rule in CROSS_REGISTER_RULES"

print("\n13. Cross-stage correlation rules:")
for rule_id, base, reg, new in RULE_CASES:
    old = base[reg]
    # base alone must be safe
    vbase = physical_agent.check_command(cmd(f"tx-{rule_id}-noop", reg, old + 0.5),
                                         make_state(base, ts=NOW - 10.0))
    assert vbase["pass"], f"{rule_id}: base state unexpectedly dropped: {vbase['reason']}"
    # the combination is dropped
    vd = physical_agent.check_command(cmd(f"tx-{rule_id}", reg, new), make_state(base, ts=NOW - 10.0))
    assert not vd["pass"] and vd["reason"].startswith(f"CROSS_REGISTER_VIOLATION:{rule_id}:"), \
        f"{rule_id}: expected DROP, got {vd}"
    # recovery: plant already in violation, move this register back towards safety
    violating = dict(base); violating[reg] = new
    vr = physical_agent.check_command(cmd(f"tx-{rule_id}-fix", reg, old), make_state(violating, ts=NOW - 10.0))
    assert vr["pass"], f"{rule_id}: recovery move dropped: {vr['reason']}"
    # ...but pushing further into violation is still dropped
    vf = physical_agent.check_command(cmd(f"tx-{rule_id}-worse", reg, new + 5.0),
                                      make_state(violating, ts=NOW - 10.0))
    assert not vf["pass"] and f":{rule_id}:" in vf["reason"], f"{rule_id}: worsening move passed"
    print(f"    {rule_id:24s} DROP ok, recovery PASS ok")

# recovery by opening the *other* half of the rule (the "<=" register) also passes
v13b = physical_agent.check_command(cmd("tx-fix-other", P101, 30.0),
                                    make_state({P203: 90.0, P101: 15.0}, ts=NOW - 10.0))
print(f"13b. Recovery by raising P101 15->30 while P203 90: {v13b}")
assert v13b["pass"], "Test 13b failed"

# -- Test 14: rule B - RO pump near max while RO feed pressure near its limit ------
PIT_MAX = [m["max"] for m in MACHINES if m["register"] == PIT501][0]
v14 = physical_agent.check_command(cmd("tx-ro-overload", P501, 95.0),
                                   make_state({P501: 90.0, PIT501: 0.95 * PIT_MAX}, ts=NOW - 10.0))
print(f"\n14. RO_PRESSURE_OVERLOAD (P501 95 with PIT501 at 95 % of its range): {v14}")
assert not v14["pass"] and "RO_PRESSURE_OVERLOAD" in v14["reason"], "Test 14 failed"
v14b = physical_agent.check_command(cmd("tx-ro-ok", P501, 95.0),
                                    make_state({P501: 90.0, PIT501: NOM[PIT501]}, ts=NOW - 10.0))
assert v14b["pass"], f"Test 14b failed: {v14b}"

# -- Test 15: feedback works for sensors / ranges other than 0-100 -------------------
# tolerance is 20 % of each register's own range (LIT101: 0-1200 mm -> 240 mm)
assert physical_agent.check_feedback(600.0, 450.0, LIT101)["pass"]
v15 = physical_agent.check_feedback(600.0, 300.0, LIT101)
assert not v15["pass"] and "TELEMETRY_MISMATCH" in v15["reason"], "Test 15 failed"

print("\n" + "=" * 60)
print("All 15 test groups passed")
print("=" * 60)
