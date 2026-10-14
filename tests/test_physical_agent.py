"""
tests/test_physical_agent.py — standalone test for Prapanch's Physical Agent.

Run from the repo root:
    python tests/test_physical_agent.py

All three test cases per the PDF spec:
  1. Valid slow-moving value     → PASS
  2. In-bounds but too fast      → DROP (RATE_OF_CHANGE_EXCEEDED)
  3. Out-of-bounds value         → DROP (OUT_OF_BOUNDS)

Additional tests:
  4. Cross-register consistency  → DROP (CROSS_REGISTER)
  5. Upstream feedback OK        → PASS
  6. Upstream telemetry mismatch → DROP (TELEMETRY_MISMATCH)
"""

import time
from docs.interfaces import (make_command, MACHINES, TANK_PRESSURE, CONVEYOR_SPEED, COOLING_VALVE,
                             HEATER_TEMP, FEED_PUMP, RELIEF_VALVE)
from middleware import physical_agent

SRC = "192.168.1.10"
NOW = time.time()

# Helper: build a current_state dict as the middleware would receive from plc.get_telemetry()
def make_state(tank=50.0, conveyor=0.0, valve=45.0, ts=None, **extra):
    regs = {m["register"]: m["initial"] for m in MACHINES}
    regs.update({TANK_PRESSURE: tank, CONVEYOR_SPEED: conveyor, COOLING_VALVE: valve})
    for name, v in extra.items():
        regs[{"heater": HEATER_TEMP, "pump": FEED_PUMP, "relief": RELIEF_VALVE}[name]] = v
    return {
        "registers": regs,
        "timestamp": ts if ts is not None else NOW,
    }


print("=" * 60)
print("Physical Agent — standalone test")
print("=" * 60)

# ── Test 1: Valid slow-moving value ─────────────────────────────────────────
# Valve is at 45°, we command 46° (1° move, 1-second window) → well within rate
state1 = make_state(valve=45.0, ts=NOW - 1.0)
cmd1   = make_command("tx-valid", NOW, SRC, 6, COOLING_VALVE, 46.0)
v1     = physical_agent.check_command(cmd1, state1)
status = "✓ PASS" if v1["pass"] else f"✗ FAIL (unexpected DROP: {v1['reason']})"
print(f"\n1. Valid slow move (valve 45→46° in 1s): {status}")
print(f"   verdict: {v1}")
assert v1["pass"], "Test 1 failed — expected PASS"


# ── Test 2: In-bounds but too fast ──────────────────────────────────────────
# Valve is at 45°, command 80° (35° jump) in only 0.1 seconds
# Rate limit is 5.0 * 1.10 = 5.5 °/s → max 0.55° in 0.1s → 35° is way over
state2 = make_state(valve=45.0, ts=NOW - 0.1)
cmd2   = make_command("tx-fast", NOW, SRC, 6, COOLING_VALVE, 80.0)
v2     = physical_agent.check_command(cmd2, state2)
status = "✓ PASS" if not v2["pass"] and "RATE_OF_CHANGE_EXCEEDED" in v2["reason"] \
         else f"✗ FAIL (expected RATE_OF_CHANGE_EXCEEDED, got: {v2})"
print(f"\n2. In-bounds but too fast (valve 45→80° in 0.1s): {status}")
print(f"   verdict: {v2}")
assert not v2["pass"] and "RATE_OF_CHANGE_EXCEEDED" in v2["reason"], "Test 2 failed"


# ── Test 3: Out-of-bounds value ─────────────────────────────────────────────
# TANK_PRESSURE max is 100 PSI — command 150 PSI
state3 = make_state(tank=50.0, ts=NOW - 5.0)
cmd3   = make_command("tx-oob", NOW, SRC, 6, TANK_PRESSURE, 150.0)
v3     = physical_agent.check_command(cmd3, state3)
status = "✓ PASS" if not v3["pass"] and "OUT_OF_BOUNDS" in v3["reason"] \
         else f"✗ FAIL (expected OUT_OF_BOUNDS, got: {v3})"
print(f"\n3. Out-of-bounds (tank pressure 150 PSI, max 100): {status}")
print(f"   verdict: {v3}")
assert not v3["pass"] and "OUT_OF_BOUNDS" in v3["reason"], "Test 3 failed"


# ── Test 4: Cross-register — valve slamming shut, tank already low ──────────
# Valve at 60°, command 30° (drop of 30, threshold is 15) while tank is at 8 PSI
state4 = make_state(tank=8.0, valve=60.0, ts=NOW - 10.0)
cmd4   = make_command("tx-cross", NOW, SRC, 6, COOLING_VALVE, 30.0)
v4     = physical_agent.check_command(cmd4, state4)
status = "✓ PASS" if not v4["pass"] and "CROSS_REGISTER" in v4["reason"] \
         else f"✗ FAIL (expected CROSS_REGISTER, got: {v4})"
print(f"\n4. Cross-register violation (valve closing, tank pressure low): {status}")
print(f"   verdict: {v4}")
assert not v4["pass"] and "CROSS_REGISTER" in v4["reason"], "Test 4 failed"


# ── Test 5: Upstream feedback — small normal lag (PASS) ─────────────────────
# Commanded 60.0 PSI; PLC reports 57.0 PSI (3 PSI lag; 20 % of 100 = 20 → OK)
v5 = physical_agent.check_feedback(60.0, 57.0, TANK_PRESSURE)
v5["tx_id"] = "tx-fb-ok"
status = "✓ PASS" if v5["pass"] else f"✗ FAIL (unexpected DROP: {v5['reason']})"
print(f"\n5. Upstream feedback — small lag (commanded 60 PSI, reported 57 PSI): {status}")
print(f"   verdict: {v5}")
assert v5["pass"], "Test 5 failed — expected PASS"


# ── Test 6: Upstream feedback — large mismatch (TELEMETRY_MISMATCH) ─────────
# Commanded 60.0 PSI; PLC reports 10.0 PSI (50 PSI off — sensor spoofed?)
v6 = physical_agent.check_feedback(60.0, 10.0, TANK_PRESSURE)
v6["tx_id"] = "tx-fb-bad"
status = "✓ PASS" if not v6["pass"] and "TELEMETRY_MISMATCH" in v6["reason"] \
         else f"✗ FAIL (expected TELEMETRY_MISMATCH, got: {v6})"
print(f"\n6. Upstream feedback — large mismatch (commanded 60 PSI, reported 10 PSI): {status}")
print(f"   verdict: {v6}")
assert not v6["pass"] and "TELEMETRY_MISMATCH" in v6["reason"], "Test 6 failed"


# ── Test 7: Cross-register correlation attack — heater raise, cooling closed ─
# Each value alone is in range and the heater move is slow enough, but
# heater 112 C + cooling valve 20 deg is a thermal-runaway combination.
state7 = make_state(valve=20.0, heater=102.0, ts=NOW - 10.0)
v7 = physical_agent.check_command(make_command("tx-corr", NOW, SRC, 16, HEATER_TEMP, 112.0), state7)
print(f"\n7. Correlation attack (heater 102->112 with cooling valve 20): {v7}")
assert not v7["pass"] and v7["reason"].startswith("CROSS_REGISTER_VIOLATION:THERMAL_RUNAWAY"), "Test 7 failed"

# ── Test 8: Same heater command with cooling open → legitimate, PASS ──────────
state8 = make_state(valve=60.0, heater=102.0, ts=NOW - 10.0)
v8 = physical_agent.check_command(make_command("tx-legit", NOW, SRC, 16, HEATER_TEMP, 112.0), state8)
print(f"\n8. Legit combination (heater 112 with cooling valve 60): {v8}")
assert v8["pass"], "Test 8 failed"

# ── Test 9: Pending setpoint is used, not stale telemetry ─────────────────────
# Relief valve telemetry still 40 but an approved setpoint of 10 is ramping;
# raising the feed pump to 75 must be judged against the 10.
state9 = make_state(pump=65.0, relief=40.0, ts=NOW - 10.0)
state9["setpoints"] = dict(state9["registers"]); state9["setpoints"][RELIEF_VALVE] = 10.0
v9 = physical_agent.check_command(make_command("tx-pend", NOW, SRC, 16, FEED_PUMP, 75.0), state9)
print(f"\n9. Overpressure via pending setpoint (pump 75, relief heading to 10): {v9}")
assert not v9["pass"] and "OVERPRESSURE" in v9["reason"], "Test 9 failed"

# ── Test 10: Corrective move out of an unsafe state is allowed ───────────────
state10 = make_state(pump=80.0, relief=10.0, ts=NOW - 10.0)
v10 = physical_agent.check_command(make_command("tx-fix", NOW, SRC, 16, FEED_PUMP, 75.0), state10)
print(f"\n10. Corrective move (pump 80->75 while relief 10): {v10}")
assert v10["pass"], "Test 10 failed"

# ── Test 11: Existing bounds still apply to new machines ─────────────────────
v11 = physical_agent.check_command(make_command("tx-oob2", NOW, SRC, 16, HEATER_TEMP, 180.0),
                                   make_state(ts=NOW - 60.0))
print(f"\n11. Heater out of bounds (180 C, max 150): {v11}")
assert not v11["pass"] and "OUT_OF_BOUNDS" in v11["reason"], "Test 11 failed"

print("\n" + "=" * 60)
print("All 11 tests passed ✓")
print("=" * 60)
