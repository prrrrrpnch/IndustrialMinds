"""
Exercises the exact production functions from middleware_server.py against a
real, running plc.py — without needing middleware_server's own Modbus TCP
server thread. This validates the actual pipeline logic:
  cyber_agent.check() + physical_agent.check_command() -> orchestrator.decide()
  -> forward-to-PLC-if-PASS -> poll-and-check-feedback
"""
import json
import logging
import os
import tempfile
import time

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s - %(message)s")
logging.getLogger("pymodbus").setLevel(logging.WARNING)

# Keep test DROPs out of the real logs/blocked_attacks.jsonl.
os.environ.setdefault("IM_LOG_DIR", tempfile.mkdtemp(prefix="im-pipeline-"))

from pymodbus.client import ModbusTcpClient

import middleware.middleware_server as mw
from middleware import orchestrator
from docs import hmac_auth, attack_log
from docs.interfaces import (TANK_PRESSURE, CONVEYOR_SPEED, COOLING_VALVE, HEATER_TEMP,
                             REGISTER_MAP, NUM_REGISTERS, DATASTORE_SIZE, FRAME_BASE)

TEST_IP = "127.0.0.1"   # what a local SCADA connection reports as its peer address


def send_signed(register, value, ip=TEST_IP):
    """Push a signed frame through the same entry point the Modbus server uses."""
    mw._process_write(FRAME_BASE, hmac_auth.build_frame(register, value),
                      {"source_ip": ip, "source_port": 50000, "function_code": 16})


def send_unsigned(register, value, ip=TEST_IP):
    mw._process_write(register, [int(round(value * 10))],
                      {"source_ip": ip, "source_port": 50001, "function_code": 6})

# Wire up the middleware's PLC-facing client manually (skip start_middleware_server,
# which would also try to launch the blocking StartTcpServer call).
mw._plc_client = ModbusTcpClient(host="127.0.0.1", port=5020)
assert mw._plc_client.connect(), "middleware could not connect to the real PLC"

from pymodbus.datastore import ModbusSequentialDataBlock as _MSDB
_warmup_block = _MSDB(0, [0] * DATASTORE_SIZE)
mw._poll_once(_warmup_block)  # warm up _plc_state["timestamp"] before any command evaluation

def read_real_plc():
    r = mw._plc_client.read_holding_registers(0, count=NUM_REGISTERS)
    return [mw._from_raw(v) for v in r.registers]

print("=" * 70)
print("TEST 1: legit in-bounds write -> should PASS and reach the real PLC")
print("=" * 70)
before = read_real_plc()
print("PLC state before:", before)
send_signed(COOLING_VALVE, 50.0)   # 45 -> 50, well within rate limit
for _ in range(3):
    time.sleep(0.5)
    mw._poll_once(_warmup_block)
after = read_real_plc()
print("PLC state after (t+1.5s):", after)
assert after[2] > before[2], "FAIL: cooling valve did not move on the real PLC after a PASS"
print("PASS confirmed: real PLC register actually changed.\n")

print("=" * 70)
print("TEST 2: out-of-bounds write -> should DROP, PLC must NOT move")
print("=" * 70)
before = read_real_plc()
send_signed(TANK_PRESSURE, 500.0)  # way over the 100 PSI safe max
time.sleep(1.0)
after = read_real_plc()
print(f"PLC TANK_PRESSURE before={before[0]:.2f} after={after[0]:.2f}")
assert abs(after[0] - before[0]) < 0.1, "FAIL: PLC moved even though the command should have DROPped"
print("PASS confirmed: DROPped command never reached the PLC.\n")

print("=" * 70)
print("TEST 3: rate-of-change violation -> should DROP")
print("=" * 70)
before = read_real_plc()
send_signed(CONVEYOR_SPEED, 100.0)  # 0 -> 100 RPM instantly, way too fast
time.sleep(1.0)
after = read_real_plc()
print(f"PLC CONVEYOR_SPEED before={before[1]:.2f} after={after[1]:.2f}")
assert abs(after[1] - before[1]) < 0.5, "FAIL: PLC moved on a rate-of-change violation"
print("PASS confirmed: rate-of-change violation correctly dropped.\n")

print("=" * 70)
print("TEST 4: flood (same register, same source_ip) -> later ones DROP")
print("=" * 70)
log_before = len(orchestrator.get_log())
for i in range(7):
    send_signed(COOLING_VALVE, 50.0 + i * 0.1)  # tiny moves, in-bounds & in-rate
decisions = orchestrator.get_log()[log_before:]
passes = sum(1 for d in decisions if d["verdict"] == "PASS")
drops = sum(1 for d in decisions if d["verdict"] == "DROP")
print(f"7 rapid writes -> {passes} PASS, {drops} DROP")
for d in decisions:
    print("  ", d)
assert drops > 0, "FAIL: flood should have triggered RATE_LIMIT_EXCEEDED on some writes"
print("PASS confirmed: flood correctly rate-limited.\n")

print("=" * 70)
print("TEST 5: upstream feedback check runs one poll cycle and fills in tx_id")
print("=" * 70)
log_before2 = len(orchestrator.get_log())
mw._poll_once(_warmup_block)
upstream_decisions = orchestrator.get_log()[log_before2:]
print(f"Upstream decisions logged this cycle: {len(upstream_decisions)}")
for d in upstream_decisions:
    print("  ", d)
    assert d["tx_id"] != "", "FAIL: upstream decision has a blank tx_id"
if upstream_decisions:
    print("PASS confirmed: upstream feedback logged with a real tx_id, not blank.\n")
else:
    print("(no pending commands left to check feedback against at this exact moment — timing-dependent, not a bug)\n")

print("=" * 70)
print("TEST 6: unsigned write -> HMAC_MISSING, PLC must NOT move")
print("=" * 70)
time.sleep(1.1)   # leave the rate-limit window from TEST 4
before = read_real_plc()
send_unsigned(HEATER_TEMP, before[HEATER_TEMP] + 1.0)
time.sleep(1.0)
after = read_real_plc()
last = orchestrator.get_log()[-1]
print("decision:", last)
assert last["verdict"] == "DROP" and last["reason"].startswith("HMAC_MISSING")
assert abs(after[HEATER_TEMP] - before[HEATER_TEMP]) < 0.1, "FAIL: unsigned command reached the PLC"
print("PASS confirmed: unsigned command blocked by Cyber Agent.\n")

print("=" * 70)
print("TEST 7: tampered signed frame -> HMAC_INVALID")
print("=" * 70)
frame = hmac_auth.build_frame(HEATER_TEMP, before[HEATER_TEMP] + 1.0)
frame[2] = 1400
mw._process_write(FRAME_BASE, frame, {"source_ip": TEST_IP, "function_code": 16})
last = orchestrator.get_log()[-1]
print("decision:", last)
assert last["verdict"] == "DROP" and last["reason"].startswith("HMAC_INVALID")
print("PASS confirmed.\n")

print("=" * 70)
print("TEST 8: each blocked command is in the attack log with its real source IP")
print("=" * 70)
send_signed(COOLING_VALVE, 51.0, ip="10.9.8.7")   # untrusted source
recs = attack_log.AttackLogReader().records()
print(f"{len(recs)} records in {attack_log.LOG_FILE}")
print(json.dumps(recs[-1], indent=2))
ips = {r["source_ip"] for r in recs}
assert "10.9.8.7" in ips and TEST_IP in ips
assert all("secret" not in json.dumps(r).lower() for r in recs)
assert any(r["attack_type"] == "Missing HMAC (Unsigned Command)" for r in recs)
print("PASS confirmed.\n")

mw._plc_client.close()
print("ALL PIPELINE TESTS COMPLETED")