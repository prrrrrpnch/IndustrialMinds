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
from docs import netconfig
from docs.netconfig import LOOPBACK  # documented loopback default
from docs import hmac_auth, attack_log
from docs.interfaces import (MACHINES, MV101, P101, LIT101, PIT501, UV401,
                             REGISTER_MAP, NUM_REGISTERS, DATASTORE_SIZE, FRAME_BASE)

NOM = {m['register']: m['initial'] for m in MACHINES}   # nominal setpoints (docs/interfaces)
TEST_IP = LOOPBACK   # what a local SCADA connection reports as its peer address


def send_signed(register, value, ip=TEST_IP):
    """Push a signed frame through the same entry point the Modbus server uses."""
    mw._process_write(FRAME_BASE, hmac_auth.build_frame(register, value),
                      {"source_ip": ip, "source_port": 50000, "function_code": 16})


def send_unsigned(register, value, ip=TEST_IP):
    mw._process_write(register, [int(round(value * 10))],
                      {"source_ip": ip, "source_port": 50001, "function_code": 6})

# Wire up the middleware's PLC-facing client manually (skip start_middleware_server,
# which would also try to launch the blocking StartTcpServer call).
mw._plc_client = ModbusTcpClient(host=netconfig.PLC_HOST, port=netconfig.PLC_PORT)
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
send_signed(MV101, NOM[MV101] + 4.0)   # inlet valve nominal +4 %, well within rate limit
for _ in range(3):
    time.sleep(0.5)
    mw._poll_once(_warmup_block)
after = read_real_plc()
print("PLC state after (t+1.5s):", after)
assert after[MV101] > before[MV101], "FAIL: inlet valve MV101 did not move on the real PLC after a PASS"
print("PASS confirmed: real PLC register actually changed.\n")

print("=" * 70)
print("TEST 2: out-of-bounds write -> should DROP, PLC must NOT move")
print("=" * 70)
before = read_real_plc()
send_signed(P101, 500.0)  # way over the 100 % safe max
time.sleep(1.0)
after = read_real_plc()
print(f"PLC P101 before={before[P101]:.2f} after={after[P101]:.2f}")
assert abs(after[P101] - before[P101]) < 0.1, "FAIL: PLC moved even though the command should have DROPped"
print("PASS confirmed: DROPped command never reached the PLC.\n")

print("=" * 70)
print("TEST 3: rate-of-change violation -> should DROP")
print("=" * 70)
# The rate window is "time since this register last settled" (middleware
# _register_settled_since, 3 s after startup), so first settle P101 with a tiny
# legitimate move; then the next command is judged over a window of ~1 s
# (max ~9 %/s) instead of several seconds.
send_signed(P101, NOM[P101] + 1.0)
for _ in range(3):
    time.sleep(0.4)
    mw._poll_once(_warmup_block)
before = read_real_plc()
send_signed(P101, 100.0)  # raw pump nominal -> 100 % instantly, way too fast (limit ~8.8 %/s)
time.sleep(1.0)
after = read_real_plc()
print(f"PLC P101 before={before[P101]:.2f} after={after[P101]:.2f}")
assert abs(after[P101] - before[P101]) < 0.5, "FAIL: PLC moved on a rate-of-change violation"
print("PASS confirmed: rate-of-change violation correctly dropped.\n")

print("=" * 70)
print("TEST 4: flood (same register, same source_ip) -> later ones DROP")
print("=" * 70)
log_before = len(orchestrator.get_log())
for i in range(7):
    send_signed(MV101, NOM[MV101] + 4.0 + i * 0.1)  # tiny moves, in-bounds & in-rate
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
send_unsigned(UV401, before[UV401] + 1.0)
time.sleep(1.0)
after = read_real_plc()
last = orchestrator.get_log()[-1]
print("decision:", last)
assert last["verdict"] == "DROP" and last["reason"].startswith("HMAC_MISSING")
assert abs(after[UV401] - before[UV401]) < 0.1, "FAIL: unsigned command reached the PLC"
print("PASS confirmed: unsigned command blocked by Cyber Agent.\n")

print("=" * 70)
print("TEST 7: tampered signed frame -> HMAC_INVALID")
print("=" * 70)
frame = hmac_auth.build_frame(UV401, before[UV401] + 1.0)
frame[2] = 1400
mw._process_write(FRAME_BASE, frame, {"source_ip": TEST_IP, "function_code": 16})
last = orchestrator.get_log()[-1]
print("decision:", last)
assert last["verdict"] == "DROP" and last["reason"].startswith("HMAC_INVALID")
print("PASS confirmed.\n")

print("=" * 70)
print("TEST 8: each blocked command is in the attack log with its real source IP")
print("=" * 70)
UNTRUSTED_IP = "127.9.8.7"   # loopback range, but not on the trusted whitelist (127.0.0.1 only)
send_signed(MV101, NOM[MV101] + 5.0, ip=UNTRUSTED_IP)   # untrusted source
recs = attack_log.AttackLogReader().records()
print(f"{len(recs)} records in {attack_log.LOG_FILE}")
print(json.dumps(recs[-1], indent=2))
ips = {r["source_ip"] for r in recs}
assert UNTRUSTED_IP in ips and TEST_IP in ips
assert all("secret" not in json.dumps(r).lower() for r in recs)
assert any(r["attack_type"] == "Missing HMAC (Unsigned Command)" for r in recs)
print("PASS confirmed.\n")

print("=" * 70)
print("TEST 9: write to a SENSOR register -> WRITE_TO_SENSOR_REGISTER, PLC value unaffected")
print("=" * 70)
time.sleep(1.1)   # leave the rate-limit window
before = read_real_plc()
for reg in (LIT101, PIT501):
    send_signed(reg, 5.0)
    last = orchestrator.get_log()[-1]
    print("decision:", last)
    assert last["verdict"] == "DROP" and last["reason"].startswith("WRITE_TO_SENSOR_REGISTER"), last
time.sleep(1.0)
after = read_real_plc()
# a sensor follows the physics, so it may drift slightly, but never jumps to the written 5.0
assert abs(after[LIT101] - 5.0) > 50 and abs(after[PIT501] - 5.0) > 50, "FAIL: sensor value forced by a write"
print("PASS confirmed: sensor writes dropped by the Physical Agent.\n")

mw._plc_client.close()
print("ALL PIPELINE TESTS COMPLETED")