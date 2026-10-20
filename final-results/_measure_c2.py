"""Measure the black-hole-PLC stall before/after the C2 structural fix.

A PLC that accepts TCP and never answers. The audit measured 2,002 ms per command (library defaults), then 504 ms after
the timeout was bounded. With the forward moved off the event loop the SCADA client should no longer wait for it at all.
"""
import os
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time

ROOT = "/home/user/IndustrialMinds"
RUN = tempfile.mkdtemp(prefix="c2-")
BH_PORT, MW_PORT = 5920, 5921

stop = threading.Event()


def blackhole():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", BH_PORT))
    s.listen(50)
    s.settimeout(0.5)
    held = []
    while not stop.is_set():
        try:
            c, _ = s.accept()
            held.append(c)          # accept, never answer
        except socket.timeout:
            pass
    for c in held:
        c.close()
    s.close()


t = threading.Thread(target=blackhole, daemon=True)
t.start()
time.sleep(0.5)

env = dict(os.environ, PYTHONPATH=ROOT, PYTHONUNBUFFERED="1", IM_LOG_DIR=RUN,
           IM_PLC_PORT=str(BH_PORT), IM_LISTEN_PORT=str(MW_PORT), IM_MIDDLEWARE_PORT=str(MW_PORT),
           IM_HMAC_SECRET="c2-measure-secret-0123456789abcdef0123456789",
           IM_DASHBOARD_URL="http://127.0.0.1:5999")        # nothing listening: dashboard posts are fire-and-forget
for k in ("IM_QUARANTINE", "IM_DASHBOARD_TOKEN", "IM_INVESTIGATOR", "IM_POLICY_FILE"):
    env.pop(k, None)

mw = subprocess.Popen([sys.executable, "-m", "middleware.middleware_server"], cwd=ROOT, env=env,
                      stdout=open(os.path.join(RUN, "mw.log"), "w"), stderr=subprocess.STDOUT)
for _ in range(80):
    with socket.socket() as s:
        s.settimeout(0.3)
        if s.connect_ex(("127.0.0.1", MW_PORT)) == 0:
            break
    time.sleep(0.25)
time.sleep(3)

_boot = open(os.path.join(RUN, "mw.log")).read()
if "address already in use" in _boot or mw.poll() is not None:
    raise SystemExit("the middleware under test did not start (a stale one holds the port) - measurement aborted")

sys.path.insert(0, ROOT)
os.environ["IM_HMAC_SECRET"] = "c2-measure-secret-0123456789abcdef0123456789"
os.environ["IM_MIDDLEWARE_PORT"] = str(MW_PORT)
import contextlib
import io as _io
from pymodbus.client import ModbusTcpClient
from docs import hmac_auth
from docs.interfaces import MACHINE_BY_NAME, to_raw

FRAME_BASE = 100
client = ModbusTcpClient("127.0.0.1", port=MW_PORT, timeout=10)
client.connect()


def signed_write(reg, value):
    frame = hmac_auth.build_frame(reg, value)   # build_frame takes the ENGINEERING value and scales it itself
    t0 = time.perf_counter()
    client.write_registers(FRAME_BASE, frame)
    return (time.perf_counter() - t0) * 1000.0


# Small moves around each actuator's nominal, so every command PASSes the rules and actually reaches the forwarder -
# the point of the measurement is the forward, not the drop path.
NOMINAL = {"P101": 70.0, "MV101": 55.0, "P302": 70.0, "MV302": 98.0}
tags = ["P101", "MV101", "P302", "P101", "MV101", "P302", "P101", "MV101", "P302", "P101"]
lat = []
with contextlib.redirect_stdout(_io.StringIO()):
    for i, tag in enumerate(tags):
        lat.append(signed_write(MACHINE_BY_NAME[tag]["register"], NOMINAL[tag] + (i % 5) - 2))
        time.sleep(0.35)          # stay under the 5/s rate limit
client.close()

print('waiting for the forward backlog to drain...')
time.sleep(25)

stop.set()
mw.terminate()
try:
    mw.wait(timeout=10)
except Exception:
    mw.kill()

lat.sort()
print(f"n={len(lat)}")
print(f"  min    {lat[0]:8.1f} ms")
print(f"  median {statistics.median(lat):8.1f} ms")
print(f"  max    {lat[-1]:8.1f} ms")
print(f"  mean   {statistics.mean(lat):8.1f} ms")
print(f"  throughput ceiling {1000.0 / statistics.mean(lat):.1f} commands/s")
log = open(os.path.join(RUN, "mw.log")).read()
print(f"UNDELIVERED lines: {log.count('UNDELIVERED')}")
print(f"pymodbus lines:    {log.count('pymodbus')}")
print(f"log dir: {RUN}")
