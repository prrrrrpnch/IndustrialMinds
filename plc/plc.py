"""
plc/plc.py — Modbus TCP server + physics simulation for the plant PLC.

Pinned dependency: pymodbus==3.6.9
    pip install "pymodbus==3.6.9"

Why pinned: pymodbus 3.13+ replaced ModbusSlaveContext / ModbusSequentialDataBlock
with a new SimData/SimDevice model and is actively removing the old classes on
the way to v4.0. The write-hook pattern this file relies on (subclassing
ModbusSequentialDataBlock.setValues) only works on the pre-3.13 API. Don't
`pip install -U pymodbus` on this file without re-testing against the new API.
"""

from __future__ import annotations

import asyncio
import contextvars
import ipaddress
import logging
import os
import time
import threading
from typing import Any, List, Optional, Union

from core import netconfig
from plc.twin import PlantTwin
from core.interfaces import MACHINES, NUM_REGISTERS, REGISTER_MAP, SCALE

from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext, ModbusSequentialDataBlock
from pymodbus.server import ModbusTcpServer
from pymodbus.server.async_io import ModbusServerRequestHandler

log = logging.getLogger("industrialmind.plc")

# =========================================================
# WRITE-SOURCE ENFORCEMENT  (AUDIT S1)
#
# The whole product rests on the middleware being IN the path. It was not enforced: anything on the OT segment could open a
# socket to the PLC on :5020 and write FC6 register 0 = 0, slamming the inlet valve shut with no signature, no rule, no log
# and no trace. Demonstrated on the wire as frame 2018 in docs/reports/system_flow_verification.md. A guard that can be
# walked around is not a guard.
#
# The PLC now applies a write only from an allowed writer. This is deliberately NOT another off-by-default flag (the audit's
# A5 finding was that every security control shipped off): the default allow-list is the middleware's own address, which on
# a one-laptop demo is 127.0.0.1 - the same address everything else uses - so the default demo is unchanged. On the
# documented four-laptop lab, where the addresses differ, the PLC refuses the attacker's direct write out of the box.
#
#   IM_PLC_ALLOWED_WRITERS   comma-separated IPs/CIDRs; default = IM_MIDDLEWARE_HOST
#                            "any" (or "*") restores the old unprotected behaviour, explicitly, for demonstrating the bypass
#
# This is defence in depth, not a replacement for network segmentation: a writer that can spoof the middleware's source
# address still gets through. Segmenting the PLC so only the middleware can route to it remains the real control.
# =========================================================

ALLOWED_WRITERS_ENV = netconfig.PLC_ALLOWED_WRITERS

UNKNOWN_SOURCE_IP = "unknown"

_write_source: contextvars.ContextVar = contextvars.ContextVar("im_plc_write_source", default=None)

_refused_writes = []          # recent refusals, for the telemetry counter and the operator log
_refused_lock = threading.Lock()
_last_refusal_log = 0.0
REFUSAL_LOG_INTERVAL = 2.0


def _parse_networks(spec: str) -> List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
    nets = []
    for item in (spec or "").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            log.warning(f"[PLC] ignoring unparseable entry in IM_PLC_ALLOWED_WRITERS: {item!r}")
    return nets


_ALLOW_ANY = ALLOWED_WRITERS_ENV.strip().lower() in ("any", "*", "all")
_ALLOWED_WRITER_NETS = [] if _ALLOW_ANY else _parse_networks(ALLOWED_WRITERS_ENV)


def _normalize_ip(ip: object) -> str:
    ip = str(ip or "")
    if ip.startswith("::ffff:"):
        ip = ip[7:]
    return ip


def writer_allowed(source_ip: object) -> bool:
    """May this source apply a write to the plant? (AUDIT S1)"""
    if _ALLOW_ANY:
        return True
    if not _ALLOWED_WRITER_NETS:
        # A configured-but-empty list would silently brick the PLC. Treat it as unconfigured and allow, having said so.
        return True
    if source_ip in (None, "", UNKNOWN_SOURCE_IP):
        # No peer address available (an in-process call, or a transport that did not report one). Internal syncs do not
        # come through here, so this is a real external write we cannot attribute - refuse it.
        return False
    try:
        addr = ipaddress.ip_address(_normalize_ip(source_ip))
    except ValueError:
        return False
    if getattr(addr, "ipv4_mapped", None):
        addr = addr.ipv4_mapped
    return any(addr in net for net in _ALLOWED_WRITER_NETS)


def _record_refusal(source_ip: str, register: int, value: float) -> None:
    global _last_refusal_log
    entry = {"time": time.time(), "source_ip": source_ip, "register": register, "value": value,
             "name": REGISTER_MAP.get(register, {}).get("name", f"reg{register}")}
    with _refused_lock:
        _refused_writes.append(entry)
        del _refused_writes[:-200]
        total = len(_refused_writes)
        now = entry["time"]
        due = now - _last_refusal_log >= REFUSAL_LOG_INTERVAL
        if due:
            _last_refusal_log = now
    if due:
        log.warning(
            f"[PLC] REFUSED direct write from {source_ip}: {entry['name']}={value:.2f} - "
            f"not an allowed writer (IM_PLC_ALLOWED_WRITERS={ALLOWED_WRITERS_ENV}). "
            f"This is a middleware bypass attempt; {total} refused so far. "
            f"(If {source_ip} IS your middleware, set IM_MIDDLEWARE_HOST or IM_PLC_ALLOWED_WRITERS to it on this laptop.)"
        )


def refused_writes() -> list:
    """A copy of the recent refused direct writes (AUDIT S1), for telemetry and tests."""
    with _refused_lock:
        return list(_refused_writes)


class WriteSourceRequestHandler(ModbusServerRequestHandler):
    """Records the real peer address of each request so the datastore hook knows who is writing (AUDIT S1).

    Same pattern as the middleware's SourceTrackingRequestHandler - the datastore API gives the hook no access to the
    connection, so the address is carried in a context variable for the duration of the request."""

    async def _async_execute(self, request: Any, *addr: Any) -> None:
        try:
            peer = self.transport.get_extra_info("peername")
        except Exception:
            peer = None
        token = _write_source.set(_normalize_ip(peer[0]) if peer else UNKNOWN_SOURCE_IP)
        try:
            await super()._async_execute(request, *addr)
        finally:
            _write_source.reset(token)


class WriteSourceTcpServer(ModbusTcpServer):
    def callback_new_connection(self) -> "WriteSourceRequestHandler":
        return WriteSourceRequestHandler(self)

# --- Internal plant state -------------------------------------------------

_state_lock = threading.Lock()

# The plant is a staged, physically coupled water-treatment twin (plc/twin.py).
# Actuator registers accept commands; sensor registers are computed by the physics.
# IM_TWIN_TIME_SCALE > 1 speeds the process up. Sensor noise is ON by default (IM_TWIN_NOISE=0 turns it off): the
# physical model was trained on real, noisy SWaT sensors and treats a perfectly flat, noiseless plant as out-of-distribution.
_twin = PlantTwin(
    noise=os.environ.get("IM_TWIN_NOISE", "1") == "1",
    time_scale=float(os.environ.get("IM_TWIN_TIME_SCALE", "1")),
)
_target_values = _twin.target   # actuator registers only (live view of the twin's commands)

_recent_writes = []   # timestamps of recent writes, for the CPU-load metric
_cpu_baseline = 5.0
_cpu_current = _cpu_baseline

# Registers are stored on the wire as raw 16-bit unsigned ints (0-65535).
# We keep one decimal place of precision by scaling floats by this factor
# before writing, and dividing by it after reading. Agreed with Abhiram so
# middleware_server.py decodes the same way.
_SCALE = SCALE


def notify_upstream_response(register: int, value: float) -> None:
    """Notifies middleware/orchestrator of upstream PLC feedback response."""
    try:
        from middleware.orchestrator import decide
        reg_info = REGISTER_MAP.get(register, {})
        reg_name = reg_info.get("name", f"REGISTER_{register}")
        unit = reg_info.get("unit", "")
        tx_id = f"PLC-TXN-{int(time.time())}"
        phys_verdict = {
            "tx_id": tx_id,
            "pass": True,
            "reason": f"PLC confirmed: {reg_name} updated to {value} {unit}".strip(),
            "command": f"{reg_name} → {value} {unit}".strip(),
        }
        decide(None, phys_verdict)
    except Exception:
        pass


def apply_write(register: int, value: float) -> None:
    """Called by middleware when a command is forwarded. Updates an actuator target.

    No safety checking here by design — that's the Physical Agent's job. The PLC
    just records the target and moves toward it. Sensor registers cannot be
    commanded (the physics produces them); a write to one is ignored.
    """
    with _state_lock:
        if register not in _target_values:
            return
        _twin.set_target(register, value)
        _recent_writes.append(time.time())

    notify_upstream_response(register, value)



def tick(dt: float) -> None:
    """Advances the physics simulation by dt seconds. Call this in a loop."""
    with _state_lock:
        _twin.step(dt)
        _update_cpu_load()


def _update_cpu_load() -> None:
    """Internal: derive a fake CPU load from recent write frequency."""
    global _cpu_current
    now = time.time()
    recent = [t for t in _recent_writes if now - t <= 1.0]
    _recent_writes[:] = recent

    writes_per_sec = len(recent)
    target_load = min(100.0, _cpu_baseline + writes_per_sec * 8.0)
    _cpu_current += (target_load - _cpu_current) * 0.3


def _physics_loop(interval: float = 0.1) -> None:
    while True:
        tick(interval)
        time.sleep(interval)


def get_telemetry() -> dict:
    """Returns {"registers": {...}, "cpu_load": float, "timestamp": float}"""
    with _state_lock:
        return {
            "registers": {
                REGISTER_MAP[reg]["name"]: round(val, 2)
                for reg, val in _twin.values().items()
            },
            "cpu_load": round(_cpu_current, 1),
            "timestamp": time.time(),
        }


def _to_raw(value: float) -> int:
    """Float plant value -> raw 16-bit register int, clamped to a valid range."""
    raw = int(round(value * _SCALE))
    return max(0, min(65535, raw))


def _from_raw(raw: int) -> float:
    """Raw 16-bit register int -> float plant value."""
    return raw / _SCALE


class SyncedDataBlock(ModbusSequentialDataBlock):
    """Holding-register block that calls apply_write() when an EXTERNAL
    master (middleware/SCADA) writes to it.

    Internal state->datastore syncing must NOT go through this override —
    see internal_sync_write() below. If it did, every periodic sync would
    re-trigger apply_write() and immediately overwrite whatever target a
    real external write had just set, freezing the physics simulation and
    permanently inflating the CPU-load metric.
    """

    def setValues(self, address: int, values: list) -> None:

        # AUDIT S1: who is writing? An external write from anything but an allowed writer is refused outright - the value
        # is not stored and the physics never sees it, so a bypass cannot move the plant. The frame is still visible on the
        # wire (and in a capture), which is what makes the refusal demonstrable.
        source_ip = _write_source.get()
        if not writer_allowed(source_ip):
            for i, raw_value in enumerate(values):
                register = address + i
                if register in _target_values:
                    _record_refusal(source_ip or UNKNOWN_SOURCE_IP, register, _from_raw(raw_value))
            return

        super().setValues(address, values)
        for i, raw_value in enumerate(values):
            register = address + i
            if register in _target_values:
                apply_write(register, _from_raw(raw_value))


def internal_sync_write(block: ModbusSequentialDataBlock, address: int, values: list) -> None:
    """Writes to the datastore WITHOUT re-triggering apply_write.
    Use this for the internal current-state -> datastore sync loop only.
    """
    ModbusSequentialDataBlock.setValues(block, address, values)


def start_modbus_server(host: str = netconfig.PLC_LISTEN_HOST, port: int = netconfig.PLC_LISTEN_PORT) -> None:
    """Starts the Modbus TCP server exposing one register per configured machine."""
    block = SyncedDataBlock(0, [0] * NUM_REGISTERS)  # base address 0 -> valid addrs 0..N-1
    store = ModbusSlaveContext(hr=block, zero_mode=True)
    context = ModbusServerContext(slaves=store, single=True)

    def _sync_reads_loop() -> None:
        while True:
            with _state_lock:
                for reg, val in _twin.values().items():
                    internal_sync_write(block, reg, [_to_raw(val)])
            time.sleep(0.1)

    threading.Thread(target=_physics_loop, daemon=True).start()
    threading.Thread(target=_sync_reads_loop, daemon=True).start()

    print(f"PLC Modbus server running on {host}:{port}")
    if _ALLOW_ANY:
        print("  write protection: OFF (IM_PLC_ALLOWED_WRITERS=any) - ANY host on this network can command the plant")
    elif _ALLOWED_WRITER_NETS:
        print(f"  writes accepted only from: {ALLOWED_WRITERS_ENV}  (AUDIT S1; set IM_PLC_ALLOWED_WRITERS=any to disable)")
    else:
        print("  write protection: OFF - IM_PLC_ALLOWED_WRITERS parsed to an empty list")

    async def _serve() -> None:
        server = WriteSourceTcpServer(context=context, address=(host, port))
        await server.serve_forever()

    asyncio.run(_serve())


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Industrial Mind PLC digital twin (Modbus TCP)")
    parser.add_argument("--host", default=netconfig.PLC_LISTEN_HOST, help="bind address (env IM_PLC_LISTEN_HOST)")
    parser.add_argument("--port", type=int, default=netconfig.PLC_LISTEN_PORT, help="bind port (env IM_PLC_LISTEN_PORT)")
    args = parser.parse_args()
    start_modbus_server(args.host, args.port)