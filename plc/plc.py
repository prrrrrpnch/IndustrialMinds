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

import time
import threading

from docs import netconfig
from docs.interfaces import MACHINES, NUM_REGISTERS, REGISTER_MAP, SCALE

from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext, ModbusSequentialDataBlock
from pymodbus.server import StartTcpServer

# --- Internal plant state -------------------------------------------------

_state_lock = threading.Lock()

# One entry per machine in docs/interfaces.MACHINES (centralized config).
_current_values = {m["register"]: float(m["initial"]) for m in MACHINES}

_target_values = dict(_current_values)  # targets start equal to current

# How fast each register can physically move per second (tune these)
_RATE_PER_SEC = {m["register"]: float(m["rate_per_sec"]) for m in MACHINES}

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
    """Called by middleware when a command is forwarded. Updates plant target.

    No bounds-checking here by design — that's the Physical Agent's job.
    The PLC just records whatever target it's told and moves toward it.
    """
    with _state_lock:
        if register not in _target_values:
            raise ValueError(f"Unknown register: {register}")
        _target_values[register] = value
        _recent_writes.append(time.time())

    notify_upstream_response(register, value)



def tick(dt: float) -> None:
    """Advances the physics simulation by dt seconds. Call this in a loop."""
    with _state_lock:
        for reg in _current_values:
            current = _current_values[reg]
            target = _target_values[reg]
            max_step = _RATE_PER_SEC[reg] * dt

            diff = target - current
            if abs(diff) <= max_step:
                _current_values[reg] = target
            else:
                _current_values[reg] = current + max_step * (1 if diff > 0 else -1)

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
                for reg, val in _current_values.items()
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
                for reg, val in _current_values.items():
                    internal_sync_write(block, reg, [_to_raw(val)])
            time.sleep(0.1)

    threading.Thread(target=_physics_loop, daemon=True).start()
    threading.Thread(target=_sync_reads_loop, daemon=True).start()

    print(f"PLC Modbus server running on {host}:{port}")
    StartTcpServer(context=context, address=(host, port))


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Industrial Mind PLC digital twin (Modbus TCP)")
    parser.add_argument("--host", default=netconfig.PLC_LISTEN_HOST, help="bind address (env IM_PLC_LISTEN_HOST)")
    parser.add_argument("--port", type=int, default=netconfig.PLC_LISTEN_PORT, help="bind port (env IM_PLC_LISTEN_PORT)")
    args = parser.parse_args()
    start_modbus_server(args.host, args.port)