"""
scada/scada.py

SCADA operator simulation.

Sends one Modbus write every 2 seconds to the middleware.

Every command is an HMAC-SHA256 signed frame (Modbus FC16 to FRAME_BASE,
see core/hmac_auth.py). The shared secret comes from IM_HMAC_SECRET /
IM_HMAC_SECRET_FILE / config/hmac_secret.key - the same source the
middleware uses.

Flow:
    SCADA -> Middleware :5021 -> PLC :5020
"""

from __future__ import annotations

from typing import Dict, Optional
import argparse
import random
import time
import uuid

from pymodbus.client import ModbusTcpClient

from core.interfaces import REGISTER_MAP, MACHINES, NUM_REGISTERS, FRAME_BASE, from_raw
from core import hmac_auth, netconfig


# ============================================================
# CONFIGURATION
# ============================================================

# The source IP seen by the middleware is the real address of this
# process's TCP connection; it is not configured here.

FUNCTION_CODE = 16   # signed frames use write-multiple-registers
SCALE = 10

COMMAND_INTERVAL = 2.0


# ============================================================
# OPERATOR PROFILES
# ============================================================

# Built from the central machine config (core/interfaces.MACHINES).
OPERATOR_PROFILES = {
    m["name"]: {
        "register": m["register"],
        "target": float(m["operator"]["target"]),
        "step": float(m["operator"]["step"]),
        "current": float(m["initial"]),
    }
    for m in MACHINES
    if m["kind"] == "actuator"      # SCADA commands actuators only; sensors are read back
}


# ============================================================
# SETPOINT GENERATION
# ============================================================

def _sync_with_plant(name: str, actual: Optional[float]) -> None:
    """
    If something else moved the plant well away from the operator's own
    setpoint (another operator, an attack that got through, a reset), the
    operator continues from the ACTUAL reading instead of issuing a large
    jump back to a stale value.
    """

    if actual is None:
        return

    profile = OPERATOR_PROFILES[name]

    if abs(actual - profile["current"]) > 2 * profile["step"]:
        profile["current"] = actual


def _read_plant(client: ModbusTcpClient) -> Dict[str, float]:
    """Read the live plant values the middleware mirrors from the PLC."""

    try:
        result = client.read_holding_registers(
            0,
            count=NUM_REGISTERS,
            slave=1
        )

        if result.isError():
            return {}

        return {
            m["name"]: from_raw(raw)
            for m, raw in zip(MACHINES, result.registers)
        }

    except Exception:
        return {}


def _next_setpoint(name: str) -> float:
    """
    Gradually move the simulated operator value
    toward the target value.
    """

    profile = OPERATOR_PROFILES[name]

    current = profile["current"]
    target = profile["target"]
    step = profile["step"]

    if current < target:
        current = min(current + step, target)

    elif current > target:
        current = max(current - step, target)

    profile["current"] = current

    return current


# ============================================================
# VALUE CONVERSION
# ============================================================

def _to_raw(register: int, value: float) -> int:
    """
    Convert engineering value into Modbus register value.
    """

    config = REGISTER_MAP[register]

    minimum = config["min"]
    maximum = config["max"]

    value = max(minimum, min(maximum, value))

    return int(round(value * SCALE))


# ============================================================
# SEND MODBUS WRITE
# ============================================================

def send_write(client: ModbusTcpClient, register: int, value: float) -> None:
    """
    Send one HMAC-signed command frame to middleware.
    """

    raw_value = _to_raw(register, value)

    frame = hmac_auth.build_frame(
        register,
        raw_value / SCALE
    )

    tx_id = str(uuid.uuid4())[:8]

    register_name = REGISTER_MAP[register]["name"]

    print(
        f"[SCADA] WRITE "
        f"tx={tx_id} "
        f"reg={register_name} "
        f"value={value:.2f}"
    )

    try:
        result = client.write_registers(
            address=FRAME_BASE,
            values=frame,
            slave=1
        )

        if result.isError():
            print(
                f"[SCADA] WRITE FAILED "
                f"tx={tx_id} "
                f"reg={register_name}"
            )

        else:
            print(
                f"[SCADA] WRITE SENT "
                f"tx={tx_id} "
                f"reg={register_name} "
                f"value={value:.2f}"
            )

    except Exception as e:
        print(
            f"[SCADA] ERROR "
            f"tx={tx_id}: {e}"
        )


# ============================================================
# OPERATOR SIMULATION
# ============================================================

def run_operator_loop(host: str = netconfig.MIDDLEWARE_HOST, port: int = netconfig.MIDDLEWARE_PORT) -> None:
    """
    Connect to middleware and continuously simulate
    normal SCADA operator commands.

    Exactly ONE command is sent every 2 seconds.
    """

    # Fail fast if the shared HMAC secret is misconfigured.
    hmac_auth.get_secret()

    client = ModbusTcpClient(
        host,
        port=port
    )

    print()
    print("=" * 60)
    print(" SCADA OPERATOR SIMULATION")
    print("=" * 60)

    print(
        f"[SCADA] Connecting to "
        f"{host}:{port} ..."
    )

    if not client.connect():
        print("[SCADA] Connection failed.")
        return

    print("[SCADA] Connected successfully.")
    print(
        "[SCADA] Sending ONE command every "
        f"{COMMAND_INTERVAL:.0f} seconds."
    )
    print("[SCADA] Press Ctrl-C to stop.")
    print()

    # Rotate through every configured machine.
    registers = [
        m["name"] for m in MACHINES if m["kind"] == "actuator"
    ]

    index = 0

    try:

        while True:

            name = registers[index]

            profile = OPERATOR_PROFILES[name]

            register = profile["register"]

            _sync_with_plant(
                name,
                _read_plant(client).get(name)
            )

            value = _next_setpoint(name)

            send_write(
                client=client,
                register=register,
                value=value
            )

            # Move to the next parameter.
            index = (index + 1) % len(registers)

            # Wait exactly 2 seconds before
            # generating the next command.
            time.sleep(COMMAND_INTERVAL)

    except KeyboardInterrupt:

        print()
        print("[SCADA] Operator simulation stopped.")

    finally:

        client.close()

        print("[SCADA] Connection closed.")


# ============================================================
# OPERATOR RECOVERY
# ============================================================

RESTORE_SPACING = 0.5        # s between commands (stays under the 5/s/source rate limit)
RESTORE_MAX_ROUNDS = 600
REPLAY_WINDOW = 2.5          # s; > the Cyber Agent duplicate-payload window (2 s)


def run_restore(host: str = netconfig.MIDDLEWARE_HOST, port: int = netconfig.MIDDLEWARE_PORT) -> int:
    """
    Operator recovery after an incident: bring every actuator back to its
    operator target, one signed command at a time, THROUGH the middleware.
    Each command moves an actuator by at most its operator step from the value
    the PLC reports, so the Physical Agent's rate-of-change rule accepts it.
    Exits 0 when every actuator is within one step of its target.
    """

    hmac_auth.get_secret()
    client = ModbusTcpClient(host, port=port)

    print("[SCADA] RESTORE: bringing every actuator back to its operator target")
    if not client.connect():
        print("[SCADA] Connection failed.")
        return 2

    try:
        last_sent: Dict[str, tuple] = {}     # name -> (value, time): never repeat a payload inside the replay window
        for rnd in range(1, RESTORE_MAX_ROUNDS + 1):
            plant = _read_plant(client)
            if not plant:
                print("[SCADA] Cannot read the plant state.")
                return 2

            pending = []
            for name, profile in OPERATOR_PROFILES.items():
                actual = plant.get(name)
                if actual is None:
                    continue
                gap = profile["target"] - actual
                if abs(gap) > max(profile["step"] * 0.5, 0.2):
                    pending.append((name, profile, actual, gap))

            if not pending:
                print(f"[SCADA] RESTORE complete after {rnd - 1} round(s): all actuators at their operator targets.")
                for name, profile in OPERATOR_PROFILES.items():
                    profile["current"] = plant.get(name, profile["current"])
                return 0

            print(f"[SCADA] RESTORE round {rnd}: {len(pending)} actuator(s) still away from target")
            for name, profile, actual, gap in pending:
                # Half an operator step: the Physical Agent's rate limit is measured against the age of its
                # last plant snapshot, so a small move is accepted whatever the poll phase.
                limit = profile["step"] / 2
                move = max(-limit, min(limit, gap))
                value = round(actual + move, 1)
                prev = last_sent.get(name)
                if prev and prev[0] == value and time.time() - prev[1] < REPLAY_WINDOW:
                    continue                     # same payload as the last attempt: wait, do not trip replay detection
                last_sent[name] = (value, time.time())
                send_write(client, profile["register"], value)
                time.sleep(RESTORE_SPACING)
            time.sleep(RESTORE_SPACING)

        print("[SCADA] RESTORE gave up (actuators still away from target; check the middleware log).")
        return 1

    finally:
        client.close()


# ============================================================
# MAIN
# ============================================================

def main() -> None:

    parser = argparse.ArgumentParser(
        description="Industrial Mind SCADA simulator"
    )

    parser.add_argument(
        "--host",
        default=netconfig.MIDDLEWARE_HOST,
        help="Middleware host (env IM_MIDDLEWARE_HOST)"
    )

    parser.add_argument(
        "--port",
        type=int,
        default=netconfig.MIDDLEWARE_PORT,
        help="Middleware Modbus port (env IM_MIDDLEWARE_PORT)"
    )

    parser.add_argument(
        "--restore",
        action="store_true",
        help="One-shot operator recovery: signed commands bring every actuator back to its target, then exit"
    )

    args = parser.parse_args()

    if args.restore:
        raise SystemExit(run_restore(host=args.host, port=args.port))

    run_operator_loop(
        host=args.host,
        port=args.port
    )


if __name__ == "__main__":
    main()