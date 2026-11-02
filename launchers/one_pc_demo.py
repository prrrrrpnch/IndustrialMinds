"""
launchers/one_pc_demo.py - BACKUP: run the whole system on ONE computer (everything on loopback).

    python launchers/one_pc_demo.py                # start PLC + dashboard + middleware + SCADA, open the dashboard, attack menu
    python launchers/one_pc_demo.py --no-browser   # do not open the browser
    python launchers/one_pc_demo.py --no-capture   # do not record packets with tshark

Starts the four services as child processes, waits for each port, then offers the attack menu. Ctrl+C (or Q) stops
everything. Logs go to logs/one_pc_demo/. Nothing here needs config/lab.env: every address is loopback.

This is a rehearsal/backup, NOT the real network demo: all traffic stays on this machine, so it cannot show packets
crossing between laptops. Say so if you present it.
"""

from __future__ import annotations

import argparse
import os
import secrets
import shutil
import socket
import subprocess
import sys
import time
import webbrowser

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(ROOT, "logs", "one_pc_demo")
HOST = "127.0.0.1"

SERVICES = [   # (name, argv after python, port to wait for)
    ("plc", ["-m", "plc.plc"], 5020),
    ("dashboard", ["dashboard/app.py"], 5050),
    ("middleware", ["-m", "middleware.middleware_server"], 5021),
    ("scada", ["-m", "scada.scada"], None),
]

ATTACKS = [
    ("hmac-missing", ["hmac-missing"]),
    ("hmac-tamper", ["hmac-tamper"]),
    ("hmac-forged", ["hmac-forged"]),
    ("replay", ["replay"]),
    ("flood", ["flood"]),
    ("impossible-command", ["impossible-command"]),
    ("sensor-write", ["sensor-write"]),
    ("cross-register", ["cross-register"]),
    ("random ramp", ["random", "--type", "ramp"]),
    ("false-injection", ["false-injection"]),
]

procs: dict = {}
capture = None
pcap = os.path.join(LOG_DIR, "loopback.pcapng")


def port_open(port: int) -> bool:
    try:
        with socket.create_connection((HOST, port), timeout=0.5):
            return True
    except OSError:
        return False


def wait_port(name: str, port: int, timeout: float = 40.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if procs[name].poll() is not None:
            return False
        if port_open(port):
            return True
        time.sleep(0.5)
    return False


def start(name: str, argv: list, env: dict) -> None:
    log = open(os.path.join(LOG_DIR, f"{name}.log"), "w")
    procs[name] = subprocess.Popen([sys.executable, *argv], cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)


def loopback_interface() -> str | None:
    if sys.platform == "darwin":
        return "lo0"
    if sys.platform.startswith("win"):
        return "Adapter for loopback traffic capture"
    return "lo"


def start_capture(env: dict) -> None:
    global capture
    tshark = shutil.which("tshark")
    if not tshark and sys.platform.startswith("win"):
        guess = r"C:\Program Files\Wireshark\tshark.exe"
        tshark = guess if os.path.exists(guess) else None
    if not tshark:
        print("  (tshark not found: packets will not be recorded)")
        return
    iface = loopback_interface()
    capture = subprocess.Popen(
        [tshark, "-i", iface, "-n", "-q", "-f", "tcp port 5020 or tcp port 5021", "-w", pcap],
        stdout=subprocess.DEVNULL, stderr=open(os.path.join(LOG_DIR, "capture.err"), "w"))
    time.sleep(2)
    if capture.poll() is not None:
        print(f"  (capture could not start on '{iface}'; see {os.path.join(LOG_DIR, 'capture.err')}. Continuing without it)")
        capture = None
    else:
        print(f"  packet capture running on '{iface}' -> {pcap}")


def stop_capture() -> str | None:
    global capture
    if capture is None:
        return None
    capture.terminate()
    try:
        capture.wait(timeout=10)
    except subprocess.TimeoutExpired:
        capture.kill()
    capture = None
    return pcap if os.path.exists(pcap) else None


def show_packets() -> None:
    path = stop_capture()
    tshark = shutil.which("tshark") or (r"C:\Program Files\Wireshark\tshark.exe" if sys.platform.startswith("win") else None)
    if not path or not tshark:
        print("  no capture to show.")
        return
    print("  captured Modbus writes (source, destination port, function code, register):")
    subprocess.run([tshark, "-r", path, "-n", "-o", "mbtcp.tcp.port:5020,5021", "-Y", "mbtcp", "-T", "fields",
                    "-e", "frame.number", "-e", "ip.src", "-e", "tcp.dstport", "-e", "modbus.func_code", "-e", "modbus.reference_num"])
    print("  (the capture is now stopped; port 5021 = to the middleware, port 5020 = middleware to PLC)")


def open_panel(env: dict) -> None:
    """Start the button panel once, pointed at THIS computer (an empty lab file, so config/lab.env's real addresses are not used)."""
    if "panel" in procs and procs["panel"].poll() is None:
        print("  the panel is already running: http://127.0.0.1:5070")
        return
    # IM_LAB_ENV = a file that does not exist -> the launcher falls back to loopback; HMAC_SECRET = this run's secret, so the
    # launcher finds one (it only reads the secret from lab.env or from here) and does not print its "secret not set" warning.
    penv = dict(env, IM_LAB_ENV=os.path.join(LOG_DIR, "no_lab.env"), HMAC_SECRET=env["IM_HMAC_SECRET"])
    log = open(os.path.join(LOG_DIR, "panel.log"), "w")
    procs["panel"] = subprocess.Popen([sys.executable, "-m", "attacker.control_panel"], cwd=ROOT, env=penv,
                                      stdout=log, stderr=subprocess.STDOUT)
    print("  attack panel: http://127.0.0.1:5070 (opening in your browser)")


def run_attack(argv: list, env: dict) -> None:
    print(f"\n>>> attack: {' '.join(argv)}")
    subprocess.run([sys.executable, "-m", "attacker.attacker", *argv], cwd=ROOT, env=env)


def stop_all() -> None:
    stop_capture()
    for name in reversed(list(procs)):
        p = procs[name]
        if p.poll() is None:
            p.terminate()
    for p in procs.values():
        try:
            p.wait(timeout=8)
        except subprocess.TimeoutExpired:
            p.kill()


def menu(env: dict) -> None:
    started = time.time()
    while True:
        warm = max(0, 120 - int(time.time() - started))
        print("\n=== ONE-PC DEMO ===  dashboard: http://127.0.0.1:5050"
              + (f"   (model warming up, ~{warm}s left)" if warm else "   (model warmed up)"))
        for i, (label, _) in enumerate(ATTACKS, 1):
            print(f"  {i:2d}  {label}")
        print("   A  run ALL attacks, one after another")
        print("   R  restore the plant (SCADA --restore)")
        print("   B  open the attack BUTTON panel in the browser (http://127.0.0.1:5070)")
        print("   P  stop the capture and show the packets")
        print("   Q  quit and stop everything")
        choice = input("Choose: ").strip().upper()
        if choice == "Q":
            return
        if choice == "A":
            for _, argv in ATTACKS:
                run_attack(argv, env)
                time.sleep(5)
        elif choice == "R":
            subprocess.run([sys.executable, "-m", "scada.scada", "--restore"], cwd=ROOT, env=env)
        elif choice == "B":
            open_panel(env)
        elif choice == "P":
            show_packets()
        elif choice.isdigit() and 1 <= int(choice) <= len(ATTACKS):
            run_attack(ATTACKS[int(choice) - 1][1], env)
        else:
            print("Not a valid choice.")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--no-capture", action="store_true")
    args = ap.parse_args()

    os.makedirs(LOG_DIR, exist_ok=True)
    env = dict(os.environ)
    for k in [k for k in env if k.startswith("IM_") and k not in ("IM_LOG_DIR",)]:
        del env[k]                                 # an old lab setting must not leak into the loopback run
    env["IM_HMAC_SECRET"] = secrets.token_hex(24)  # one secret for this run, shared by all children

    busy = [p for p in (5020, 5021, 5050) if port_open(p)]
    if busy:
        print(f"Ports {busy} are already in use here - stop the other copy of the system first.")
        return 2

    print("Starting the whole system on this computer (loopback)...")
    try:
        if not args.no_capture:
            start_capture(env)
        for name, argv, port in SERVICES:
            start(name, argv, env)
            if port is not None:
                if not wait_port(name, port):
                    print(f"  {name} FAILED to start - see {os.path.join(LOG_DIR, name + '.log')}")
                    return 1
            else:
                time.sleep(3)
            print(f"  {name}: running")
        if not args.no_browser:
            webbrowser.open("http://127.0.0.1:5050")
        menu(env)
    except (KeyboardInterrupt, EOFError):
        print()
    finally:
        print("Stopping everything...")
        stop_all()
        print(f"Logs: {LOG_DIR}")
        if os.path.exists(pcap):
            print(f"Packet capture: {pcap}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
