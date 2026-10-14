"""
tools/check_topology.py - per-laptop preflight for the multi-laptop demo (docs/topology.md).

    python -m tools.check_topology --role plc|middleware|dashboard|scada|attacker [--multi]

Run it on each laptop BEFORE the demo, in the order PLC -> middleware -> dashboard -> scada/attacker. It reads the same
settings the components read (docs/netconfig.py) and checks, for the role you give it:
  * the settings this role needs are not left at their loopback defaults (--multi: the laptops are different machines)
  * the ports this role must serve are free to bind (or already served by you)
  * the peers this role must reach accept a TCP connection
  * the HMAC secret fingerprint (compare the 8 hex digits across laptops: they must be IDENTICAL; the secret is not shown)
  * tshark is installed (informational)
Exit code 0 = all required checks passed.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import socket
import sys
from typing import Callable, List, Tuple

from docs import hmac_auth, netconfig

Check = Tuple[str, str, str]        # (status OK/FAIL/WARN/INFO, name, detail)


def can_connect(host: str, port: int, timeout: float = 2.0) -> Tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, "connected"
    except OSError as e:
        return False, str(e)


def can_bind(host: str, port: int) -> Tuple[bool, str]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((host, port))
        return True, "free"
    except OSError as e:
        return False, str(e)
    finally:
        s.close()


def secret_fingerprint() -> str:
    return hashlib.sha256(b"IM-fp|" + hmac_auth.get_secret()).hexdigest()[:8]


def _loopback(h: str) -> bool:
    return h in (netconfig.LOOPBACK, "localhost")


def run_checks(role: str, multi: bool, connect: Callable = can_connect, bind: Callable = can_bind) -> List[Check]:
    out: List[Check] = []
    add = lambda st, n, d="": out.append((st, n, d))

    def need_remote(name: str, value: str) -> None:
        if multi and _loopback(value):
            add("FAIL", f"{name} is set", f"still the loopback default ({value}); set it to the other laptop's address")
        else:
            add("OK", f"{name} is set", value)

    def reach(label: str, host: str, port: int, required: bool = True) -> None:
        ok, d = connect(host, port)
        add("OK" if ok else ("FAIL" if required else "WARN"), f"can reach {label} at {host}:{port}", d)

    def serve(label: str, host: str, port: int) -> None:
        ok, d = bind(host, port)
        if ok:
            add("OK", f"{label} port {port} is free to bind on {host}", d)
        else:
            add("WARN", f"{label} port {port} is not bindable on {host}", f"{d} (fine if {label} is already running here)")

    if role == "plc":
        serve("PLC", netconfig.PLC_LISTEN_HOST, netconfig.PLC_LISTEN_PORT)
    elif role == "middleware":
        serve("middleware", netconfig.LISTEN_HOST, netconfig.LISTEN_PORT)
        need_remote("IM_PLC_HOST", netconfig.PLC_HOST)
        reach("the PLC", netconfig.PLC_HOST, netconfig.PLC_PORT)
        reach("the dashboard", netconfig.DASHBOARD_HOST, netconfig.DASHBOARD_PORT, required=False)
        add("INFO", "trusted SCADA sources (IM_TRUSTED_SOURCES)", netconfig.TRUSTED_SOURCES)
        if multi and _loopback(netconfig.TRUSTED_SOURCES):
            add("FAIL", "IM_TRUSTED_SOURCES lists the SCADA laptop", "still loopback only: every remote command would be UNTRUSTED_SOURCE")
    elif role == "dashboard":
        serve("dashboard", netconfig.DASHBOARD_BIND_HOST, netconfig.DASHBOARD_PORT)
        add("INFO", "dashboard bind host (IM_DASHBOARD_BIND_HOST)", netconfig.DASHBOARD_BIND_HOST)
    elif role in ("scada", "attacker"):
        need_remote("IM_MIDDLEWARE_HOST", netconfig.MIDDLEWARE_HOST)
        reach("the middleware", netconfig.MIDDLEWARE_HOST, netconfig.MIDDLEWARE_PORT)
        if role == "attacker":
            add("INFO", "IM_PLC_HOST (only the false-injection attack talks to the PLC directly)", netconfig.PLC_HOST)
            reach("the PLC (false-injection only)", netconfig.PLC_HOST, netconfig.PLC_PORT, required=False)
    else:
        raise ValueError(role)

    if role in ("middleware", "scada", "attacker"):
        try:
            add("INFO", "HMAC secret fingerprint (must match on SCADA, middleware, attacker)", secret_fingerprint())
        except Exception as e:                       # SecretError: too short, unreadable file...
            add("FAIL", "HMAC secret", str(e))
    add("INFO" if shutil.which("tshark") else "WARN", "tshark on PATH", shutil.which("tshark") or "not found (only needed on the capture laptops)")
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Per-laptop preflight for the multi-laptop demo.")
    ap.add_argument("--role", required=True, choices=["plc", "middleware", "dashboard", "scada", "attacker"])
    ap.add_argument("--multi", action="store_true", help="the laptops are different machines: loopback settings are errors")
    a = ap.parse_args()
    res = run_checks(a.role, a.multi)
    for st, name, detail in res:
        print(f"  [{st:<4}] {name}" + (f"  ({detail})" if detail else ""))
    failed = [r for r in res if r[0] == "FAIL"]
    print(f"\nrole={a.role}: " + ("READY" if not failed else f"{len(failed)} blocking problem(s)"))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
