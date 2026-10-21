"""
tests/test_check_topology.py - Phase 10: the per-laptop preflight (tools/check_topology.py) with injected network probes.

    python -m tests.test_check_topology
"""

from __future__ import annotations

from tools.check_topology import run_checks

fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global fails
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    fails += 0 if cond else 1


up = lambda h, p, timeout=2.0: (True, "connected")
down = lambda h, p, timeout=2.0: (False, "refused")
free = lambda h, p: (True, "free")


def status(res, text):
    return next(s for s, n, _ in res if text in n)


check("middleware: reachable PLC passes", status(run_checks("middleware", False, up, free), "can reach the PLC") == "OK")
check("middleware: unreachable PLC blocks", status(run_checks("middleware", False, down, free), "can reach the PLC") == "FAIL")
check("middleware: unreachable dashboard only warns", status(run_checks("middleware", False, down, free), "dashboard") == "WARN")
check("--multi: loopback IM_PLC_HOST is an error on the middleware laptop", status(run_checks("middleware", True, up, free), "IM_PLC_HOST") == "FAIL")
check("--multi: loopback IM_MIDDLEWARE_HOST is an error on SCADA and attacker",
      all(status(run_checks(r, True, up, free), "IM_MIDDLEWARE_HOST") == "FAIL" for r in ("scada", "attacker")))
check("--multi: loopback-only IM_TRUSTED_SOURCES is an error on the middleware laptop", status(run_checks("middleware", True, up, free), "IM_TRUSTED_SOURCES lists") == "FAIL")
check("secret fingerprint is shown for signing roles and never the secret",
      all("fingerprint" in " ".join(n for _, n, _ in run_checks(r, False, up, free)) for r in ("scada", "middleware", "attacker")))
check("the dashboard role needs no peer", all(s != "FAIL" for s, _, _ in run_checks("dashboard", True, down, free)))

# AUDIT S1: the PLC refuses plant writes from anyone but the middleware, and learns who that is from IM_MIDDLEWARE_HOST.
# On a PLC laptop where that was never set the allow-list is loopback, so the REAL middleware would be refused. That is
# exactly the failure the preflight must catch before a demo.
import ipaddress  # noqa: E402
from core import netconfig  # noqa: E402
_saved = netconfig.PLC_ALLOWED_WRITERS
try:
    netconfig.PLC_ALLOWED_WRITERS = netconfig.LOOPBACK
    check("--multi: a PLC whose allow-list is still loopback is an ERROR (it would refuse the middleware)",
          status(run_checks("plc", True, down, free), "allow-list names the middleware") == "FAIL")
    check("...but on a single-laptop rehearsal (no --multi) it is fine",
          all(s != "FAIL" for s, _, _ in run_checks("plc", False, down, free)))
    netconfig.PLC_ALLOWED_WRITERS = str(ipaddress.IPv4Address(0x0A000007))      # a non-loopback address, built at run time
    check("--multi: a PLC told the middleware's address passes",
          all(s != "FAIL" for s, _, _ in run_checks("plc", True, down, free)))
    netconfig.PLC_ALLOWED_WRITERS = "any"
    check("--multi: an explicit 'any' is not flagged (the operator chose the unprotected demo)",
          all(s != "FAIL" for s, _, _ in run_checks("plc", True, down, free)))
finally:
    netconfig.PLC_ALLOWED_WRITERS = _saved

import os as _os  # noqa: E402
_root = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
check("run.sh tells the PLC laptop who the middleware is",
      'export IM_MIDDLEWARE_HOST="$MW_IP"' in open(_os.path.join(_root, "scripts", "run.sh")).read().split("dashboard)")[0])
check("run.ps1 tells the PLC laptop who the middleware is",
      "$env:IM_MIDDLEWARE_HOST = $MW_IP" in open(_os.path.join(_root, "scripts", "run.ps1")).read().split("    'dashboard' {")[0])
check("a busy port is a warning, not a failure", status(run_checks("plc", False, up, lambda h, p: (False, "in use")), "not bindable") == "WARN")

print("\nALL PASS" if fails == 0 else f"\n{fails} CHECK(S) FAILED")
raise SystemExit(1 if fails else 0)
