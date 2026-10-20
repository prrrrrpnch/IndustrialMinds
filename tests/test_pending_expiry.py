"""
tests/test_pending_expiry.py - a forwarded command that the PLC never settles to
is expired (so it stops being projected into the cross-register setpoints and the
dashboard stops showing it as forever-pending). Covers the hardening in
middleware/middleware_server._expire_pending_if_stale.

    python -m tests.test_pending_expiry
"""

from __future__ import annotations

import time

from core.interfaces import MACHINE_BY_NAME
import middleware.middleware_server as mw

fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global fails
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    fails += 0 if cond else 1


reg = MACHINE_BY_NAME["MV101"]["register"]
now = time.time()

# A fresh pending (just forwarded) must NOT be expired.
mw._pending_commands.clear()
mw._pending_commands[reg] = {"tx_id": "tx-fresh", "value": 55.0, "time": now}
expired = mw._expire_pending_if_stale(reg, mw._pending_commands[reg], reported=15.0, now=now + 1.0)
check("a just-forwarded command is NOT expired", expired is False and reg in mw._pending_commands)

# A pending older than the timeout, still not settled, IS expired.
old = now - (mw.PENDING_COMMAND_TIMEOUT_S + 5.0)
mw._pending_commands[reg] = {"tx_id": "tx-stale", "value": 55.0, "time": old}
before_settled = mw._register_settled_since.get(reg)
expired = mw._expire_pending_if_stale(reg, mw._pending_commands[reg], reported=15.0, now=now)
check("a stale, never-settled command IS expired (removed from pending)", expired is True and reg not in mw._pending_commands)
check("expiry refreshes the register's settled timestamp (rate-of-change baseline)",
      mw._register_settled_since.get(reg) == now and mw._register_settled_since.get(reg) != before_settled)

# Boundary: exactly at the timeout is not yet stale (strictly greater-than).
mw._pending_commands[reg] = {"tx_id": "tx-edge", "value": 55.0, "time": now - mw.PENDING_COMMAND_TIMEOUT_S}
expired = mw._expire_pending_if_stale(reg, mw._pending_commands[reg], reported=15.0, now=now)
check("a command exactly at the timeout is not yet expired", expired is False and reg in mw._pending_commands)

mw._pending_commands.clear()
print("\nALL PASS" if fails == 0 else f"\n{fails} CHECK(S) FAILED")
raise SystemExit(1 if fails else 0)
