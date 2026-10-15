"""
tests/test_per_device_keys.py - per-device HMAC key registry (opt-in).

Closes the single-shared-key weakness: when IM_HMAC_KEYS is configured, each
source is verified with ITS OWN key, so a key stolen from one device cannot be
used from another address, and an unregistered source is rejected outright.
Default (no registry) stays single-shared-secret and is unaffected.

    python -m tests.test_per_device_keys
"""

from __future__ import annotations

import ipaddress
import os
import time

from docs import hmac_auth
from docs.interfaces import make_command
from middleware import cyber_agent

fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global fails
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    fails += 0 if cond else 1


MV101 = 0
KEY_A = "A" * 40          # device at 127.0.0.1
KEY_B = "B" * 40          # device at 127.0.0.2


def signed(src, key, ts=None, reg=MV101, value=45.0):
    ts = ts or time.time()
    parsed = hmac_auth.parse_frame(hmac_auth.build_frame(reg, value, key=key.encode(), timestamp_ms=int(ts * 1000)))
    return make_command(f"tx-{src}-{ts}", ts, src, 16, reg, value, raw_value=parsed["raw_value"], auth=parsed["auth"])


# Trust the whole loopback range so the whitelist is not what stops an unregistered source.
_saved_nets = cyber_agent._TRUSTED_NETWORKS
cyber_agent._TRUSTED_NETWORKS = [ipaddress.ip_network("127.0.0.0/8")]
os.environ["IM_HMAC_KEYS"] = f"127.0.0.1={KEY_A},127.0.0.2={KEY_B}"
hmac_auth.reset_secret_cache()

try:
    check("registry mode is active when IM_HMAC_KEYS is set", hmac_auth.has_key_registry())

    cyber_agent.reset_state()
    v = cyber_agent.check(signed("127.0.0.1", KEY_A))
    check("a registered device signing with ITS OWN key passes", v["pass"] and v["reason"] == "OK", v["reason"])

    cyber_agent.reset_state()
    v = cyber_agent.check(signed("127.0.0.2", KEY_B))
    check("a second registered device passes with its own key", v["pass"], v["reason"])

    cyber_agent.reset_state()
    v = cyber_agent.check(signed("127.0.0.1", KEY_B))   # device A's address, device B's key
    check("a registered device using the WRONG device's key is HMAC_INVALID",
          not v["pass"] and v["reason"].startswith("HMAC_INVALID"), v["reason"])

    cyber_agent.reset_state()
    v = cyber_agent.check(signed("127.0.0.9", KEY_A))   # trusted range, but not registered
    check("a source with no registered key is rejected UNKNOWN_DEVICE",
          not v["pass"] and v["reason"].startswith("UNKNOWN_DEVICE"), v["reason"])

    # The headline property: a key STOLEN from device A does not work from another address.
    cyber_agent.reset_state()
    v = cyber_agent.check(signed("127.0.0.9", KEY_A))
    check("a stolen key is useless from an unregistered address (per-device accountability)",
          not v["pass"] and v["reason"].startswith("UNKNOWN_DEVICE"), v["reason"])

finally:
    del os.environ["IM_HMAC_KEYS"]
    hmac_auth.reset_secret_cache()
    cyber_agent._TRUSTED_NETWORKS = _saved_nets
    cyber_agent.reset_state()

# Shared mode (no registry) is unchanged: one shared secret verifies every source.
os.environ["IM_HMAC_SECRET"] = "S" * 40
hmac_auth.reset_secret_cache()
check("no registry -> shared mode (has_key_registry False)", not hmac_auth.has_key_registry())
cyber_agent._TRUSTED_NETWORKS = [ipaddress.ip_network("127.0.0.0/8")]
try:
    cyber_agent.reset_state()
    v = cyber_agent.check(signed("127.0.0.1", "S" * 40))
    check("shared mode: a command signed with the shared secret passes", v["pass"], v["reason"])
finally:
    cyber_agent._TRUSTED_NETWORKS = _saved_nets
    cyber_agent.reset_state()

print("\nALL PASS" if fails == 0 else f"\n{fails} CHECK(S) FAILED")
raise SystemExit(1 if fails else 0)
