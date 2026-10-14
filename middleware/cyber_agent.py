"""
Cyber Agent — checks traffic-level behavior of incoming Modbus commands.
Does NOT care what a value means physically — only how it arrived.

Check order (first failure wins):
  1. Source whitelist          UNTRUSTED_SOURCE        (real socket peer IP)
  2. Function code             INVALID_FUNCTION_CODE
  3. Register allow-list       INVALID_REGISTER
  4. Per-source rate limit     RATE_LIMIT_EXCEEDED     (cheap DoS guard before crypto)
  5. HMAC-SHA256 verification  HMAC_MISSING / HMAC_MALFORMED / HMAC_INVALID / HMAC_EXPIRED
  6. Replay                    REPLAY_DETECTED         (nonce reuse or duplicate payload)

A command is only trusted after step 5 succeeds.
"""

from __future__ import annotations

import ipaddress
import os
from typing import Any, Deque, Dict, List, Tuple, Union
import time
from collections import defaultdict, deque

from docs.interfaces import make_verdict, ALL_REGISTERS, to_raw
from docs import hmac_auth, netconfig

# ---- Configuration ----
RATE_LIMIT_PER_SEC = 5
RATE_WINDOW_SECONDS = 1.0
VALID_FUNCTION_CODES = {3, 6, 16}   # read holding regs, write single, write multiple
ALLOWED_REGISTERS = set(ALL_REGISTERS)
REPLAY_WINDOW_SECONDS = 2.0

# Trusted SCADA sources. Comma-separated IPs and/or CIDR blocks.
# Default (docs/netconfig.py): this machine only. For a SCADA on another laptop set
# IM_TRUSTED_SOURCES to its address / CIDR.
TRUSTED_SOURCES_ENV = netconfig.TRUSTED_SOURCES


def _parse_whitelist(spec: str) -> List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
    nets = []
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            pass
    return nets


_TRUSTED_NETWORKS = _parse_whitelist(TRUSTED_SOURCES_ENV)

# Kept for backwards compatibility / inspection.
SOURCE_WHITELIST = {str(n.network_address) for n in _TRUSTED_NETWORKS if n.num_addresses == 1}

# ---- Internal state ----
_request_timestamps = defaultdict(deque)   # source_ip -> timestamps
_recent_payloads = defaultdict(deque)      # source_ip -> (payload, timestamp)
_seen_nonces = {}                          # nonce -> first-seen time
_nonce_order = deque()                     # (time, nonce) in arrival order, for O(1) expiry
_NONCE_RETENTION_SECONDS = (hmac_auth.MAX_CLOCK_SKEW_MS / 1000.0) * 2 + 5

# Per-source state for sources that went quiet is dropped periodically, so
# traffic from many distinct (e.g. attacker) IPs cannot grow memory forever.
_SWEEP_INTERVAL_SECONDS = 10.0
_last_sweep = 0.0


def _sweep_idle_sources(now: float) -> None:
    global _last_sweep
    if now - _last_sweep < _SWEEP_INTERVAL_SECONDS:
        return
    _last_sweep = now
    horizon = max(RATE_WINDOW_SECONDS, REPLAY_WINDOW_SECONDS)
    for table in (_request_timestamps, _recent_payloads):
        for src in [s for s, dq in table.items() if not dq or now - _last_time(dq) > horizon]:
            del table[src]


def _last_time(dq: Deque[Any]) -> float:
    last = dq[-1]
    return last[1] if isinstance(last, tuple) else last


def is_trusted_source(source_ip: object) -> bool:
    try:
        addr = ipaddress.ip_address(str(source_ip))
    except ValueError:
        return False
    if getattr(addr, "ipv4_mapped", None):
        addr = addr.ipv4_mapped
    return any(addr in net for net in _TRUSTED_NETWORKS)


def _check_rate(source_ip: str, now: float) -> bool:
    dq = _request_timestamps[source_ip]
    dq.append(now)
    while dq and now - dq[0] > RATE_WINDOW_SECONDS:
        dq.popleft()
    return len(dq) <= RATE_LIMIT_PER_SEC


def _check_replay(command: Dict[str, Any], now: float) -> bool:
    source_ip = command["source_ip"]
    payload_key = (command["function_code"], command["register"], command["value"])
    dq = _recent_payloads[source_ip]
    while dq and now - dq[0][1] > REPLAY_WINDOW_SECONDS:
        dq.popleft()
    is_replay = any(p == payload_key for p, _ in dq)
    dq.append((payload_key, now))
    return not is_replay


def _check_nonce(auth: Dict[str, Any], now: float) -> bool:
    """Authenticated nonce must never be seen twice inside the freshness window."""
    # Expire from the oldest end only - amortised O(1) per command.
    while _nonce_order and now - _nonce_order[0][0] > _NONCE_RETENTION_SECONDS:
        _, old = _nonce_order.popleft()
        _seen_nonces.pop(old, None)
    nonce = auth.get("nonce")
    if nonce in _seen_nonces:
        return False
    _seen_nonces[nonce] = now
    _nonce_order.append((now, nonce))
    return True


def check(command: Dict[str, Any]) -> Dict[str, Any]:
    """Evaluate a command dict (see make_command) against cyber-level rules."""
    now = command.get("timestamp", time.time())
    source_ip = command.get("source_ip", "")
    tx_id = command.get("tx_id", "")

    _sweep_idle_sources(now)

    if not is_trusted_source(source_ip):
        return make_verdict(tx_id, False, "UNTRUSTED_SOURCE", "cyber")

    if command.get("function_code") not in VALID_FUNCTION_CODES:
        return make_verdict(tx_id, False, "INVALID_FUNCTION_CODE", "cyber")

    if command.get("register") not in ALLOWED_REGISTERS:
        return make_verdict(tx_id, False, "INVALID_REGISTER", "cyber")

    if not _check_rate(source_ip, now):
        return make_verdict(tx_id, False, "RATE_LIMIT_EXCEEDED", "cyber")

    # ---- HMAC-SHA256: nothing below this line runs on untrusted data ----
    raw_value = command.get("raw_value")
    if raw_value is None and command.get("value") is not None:
        raw_value = to_raw(command["value"])

    auth = command.get("auth")
    ok, code, detail = hmac_auth.verify(
        command.get("register"), raw_value, auth, now_ms=int(now * 1000)
    )
    if not ok:
        verdict = make_verdict(tx_id, False, f"{code}:{detail}", "cyber")
        verdict["auth_status"] = code
        return verdict

    if not _check_nonce(auth, now):
        verdict = make_verdict(tx_id, False, "REPLAY_DETECTED:nonce reused", "cyber")
        verdict["auth_status"] = code
        return verdict

    if not _check_replay(command, now):
        verdict = make_verdict(tx_id, False, "REPLAY_DETECTED", "cyber")
        verdict["auth_status"] = code
        return verdict

    verdict = make_verdict(tx_id, True, "OK", "cyber")
    verdict["auth_status"] = code
    return verdict


def reset_state() -> None:
    """Clears rate/replay tracking — call this between test runs."""
    _request_timestamps.clear()
    _recent_payloads.clear()
    _seen_nonces.clear()
    _nonce_order.clear()
    global _last_sweep
    _last_sweep = 0.0
