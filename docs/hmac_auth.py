"""
docs/hmac_auth.py - HMAC-SHA256 authentication for SCADA -> Middleware commands.

Shared by the signer (SCADA) and the verifier (middleware Cyber Agent).

Secret handling
---------------
The shared secret is loaded, in order, from:
  1. IM_HMAC_SECRET       environment variable (>= 32 characters)
  2. IM_HMAC_SECRET_FILE  environment variable pointing at a key file
  3. <project>/config/hmac_secret.key  (auto-generated on first use, mode 0600,
     git-ignored)
The secret is never printed, logged, returned by an API or sent to the
dashboard.

Canonical serialization
-----------------------
The MAC covers a fixed-width, big-endian binary encoding of every field that
determines what the PLC will do, prefixed with a domain-separation tag:

    b"IM-CMD-v1|" + struct.pack(">BHHQQ", version, register, raw_value,
                                         nonce, timestamp_ms)

Fixed-width binary has exactly one encoding per command, so there is no
whitespace/ordering/number-format ambiguity. Tags are compared with
hmac.compare_digest (constant time).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
import hmac
import hashlib
import os
import secrets
import struct
import threading
import time

from docs.interfaces import FRAME_BASE, FRAME_LEN, FRAME_VERSION, to_raw

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_SECRET_FILE = os.path.join(PROJECT_ROOT, "config", "hmac_secret.key")

DOMAIN_TAG = b"IM-CMD-v1|"
MAC_LEN = 32
MIN_SECRET_LEN = 32

# Accepted clock skew / freshness window for signed commands.
MAX_CLOCK_SKEW_MS = int(float(os.environ.get("IM_HMAC_MAX_SKEW_SECONDS", "30")) * 1000)

_secret_cache = None
_secret_lock = threading.Lock()


class SecretError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Secret loading
# ---------------------------------------------------------------------------

def _load_secret_uncached() -> bytes:
    env_secret = os.environ.get("IM_HMAC_SECRET")
    if env_secret:
        if len(env_secret) < MIN_SECRET_LEN:
            raise SecretError(
                f"IM_HMAC_SECRET must be at least {MIN_SECRET_LEN} characters"
            )
        return env_secret.encode("utf-8")

    path = os.environ.get("IM_HMAC_SECRET_FILE", DEFAULT_SECRET_FILE)

    if not os.path.exists(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        key = secrets.token_hex(32)
        # O_EXCL: if two processes race, only one creates the file.
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(key)
        except FileExistsError:
            pass

    with open(path, "r", encoding="utf-8") as fh:
        secret = fh.read().strip()

    if len(secret) < MIN_SECRET_LEN:
        raise SecretError(f"HMAC secret in {path} is shorter than {MIN_SECRET_LEN} characters")

    return secret.encode("utf-8")


def get_secret() -> bytes:
    global _secret_cache
    with _secret_lock:
        if _secret_cache is None:
            _secret_cache = _load_secret_uncached()
        return _secret_cache


# ---------------------------------------------------------------------------
# Per-device key registry (opt-in; closes the single-shared-key weakness)
# ---------------------------------------------------------------------------
# Default: no registry -> every source is verified with the one shared secret
# (get_secret), exactly as before. When a registry is configured, each source
# identity (its address) is verified with ITS OWN key, so a key stolen from one
# device cannot be used from another address, and a device's key can be revoked
# on its own. The verifier (middleware) holds the registry; each signer (SCADA)
# holds only its own key as IM_HMAC_SECRET.
#
# Configure on the MIDDLEWARE with either:
#   IM_HMAC_KEYS="<scada-addr>=<scada-key>,<hmi-addr>=<hmi-key>"   (addr=key, comma-separated)
#   IM_HMAC_KEYS_FILE=/path/to/keys.json                          ({"<scada-addr>": "<scada-key>", ...})
# Each key must be at least MIN_SECRET_LEN characters.

_registry_cache: Optional[Dict[str, bytes]] = None


def _load_key_registry_uncached() -> Dict[str, bytes]:
    out: Dict[str, bytes] = {}
    path = os.environ.get("IM_HMAC_KEYS_FILE")
    if path:
        import json
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        for ident, key in raw.items():
            out[str(ident).strip()] = _check_key(str(key), ident)
    spec = os.environ.get("IM_HMAC_KEYS", "")
    for item in spec.split(","):
        item = item.strip()
        if not item or "=" not in item:
            continue
        ident, key = item.split("=", 1)
        out[ident.strip()] = _check_key(key.strip(), ident.strip())
    return out


def _check_key(key: str, ident: object) -> bytes:
    if len(key) < MIN_SECRET_LEN:
        raise SecretError(f"per-device key for {ident!r} is shorter than {MIN_SECRET_LEN} characters")
    return key.encode("utf-8")


def _registry() -> Dict[str, bytes]:
    global _registry_cache
    with _secret_lock:
        if _registry_cache is None:
            _registry_cache = _load_key_registry_uncached()
        return _registry_cache


def has_key_registry() -> bool:
    """True when a per-device key registry is configured (per-device mode)."""
    return bool(_registry())


def key_for_source(identity: object) -> Optional[bytes]:
    """The key registered for this source identity, or None if it is not registered.
    When no registry is configured, returns the single shared secret (shared mode)."""
    reg = _registry()
    if not reg:
        return get_secret()
    return reg.get(str(identity))


def reset_secret_cache() -> None:
    """Tests only: force the secret and the key registry to be re-read."""
    global _secret_cache, _registry_cache
    with _secret_lock:
        _secret_cache = None
        _registry_cache = None


# ---------------------------------------------------------------------------
# Canonical message + MAC
# ---------------------------------------------------------------------------

def canonical_message(version: int, register: int, raw_value: int,
                      nonce: int, timestamp_ms: int) -> bytes:
    return DOMAIN_TAG + struct.pack(
        ">BHHQQ", version, register, raw_value, nonce, timestamp_ms
    )


def compute_mac(version: int, register: int, raw_value: int, nonce: int, timestamp_ms: int,
                key: Optional[bytes] = None) -> bytes:
    key = get_secret() if key is None else key
    msg = canonical_message(version, register, raw_value, nonce, timestamp_ms)
    return hmac.new(key, msg, hashlib.sha256).digest()


# ---------------------------------------------------------------------------
# 16-bit register packing helpers
# ---------------------------------------------------------------------------

def _u64_to_regs(v: int) -> list:
    return list(struct.unpack(">4H", struct.pack(">Q", v)))


def _regs_to_u64(regs: List[int]) -> int:
    return struct.unpack(">Q", struct.pack(">4H", *regs))[0]


def _bytes_to_regs(b: bytes) -> list:
    return list(struct.unpack(f">{len(b) // 2}H", b))


def _regs_to_bytes(regs: List[int]) -> bytes:
    return struct.pack(f">{len(regs)}H", *regs)


# ---------------------------------------------------------------------------
# Frame build / parse
# ---------------------------------------------------------------------------

def build_frame(register: int, value: float, key: Optional[bytes] = None, nonce: Optional[int] = None,
                timestamp_ms: Optional[int] = None) -> List[int]:
    """Returns the FC16 register list for a signed command."""
    raw = to_raw(value)
    nonce = secrets.randbits(64) if nonce is None else nonce
    timestamp_ms = int(time.time() * 1000) if timestamp_ms is None else timestamp_ms
    mac = compute_mac(FRAME_VERSION, register, raw, nonce, timestamp_ms, key=key)
    return (
        [FRAME_VERSION, register, raw]
        + _u64_to_regs(nonce)
        + _u64_to_regs(timestamp_ms)
        + _bytes_to_regs(mac)
    )


def parse_frame(values: List[int]) -> Dict[str, Any]:
    """Parses a received frame WITHOUT verifying it.

    Returns {"register", "raw_value", "auth"}; auth["malformed"] is True when
    the frame has the wrong length or version.
    """
    values = list(values)
    if len(values) != FRAME_LEN:
        return {
            "register": values[1] if len(values) > 1 else None,
            "raw_value": values[2] if len(values) > 2 else None,
            "auth": {"malformed": True, "detail": f"frame length {len(values)} != {FRAME_LEN}"},
        }

    version = values[0]
    auth = {
        "malformed": version != FRAME_VERSION,
        "detail": "" if version == FRAME_VERSION else f"unsupported frame version {version}",
        "version": version,
        "nonce": _regs_to_u64(values[3:7]),
        "timestamp_ms": _regs_to_u64(values[7:11]),
        "mac": _regs_to_bytes(values[11:27]),
    }
    return {"register": values[1], "raw_value": values[2], "auth": auth}


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify(register: Optional[int], raw_value: Optional[int], auth: Optional[Dict[str, Any]],
           now_ms: Optional[int] = None, key: Optional[bytes] = None) -> Tuple[bool, str, str]:
    """Verifies a parsed frame.

    Returns (ok, reason_code, detail). reason_code is one of
    HMAC_OK, HMAC_MISSING, HMAC_MALFORMED, HMAC_INVALID, HMAC_EXPIRED.
    The MAC is checked BEFORE the timestamp so freshness decisions are only
    made on authenticated data. `key` selects the verifying key (per-device
    mode); None uses the single shared secret (shared mode).
    """
    if not auth:
        return False, "HMAC_MISSING", "command carried no HMAC signature"

    if auth.get("malformed"):
        return False, "HMAC_MALFORMED", auth.get("detail", "malformed signed frame")

    try:
        expected = compute_mac(
            auth["version"], int(register), int(raw_value),
            int(auth["nonce"]), int(auth["timestamp_ms"]),
            key=key,
        )
    except (KeyError, TypeError, ValueError, struct.error):
        return False, "HMAC_MALFORMED", "frame fields out of range"

    received = auth.get("mac", b"")
    if not isinstance(received, (bytes, bytearray)) or len(received) != MAC_LEN:
        return False, "HMAC_MALFORMED", "HMAC tag has wrong length"

    if not hmac.compare_digest(expected, bytes(received)):
        return False, "HMAC_INVALID", "HMAC tag does not match command (tampered or wrong key)"

    now_ms = int(time.time() * 1000) if now_ms is None else now_ms
    if abs(now_ms - int(auth["timestamp_ms"])) > MAX_CLOCK_SKEW_MS:
        return False, "HMAC_EXPIRED", (
            f"signed timestamp outside +/-{MAX_CLOCK_SKEW_MS // 1000}s freshness window"
        )

    return True, "HMAC_OK", "signature valid"


def frame_address() -> int:
    return FRAME_BASE
