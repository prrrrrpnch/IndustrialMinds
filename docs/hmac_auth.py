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


def reset_secret_cache() -> None:
    """Tests only: force the secret to be re-read."""
    global _secret_cache
    with _secret_lock:
        _secret_cache = None


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
           now_ms: Optional[int] = None) -> Tuple[bool, str, str]:
    """Verifies a parsed frame.

    Returns (ok, reason_code, detail). reason_code is one of
    HMAC_OK, HMAC_MISSING, HMAC_MALFORMED, HMAC_INVALID, HMAC_EXPIRED.
    The MAC is checked BEFORE the timestamp so freshness decisions are only
    made on authenticated data.
    """
    if not auth:
        return False, "HMAC_MISSING", "command carried no HMAC signature"

    if auth.get("malformed"):
        return False, "HMAC_MALFORMED", auth.get("detail", "malformed signed frame")

    try:
        expected = compute_mac(
            auth["version"], int(register), int(raw_value),
            int(auth["nonce"]), int(auth["timestamp_ms"]),
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
