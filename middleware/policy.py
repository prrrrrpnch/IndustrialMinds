"""
middleware/policy.py - policy-as-code: WHO may write WHICH register, and how far (rule-based, deterministic).

HMAC proves a command came from a device holding a key. It says nothing about what that device is ALLOWED to do. This module adds
that: a source (its real socket peer address) is mapped to a role, and the role limits the registers it may write and the value
range it may write. A compromised-but-authentic device therefore cannot reach beyond its job.

Policy file: JSON, path from env IM_POLICY_FILE (default config/policy.json). NO file = no policy = every authenticated source may
write every actuator (the unchanged demo behaviour). Example (see config/policy.example.json):

    {
      "default_role": "deny",
      "roles": {
        "operator": {"write": ["MV101", "P101", "P203", "P205"], "limits": {"P101": [20, 90]}},
        "engineer": {"write": "*"},
        "observer": {"write": []}
      },
      "sources": {"127.0.0.1": "operator"}
    }

  default_role   role of a source not listed in "sources" ("deny" = no writes; "allow"/absent = unrestricted)
  roles[r].write register tags or numbers the role may write, or "*"
  roles[r].limits  optional tag -> [min, max] tighter than the plant's own bounds (the physical agent still enforces those)
  sources        peer address -> role name

Reads (function code 3) are never restricted here. A malformed policy file FAILS CLOSED for writes (every write is refused with
POLICY_ERROR) so a typo cannot silently open the plant; fix the file and it reloads within IM_POLICY_RELOAD_S (default 2).
"""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Any, Dict, Optional, Tuple

from docs.interfaces import MACHINE_BY_NAME, MACHINE_BY_REGISTER

ROOT = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
DEFAULT_FILE = os.path.join(ROOT, "config", "policy.json")
WRITE_FUNCTION_CODES = {6, 16}

_lock = threading.Lock()
_state: Dict[str, Any] = {"path": None, "mtime": None, "checked": 0.0, "policy": None, "error": None}


def _path() -> str:
    return os.environ.get("IM_POLICY_FILE", "").strip() or DEFAULT_FILE


def _register_of(item: Any) -> int:
    if isinstance(item, bool):
        raise ValueError(f"bad register {item!r}")
    if isinstance(item, int):
        if item not in MACHINE_BY_REGISTER:
            raise ValueError(f"unknown register {item}")
        return item
    if isinstance(item, str) and item in MACHINE_BY_NAME:
        return MACHINE_BY_NAME[item]["register"]
    raise ValueError(f"unknown register {item!r}")


def parse(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Validate a policy document and compile it. Raises ValueError with a readable message."""
    if not isinstance(doc, dict):
        raise ValueError("policy must be a JSON object")
    roles: Dict[str, Dict[str, Any]] = {}
    for name, r in (doc.get("roles") or {}).items():
        if not isinstance(r, dict):
            raise ValueError(f"role {name!r} must be an object")
        w = r.get("write", [])
        regs = "*" if w == "*" else {_register_of(x) for x in w}
        limits: Dict[int, Tuple[float, float]] = {}
        for tag, lim in (r.get("limits") or {}).items():
            reg = _register_of(tag)
            if not (isinstance(lim, (list, tuple)) and len(lim) == 2 and lim[0] <= lim[1]):
                raise ValueError(f"limits for {tag} must be [min, max]")
            limits[reg] = (float(lim[0]), float(lim[1]))
        roles[name] = {"write": regs, "limits": limits}
    default = doc.get("default_role", "allow")
    if default not in ("allow", "deny") and default not in roles:
        raise ValueError(f"default_role {default!r} is not allow/deny or a defined role")
    sources = dict(doc.get("sources") or {})
    for src, role in sources.items():
        if role not in roles:
            raise ValueError(f"source {src} uses undefined role {role!r}")
    return {"roles": roles, "default": default, "sources": {str(k): v for k, v in sources.items()}}


def _load() -> None:
    path = _path()
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        _state.update(path=path, mtime=None, policy=None, error=None)        # no file: no policy
        return
    if _state["path"] == path and _state["mtime"] == mtime:
        return
    try:
        with open(path, "r", encoding="utf-8") as fh:
            _state.update(policy=parse(json.load(fh)), error=None)
    except Exception as exc:                                                  # fail closed for writes
        _state.update(policy=None, error=f"{type(exc).__name__}: {exc}")
    _state.update(path=path, mtime=mtime)


def _current() -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    with _lock:
        now = time.monotonic()
        try:
            gap = float(os.environ.get("IM_POLICY_RELOAD_S", "2"))
        except ValueError:
            gap = 2.0
        if _state["path"] != _path() or now - _state["checked"] >= gap:
            _state["checked"] = now
            _load()
        return _state["policy"], _state["error"]


def role_of(source_ip: str, policy: Dict[str, Any]) -> Optional[str]:
    """Role name for a source, None = unrestricted."""
    role = policy["sources"].get(str(source_ip))
    if role is None:
        role = policy["default"]
    return None if role == "allow" else role


def authorize(source_ip: str, function_code: Optional[int], register: Optional[int], value: Optional[float]
              ) -> Tuple[bool, str]:
    """(allowed, reason). reason is 'OK' or a UNAUTHORIZED_* / POLICY_ERROR code with detail."""
    if function_code not in WRITE_FUNCTION_CODES:
        return True, "OK"
    policy, error = _current()
    if error is not None:
        return False, f"POLICY_ERROR:{error}"
    if policy is None:
        return True, "OK"
    role = role_of(source_ip, policy)
    if role is None:
        return True, "OK"
    name = MACHINE_BY_REGISTER.get(register, {}).get("name", f"#{register}")
    if role == "deny":
        return False, f"UNAUTHORIZED_SOURCE:{source_ip} has no role and may not write"
    spec = policy["roles"][role]
    if spec["write"] != "*" and register not in spec["write"]:
        return False, f"UNAUTHORIZED_REGISTER:role '{role}' may not write {name}"
    lim = spec["limits"].get(register)
    if lim is not None and value is not None and not (lim[0] <= float(value) <= lim[1]):
        return False, f"UNAUTHORIZED_VALUE:role '{role}' may write {name} only within [{lim[0]:g}, {lim[1]:g}], got {float(value):g}"
    return True, "OK"


def status() -> Dict[str, Any]:
    policy, error = _current()
    return {"file": _state["path"], "active": policy is not None, "error": error,
            "roles": sorted(policy["roles"]) if policy else [], "sources": dict(policy["sources"]) if policy else {}}


def reset() -> None:
    """Forget the loaded policy (tests)."""
    with _lock:
        _state.update(path=None, mtime=None, checked=0.0, policy=None, error=None)
