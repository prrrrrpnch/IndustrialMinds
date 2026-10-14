"""
docs/netconfig.py - the ONE place where hosts and ports are resolved.

Every component (PLC, middleware, dashboard, SCADA, attacker, orchestrator)
reads its addresses from here, so the system can be spread over several
machines with environment variables or CLI flags and no code edits.

LOOPBACK below is the documented single-machine default; it is the only
place a literal address is allowed.

Environment variables (all optional):

  IM_PLC_HOST / IM_PLC_PORT                 where the middleware (and attacker) reach the PLC
  IM_PLC_LISTEN_HOST / IM_PLC_LISTEN_PORT   what the PLC binds to
  IM_MIDDLEWARE_HOST / IM_MIDDLEWARE_PORT   where SCADA/attacker reach the middleware
  IM_LISTEN_HOST / IM_LISTEN_PORT           what the middleware binds to
  IM_DASHBOARD_HOST / IM_DASHBOARD_PORT     where the middleware reaches the dashboard
  IM_DASHBOARD_URL                          full URL override for the line above
  IM_DASHBOARD_BIND_HOST                    what the dashboard binds to
  IM_TRUSTED_SOURCES                        cyber-agent SCADA whitelist (IPs/CIDRs)

CLI flags on each entry point override the environment.
"""

from __future__ import annotations

import os

LOOPBACK = "127.0.0.1"      # documented single-machine default
ALL_INTERFACES = "0.0.0.0"  # bind-all default for servers


def _env_str(name: str, default: str) -> str:
    return os.environ.get(name, "").strip() or default


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        raise SystemExit(f"{name} must be an integer, got {raw!r}")


# Client side: where to find the peers.
PLC_HOST = _env_str("IM_PLC_HOST", LOOPBACK)
PLC_PORT = _env_int("IM_PLC_PORT", 5020)
MIDDLEWARE_HOST = _env_str("IM_MIDDLEWARE_HOST", LOOPBACK)
MIDDLEWARE_PORT = _env_int("IM_MIDDLEWARE_PORT", 5021)
DASHBOARD_HOST = _env_str("IM_DASHBOARD_HOST", LOOPBACK)
DASHBOARD_PORT = _env_int("IM_DASHBOARD_PORT", 5050)
DASHBOARD_URL = _env_str("IM_DASHBOARD_URL", f"http://{DASHBOARD_HOST}:{DASHBOARD_PORT}")

# Server side: what each process binds to.
PLC_LISTEN_HOST = _env_str("IM_PLC_LISTEN_HOST", ALL_INTERFACES)
PLC_LISTEN_PORT = _env_int("IM_PLC_LISTEN_PORT", PLC_PORT)
LISTEN_HOST = _env_str("IM_LISTEN_HOST", ALL_INTERFACES)
LISTEN_PORT = _env_int("IM_LISTEN_PORT", MIDDLEWARE_PORT)
DASHBOARD_BIND_HOST = _env_str("IM_DASHBOARD_BIND_HOST", LOOPBACK)

# Cyber-agent SCADA whitelist. Default: this machine only. Add the SCADA
# laptop's address (or CIDR) via IM_TRUSTED_SOURCES for multi-laptop runs.
TRUSTED_SOURCES = _env_str("IM_TRUSTED_SOURCES", LOOPBACK)
