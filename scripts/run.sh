#!/usr/bin/env bash
# IndustrialMind launcher (macOS / Linux) — one command per role.
#
#   ./scripts/run.sh dashboard         # Mac A, terminal 1
#   ./scripts/run.sh middleware        # Mac A, terminal 2
#   ./scripts/run.sh scada             # Mac B
#   ./scripts/run.sh scada --restore   # Mac B, operator recovery (extra args pass through)
#   ./scripts/run.sh plc               # (if a Mac were the PLC; normally Windows A runs it)
#   ./scripts/run.sh attacker hmac-tamper        # extra args pass straight to attacker.py
#
# Reads config/lab.env (copy it from config/lab.env.example first). Every
# address and the shared secret come from there; nothing is hard-coded.
set -euo pipefail

ROLE="${1:-}"
shift || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# IM_LAB_ENV points the launcher at a different file (used by tools/verify_three_laptops.py to rehearse a lab without touching
# the real config/lab.env). Unset, it is config/lab.env, exactly as before.
ENV_FILE="${IM_LAB_ENV:-config/lab.env}"
if [[ -f "$ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    set -a; source "$ENV_FILE"; set +a
fi

PY="python3"; command -v python3 >/dev/null 2>&1 || PY="python"

# Loopback fallbacks so a single-laptop rehearsal works with a blank lab.env.
: "${MW_IP:=127.0.0.1}"
: "${PLC_IP:=127.0.0.1}"
: "${SCADA_IP:=127.0.0.1}"
: "${ATTACKER_IP:=127.0.0.1}"
: "${DASHBOARD_BIND_HOST:=127.0.0.1}"
: "${DASHBOARD_TOKEN:=}"

# The dashboard refuses to start on a network address without a token, so pass it through to both ends that need it.
dash_token() {
    if [[ -n "$DASHBOARD_TOKEN" ]]; then
        export IM_DASHBOARD_TOKEN="$DASHBOARD_TOKEN"
    fi
}

need_secret() {
    if [[ -z "${HMAC_SECRET:-}" ]]; then
        echo "WARNING: HMAC_SECRET is not set in $ENV_FILE." >&2
        echo "         SCADA, middleware and attacker must share one secret, or every" >&2
        echo "         command will be rejected as HMAC_INVALID. Generate one with:" >&2
        echo "           python3 -c \"import secrets; print(secrets.token_hex(24))\"" >&2
    else
        export IM_HMAC_SECRET="$HMAC_SECRET"
    fi
}

case "$ROLE" in
    plc)
        # AUDIT S1: the PLC only accepts plant writes from the middleware. Its allow-list defaults to IM_MIDDLEWARE_HOST,
        # so the PLC laptop must be told where the middleware is - otherwise it would refuse the middleware's own writes.
        export IM_MIDDLEWARE_HOST="$MW_IP"
        exec $PY -m plc.plc "$@"
        ;;
    dashboard)
        export IM_DASHBOARD_BIND_HOST="$DASHBOARD_BIND_HOST"
        # The DASHBOARD reads these to name the hosts in the Live Network Flow ("SCADA operator" instead of a bare "host").
        export IM_HOST_LABELS="$SCADA_IP=SCADA operator,$ATTACKER_IP=Attacker laptop"
        dash_token
        exec $PY dashboard/app.py "$@"
        ;;
    middleware)
        export IM_PLC_HOST="$PLC_IP"
        export IM_TRUSTED_SOURCES="$SCADA_IP,$ATTACKER_IP"
        export IM_HOST_LABELS="$SCADA_IP=SCADA operator,$ATTACKER_IP=Attacker laptop"
        # auto-quarantine: ON for a multi-laptop run, switched OFF by itself when every address is loopback (one-laptop demo)
        export IM_QUARANTINE="${IM_QUARANTINE:-auto}"
        dash_token
        need_secret
        exec $PY -m middleware.middleware_server "$@"
        ;;
    scada)
        export IM_MIDDLEWARE_HOST="$MW_IP"
        need_secret
        exec $PY -m scada.scada "$@"
        ;;
    attacker)
        export IM_MIDDLEWARE_HOST="$MW_IP"
        export IM_PLC_HOST="$PLC_IP"
        need_secret
        exec $PY -m attacker.attacker "$@"
        ;;
    check)
        # Preflight for a given sub-role: ./scripts/run.sh check middleware
        SUB="${1:-}"; shift || true
        export IM_PLC_HOST="$PLC_IP"
        export IM_MIDDLEWARE_HOST="$MW_IP"
        export IM_TRUSTED_SOURCES="$SCADA_IP,$ATTACKER_IP"
        [[ -n "${HMAC_SECRET:-}" ]] && export IM_HMAC_SECRET="$HMAC_SECRET"
        exec $PY -m tools.check_topology --role "$SUB" --multi "$@"
        ;;
    *)
        echo "Usage: ./scripts/run.sh <plc|dashboard|middleware|scada|attacker|check> [extra args]" >&2
        echo "First copy config/lab.env.example to config/lab.env and fill it in." >&2
        exit 2
        ;;
esac
