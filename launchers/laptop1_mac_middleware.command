#!/bin/bash
# LAPTOP 1 (Mac): middleware + dashboard + packet capture, started with ONE click.
#
# What it does, in order:
#   1. one-time setup if needed: creates .venv and installs the packages (needs internet), and asks for the addresses
#      and the shared secret if config/lab.env does not exist yet (nothing is hard-coded in this file);
#   2. opens three Terminal windows: dashboard, middleware, tshark capture (and the dashboard page in your browser);
#   3. stays open and tells you when the PLC (Laptop 2) is up and the middleware has connected to it.
# You can start this BEFORE the PLC: the middleware keeps retrying and connects the moment the PLC is running.
#
# Hooks for testing only: IM_OSASCRIPT, IM_OPEN, IM_SKIP_PIP, IM_WAIT_PLC_S.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IFACE="${IM_CAPTURE_IFACE:-en0}"            # the Wi-Fi interface; `tshark -D` lists the others
OSA="${IM_OSASCRIPT:-osascript}"
OPENER="${IM_OPEN:-open}"
WAIT_PLC_S="${IM_WAIT_PLC_S:-600}"          # how long this window waits for the PLC before it gives up waiting (windows stay)

cd "$ROOT" || exit 1
say()  { printf '%s\n' "$*"; }
stop() { say ""; read -r -p "Press Enter to close."; exit "${1:-1}"; }

say "=== LAPTOP 1: middleware + dashboard + capture ==="

# ---- 1a. the virtual environment and packages -----------------------------------------------------------------------
if [ ! -d ".venv" ]; then
    say "First run on this laptop: creating .venv and installing the packages (a few minutes, needs internet)..."
    PY="$(command -v python3.13 || command -v python3 || true)"
    [ -n "$PY" ] || { say "Python 3 was not found. Install Python 3.13 from python.org, then run this again."; stop; }
    say "Using $($PY --version 2>&1) at $PY"
    "$PY" -m venv .venv || { say "Could not create .venv."; stop; }
    if [ -z "$IM_SKIP_PIP" ]; then
        .venv/bin/python -m pip install -r requirements.txt || { say "Installing the packages failed (internet?). Fix that and run this again."; stop; }
        say "Checking the installation..."
        .venv/bin/python -m tests.test_environment || { say "The environment check failed (see above). Paste it to your helper."; stop; }
    fi
fi

# ---- 1b. config/lab.env ----------------------------------------------------------------------------------------------
if [ ! -f "config/lab.env" ]; then
    say ""
    say "config/lab.env is missing. Type the values for this lab (the same file is used on every laptop)."
    DEFAULT_MW="$(ipconfig getifaddr en0 2>/dev/null || true)"
    read -r -p "Laptop 1 (middleware, this Mac) address [${DEFAULT_MW}]: " MW_IP;   MW_IP="${MW_IP:-$DEFAULT_MW}"
    read -r -p "Laptop 2 (PLC) address: "           PLC_IP
    read -r -p "Laptop 3 (SCADA) address: "         SCADA_IP
    read -r -p "Laptop 4 (attacker) address: "      ATTACKER_IP
    read -r -p "Shared HMAC secret (the SAME on every laptop): " HMAC_SECRET
    if [ -z "$MW_IP" ] || [ -z "$PLC_IP" ] || [ -z "$SCADA_IP" ] || [ -z "$ATTACKER_IP" ] || [ -z "$HMAC_SECRET" ]; then
        say "All five values are needed. Nothing was written; run this again."; stop
    fi
    mkdir -p config
    {
        echo "MW_IP=$MW_IP"; echo "PLC_IP=$PLC_IP"; echo "SCADA_IP=$SCADA_IP"; echo "ATTACKER_IP=$ATTACKER_IP"
        echo "HMAC_SECRET=$HMAC_SECRET"; echo "DASHBOARD_BIND_HOST=127.0.0.1"; echo "DASHBOARD_TOKEN="
    } > config/lab.env
    say "Wrote config/lab.env."
fi
PLC_IP="$(grep -E '^PLC_IP=' config/lab.env | head -1 | cut -d= -f2 | cut -d'#' -f1 | tr -d '[:space:]')"

# ---- 2. the windows --------------------------------------------------------------------------------------------------
PYV=".venv/bin/python"
port_open() { "$PYV" -c "import socket,sys; socket.create_connection((sys.argv[1], int(sys.argv[2])), 2).close()" "$1" "$2" 2>/dev/null; }

for p in 5021 5050; do
    port_open 127.0.0.1 "$p" && say "WARNING: port $p is already in use here. Close any old dashboard/middleware window first."
done

new_window() {   # $1 = command to run inside the project, in a new Terminal window
    "$OSA" >/dev/null <<EOF
tell application "Terminal"
    activate
    do script "cd '$ROOT' && source .venv/bin/activate && $1"
end tell
EOF
}

TSHARK="$(command -v tshark || true)"
[ -n "$TSHARK" ] || TSHARK="/Applications/Wireshark.app/Contents/MacOS/tshark"
[ -x "$TSHARK" ] || { say "(tshark not found: the capture window is skipped)"; TSHARK=""; }

say "Opening the dashboard window..."
new_window "bash scripts/run.sh dashboard"
sleep 4
say "Opening the middleware window..."
new_window "bash scripts/run.sh middleware"
if [ -n "$TSHARK" ]; then
    sleep 2
    say "Opening the capture window on $IFACE..."
    new_window "'$TSHARK' -i $IFACE -f 'tcp port 5021' -o mbtcp.tcp.port:5021 -Y mbtcp"
fi
sleep 5
"$OPENER" "http://127.0.0.1:5050"

# ---- 3. wait for the PLC, then confirm the middleware connected ------------------------------------------------------------
say ""
say "Dashboard and middleware are starting. Leave their windows open."
if [ -n "$PLC_IP" ]; then
    say "Waiting for the PLC (Laptop 2) at $PLC_IP:5020. Start it now if you have not (double-click laptop2_win_plc.bat)."
    waited=0
    until port_open "$PLC_IP" 5020; do
        sleep 3; waited=$((waited + 3))
        if [ "$waited" -ge "$WAIT_PLC_S" ]; then
            say "Still no PLC after ${WAIT_PLC_S}s. The middleware window keeps retrying, so it connects as soon as the PLC is up."
            say "If it never does: both laptops on the same Wi-Fi? Try   ping -c 3 $PLC_IP"
            stop 0
        fi
    done
    say "PLC is reachable."
    for _ in $(seq 1 20); do
        if "$PYV" -c "import json,urllib.request,sys; sys.exit(0 if json.load(urllib.request.urlopen('http://127.0.0.1:5050/api/health',timeout=3)).get('plc')=='connected' else 1)" 2>/dev/null; then
            say "Middleware is connected to the PLC."
            say ""
            say "READY. Next: start Laptop 3 (SCADA), wait about 2 minutes for the model, then Laptop 4 (attacks)."
            stop 0
        fi
        sleep 3
    done
    say "The PLC is reachable but the middleware has not reported a connection yet. Look at the middleware window for errors."
fi
stop 0
