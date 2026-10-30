#!/bin/bash
# LAPTOP 1 (Mac): middleware + dashboard + packet capture.  Double-click this file.
# Opens three Terminal windows (dashboard, middleware, tshark capture) and the dashboard page in the browser.
# Addresses and the shared secret come from config/lab.env (via scripts/run.sh); nothing is hard-coded here.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IFACE="${IM_CAPTURE_IFACE:-en0}"      # the Wi-Fi interface; `tshark -D` lists the others

if [ ! -d "$ROOT/.venv" ]; then
    echo "No .venv found in $ROOT - run the one-time setup first."; read -r -p "Press Enter to close"; exit 1
fi

new_window() {   # $1 = shell command to run inside the project, in a new Terminal window
    osascript >/dev/null <<EOF
tell application "Terminal"
    activate
    do script "cd '$ROOT' && source .venv/bin/activate && $1"
end tell
EOF
}

echo "Starting LAPTOP 1 (middleware + dashboard + capture)..."
new_window "bash scripts/run.sh dashboard"
sleep 4
new_window "bash scripts/run.sh middleware"
sleep 2
new_window "tshark -i $IFACE -f 'tcp port 5021' -o mbtcp.tcp.port:5021 -Y mbtcp"
sleep 6
open "http://127.0.0.1:5050"

cat <<'TXT'

Three windows are open: dashboard, middleware, capture (leave them all open).
The dashboard is open in your browser.
The physical model needs about 2 minutes to warm up after the middleware starts.
Start Laptop 3 (SCADA) once the middleware window says it is listening, then Laptop 4 (attacks).
To stop: close the three windows (or press Ctrl+C in each).
TXT
read -r -p "You can close this window. Press Enter."
