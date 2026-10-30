#!/bin/bash
# LAPTOP 3 (Mac): SCADA operator.  Double-click this file AFTER Laptop 1 (middleware) is running.
# It waits for the middleware to be reachable, then starts SCADA. Address and secret come from config/lab.env.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1

if [ ! -d ".venv" ]; then
    echo "No .venv found in $ROOT - run the one-time setup first."; read -r -p "Press Enter to close"; exit 1
fi
source .venv/bin/activate

MW_IP="$(grep -E '^MW_IP=' config/lab.env 2>/dev/null | head -1 | cut -d= -f2 | cut -d'#' -f1 | tr -d '[:space:]')"
MW_IP="${MW_IP:-127.0.0.1}"

echo "Waiting for the middleware at $MW_IP:5021 (start Laptop 1 first; Ctrl+C to give up)..."
until nc -z -G 2 "$MW_IP" 5021 2>/dev/null; do sleep 2; done
echo "Middleware is reachable. Starting SCADA."
bash scripts/run.sh scada
echo
read -r -p "SCADA stopped. Press Enter to close."
