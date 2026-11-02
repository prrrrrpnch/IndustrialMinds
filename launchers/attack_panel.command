#!/bin/bash
# Mac/Linux: the attack BUTTON panel (normally the attacker laptop is Windows: use laptop4_attack_panel.bat there).
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1
if [ ! -d ".venv" ]; then echo "No .venv found in $ROOT - run the one-time setup first."; read -r -p "Press Enter to close"; exit 1; fi
source .venv/bin/activate
python -m attacker.control_panel
read -r -p "Panel stopped. Press Enter to close."
