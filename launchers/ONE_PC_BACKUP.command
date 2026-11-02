#!/bin/bash
# BACKUP (Mac): the whole system on THIS computer, loopback only. Double-click this file.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1
if [ ! -d ".venv" ]; then echo "No .venv found in $ROOT - run the one-time setup first."; read -r -p "Press Enter to close"; exit 1; fi
source .venv/bin/activate
python launchers/one_pc_demo.py
read -r -p "Finished. Press Enter to close."
