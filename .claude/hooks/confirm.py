#!/usr/bin/env python3
"""
Record a user confirmation for the CURRENT session. Run ONLY after the user has
explicitly approved in chat.

  python3 .claude/hooks/confirm.py delete <path> [<path>...]   # R1
  python3 .claude/hooks/confirm.py retrain <cyber|physical|orchestrator|all>  # R2
  python3 .claude/hooks/confirm.py ips <ip> [<ip>...]          # R3 (Phase 10 laptop IPs)
  python3 .claude/hooks/confirm.py show
"""
import json, os, sys
ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", ".."))
STATE = os.path.join(ROOT, ".claude", "state")
CONF = os.path.join(STATE, "confirmations.json")
kind, items = (sys.argv[1] if len(sys.argv) > 1 else "show"), sys.argv[2:]
session = open(os.path.join(STATE, "current_session")).read().strip()
try:
    data = json.load(open(CONF))
except Exception:
    data = {}
cur = data.setdefault(session, {"delete": [], "retrain": [], "ips": []})
if kind in ("delete", "retrain", "ips"):
    for i in items:
        if i not in cur[kind]:
            cur[kind].append(i)
    json.dump(data, open(CONF, "w"), indent=2)
print(json.dumps({session: cur}, indent=2))
