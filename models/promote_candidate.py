"""
models/promote_candidate.py - copy an APPROVED candidate from models/candidates/ into models/weights/.

    python -m models.promote_candidate cyber          # also: physical, orchestrator

Enforcement (same state the hooks use): the user must have approved replacing THAT model in this
session, recorded with
    python3 .claude/hooks/confirm.py retrain <model>
which writes .claude/state/confirmations.json for the current session. Without it this script refuses.
Never run the confirm command without an explicit approval from the user in chat.
"""

from __future__ import annotations

import json
import os
import shutil
import sys

ROOT = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
STATE = os.path.join(ROOT, ".claude", "state")
CAND = os.path.join(ROOT, "models", "candidates")
WEIGHTS = os.path.join(ROOT, "models", "weights")
FILES = {
    "cyber": ["cyber_model.joblib", "cyber_training_report.json", "cyber_training_report.md"],
    "physical": ["physical_model.joblib", "physical_training_report.json", "physical_training_report.md"],
    "orchestrator": ["orchestrator_model.joblib", "orchestrator_training_report.json", "orchestrator_training_report.md"],
}


def approved(model: str) -> bool:
    try:
        session = open(os.path.join(STATE, "current_session")).read().strip()
        conf = json.load(open(os.path.join(STATE, "confirmations.json"))).get(session, {})
    except Exception:
        return False
    return model in conf.get("retrain", []) or "all" in conf.get("retrain", [])


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in FILES:
        print(__doc__)
        return 2
    model = sys.argv[1]
    if not approved(model):
        print(f"REFUSED: replacing the '{model}' weights was not approved this session "
              f"(user approval, then: python3 .claude/hooks/confirm.py retrain {model})")
        return 1
    missing = [f for f in FILES[model][:1] if not os.path.exists(os.path.join(CAND, f))]
    if missing:
        print(f"no candidate to promote: {missing} not found in {CAND}")
        return 1
    os.makedirs(WEIGHTS, exist_ok=True)
    for f in FILES[model]:
        src = os.path.join(CAND, f)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(WEIGHTS, f))
            print(f"promoted {f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
