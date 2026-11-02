"""
models/train_models.py - RETIRED.

This script trained the old synthetic health/RUL PhysicalModel and the synthetic CyberModel. Both are gone:
the dataset policy is SWaT-only. Use instead

    python -m research.train_cyber_swat    --data-dir <archive> --candidate
    python -m models.train_physical_swat --data-dir <archive> --candidate

(each writes a CANDIDATE to models/candidates/; weights only change through models/promote_candidate.py
after the user approves).
"""

raise SystemExit(__doc__)
