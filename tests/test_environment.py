"""
tests/test_environment.py - Phase 11: the environment matches the pins, and the promoted weights unpickle cleanly.

    python -m tests.test_environment
"""

from __future__ import annotations

import os
import re
import warnings

import sklearn

from benchmark.env import ROOT

fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global fails
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    fails += 0 if cond else 1


req = open(os.path.join(ROOT, "requirements.txt")).read()
m = re.search(r"^scikit-learn==([\d.]+)\s*$", req, re.M)
check("requirements.txt pins scikit-learn exactly", m is not None)
check("the installed scikit-learn equals the pin (pickled weights depend on it)", bool(m) and sklearn.__version__ == m.group(1),
      f"installed {sklearn.__version__}, pinned {m.group(1) if m else '?'}")
check("pymodbus stays pinned to 3.6.9", re.search(r"^pymodbus==3\.6\.9\s*$", req, re.M) is not None)

with warnings.catch_warnings():
    warnings.simplefilter("error")
    try:
        from models.physical_model import PhysicalModel
        pm = PhysicalModel.load()
        ok, why = pm.status == "OK", pm.status
    except Exception as e:                                   # InconsistentVersionWarning is raised as an error here
        ok, why = False, type(e).__name__
check("the promoted physical weights load with no version warning and report status OK", ok, why)

print("\nALL PASS" if fails == 0 else f"\n{fails} CHECK(S) FAILED")
raise SystemExit(1 if fails else 0)
