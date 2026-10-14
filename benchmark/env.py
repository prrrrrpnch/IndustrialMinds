"""benchmark/env.py - record what a benchmark ran on, so a number is never quoted without its machine and versions."""

from __future__ import annotations

import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any, Dict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _git(*args: str) -> str:
    try:
        return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception:
        return ""


def environment() -> Dict[str, Any]:
    import joblib
    import numpy
    import pandas
    import sklearn
    return {
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "python": sys.version.split()[0], "platform": platform.platform(), "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
        "numpy": numpy.__version__, "pandas": pandas.__version__, "scikit_learn": sklearn.__version__, "joblib": joblib.__version__,
        "git_commit": _git("rev-parse", "--short", "HEAD"), "git_dirty": bool(_git("status", "--porcelain")),
    }
