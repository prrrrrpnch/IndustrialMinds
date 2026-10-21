"""
tests/test_verify_three_laptops.py - the end-to-end rehearsal tool (tools/verify_three_laptops.py), without starting any process.

The tool itself is exercised for real by `python -m tools.verify_three_laptops` (about 5 minutes). This pins the parts that can
be checked offline: that it points the launcher at its OWN lab.env (so it can never be overridden by, or modify, the real
config/lab.env), that the one disclosed shim is the one it claims to be, and that the report is built from the run's own results.

    python -m tests.test_verify_three_laptops
"""

from __future__ import annotations

import io
import json
import os
import tempfile

from tools import verify_three_laptops as V

fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global fails
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    fails += 0 if cond else 1


ROOT = V.ROOT
out = tempfile.mkdtemp(prefix="im-v3l-")
lab = V.Lab(out)

print("THE LAB IT BUILDS")
env_text = io.open(os.path.join(out, "lab.env")).read()
check("it writes its own lab.env in the launcher's own variable names",
      all(k in env_text for k in ("MW_IP=", "PLC_IP=", "SCADA_IP=", "ATTACKER_IP=", "HMAC_SECRET=")))
check("PLC and SCADA share ONE address (the three-laptop layout), the attacker has another",
      f"PLC_IP={V.L2}" in env_text and f"SCADA_IP={V.L2}" in env_text and f"ATTACKER_IP={V.L3}" in env_text)
check("every address is loopback - the rehearsal can never put a real IP in a file or a command",
      all(a.startswith("127.") for a in (V.L1, V.L2, V.L3, V.ROGUE)))
check("the launcher is pointed at THAT file, so the real config/lab.env cannot override it or be touched",
      lab.env["IM_LAB_ENV"] == os.path.join(out, "lab.env"))
check("no inherited opt-in setting can change the verdicts",
      not [k for k in lab.env if k.startswith("IM_") and k not in ("IM_LOG_DIR", "IM_LAB_ENV")])
check("logs go to the run directory, not the repo's logs/", lab.env["IM_LOG_DIR"] == out)

print("\nTHE ONE DISCLOSED SHIM")
shim = io.open(os.path.join(out, "shim", "sitecustomize.py")).read()
check("it only acts when IM_BIND_SOURCE is set, so it cannot touch any other process", "IM_BIND_SOURCE" in shim and "if _src:" in shim)
check("it only sets a source address, nothing about behaviour", "source_address" in shim and "setdefault" in shim)
check("it lives in the run directory, not in the repository", os.path.dirname(os.path.join(out, "shim")) == out)

print("\nTHE LAUNCHER HONOURS IM_LAB_ENV")
sh = io.open(os.path.join(ROOT, "scripts", "run.sh")).read()
ps = io.open(os.path.join(ROOT, "scripts", "run.ps1")).read()
check("run.sh reads IM_LAB_ENV and falls back to config/lab.env", 'ENV_FILE="${IM_LAB_ENV:-config/lab.env}"' in sh)
check("run.ps1 does the same", "$env:IM_LAB_ENV" in ps and "config\\lab.env" in ps)
check("the dashboard role gets the host labels, so the flow view says 'SCADA operator' not 'host'",
      "IM_HOST_LABELS" in sh.split("dashboard)")[1].split("middleware)")[0]
      and "IM_HOST_LABELS" in ps.split("'dashboard' {")[1].split("'middleware' {")[0])

print("\nTHE REPORT IS BUILT FROM THE RUN'S OWN RESULTS")
res = {"passed": 2, "total": 3, "seconds": 9, "findings": ["a thing the run saw"],
       "results": [{"section": "1. A", "check": "first", "pass": True, "detail": "ok"},
                   {"section": "1. A", "check": "second", "pass": True, "detail": ""},
                   {"section": "2. B", "check": "third", "pass": False, "detail": "bad | pipe"}],
       "wire": {"frames_to_mw": 5, "frames_to_plc": 4, "attacker_frames": 3, "plc_from_mw": 4, "forwarded_log": 4, "blocked_records": 2},
       "attacks": {"replay": [{"verdict": "PASS", "reason": "OK"}, {"verdict": "DROP", "reason": "REPLAY_DETECTED:x"}]}}
with open(os.path.join(out, "e2e_result.json"), "w") as fh:
    json.dump(res, fh)
saved = V.ROOT
V.ROOT = tempfile.mkdtemp(prefix="im-v3l-root-")
os.makedirs(os.path.join(V.ROOT, "docs", "reports"))
try:
    path = V.render(out)
    md = io.open(path).read()
finally:
    V.ROOT = saved
check("the report states the pass count from the data", "**2/3 checks passed**" in md)
check("a FAILING check is shown as a failure, not dropped", "| **FAIL** | third |" in md)
check("a pipe in an observation cannot break the table", "bad \\| pipe" in md)
check("each stage gets its own tally", "| 1. A | 2/2 |" in md and "| 2. B | 0/1 |" in md)
check("it says what is NOT proven", "**Not proven**" in md and "real Wi-Fi" in md)
check("it discloses the shim", "**One disclosed shim**" in md)
check("the wire cross-check table is there", "writes the PLC received from the middleware" in md)
check("findings are carried through", "a thing the run saw" in md)

print("\nALL PASS" if fails == 0 else f"\n{fails} CHECK(S) FAILED")
raise SystemExit(1 if fails else 0)
