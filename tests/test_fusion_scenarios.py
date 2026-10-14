"""
tests/test_fusion_scenarios.py - Phase 7: invariants of the fusion scenario set (on the synthetic fixture).

    python -m tests.test_fusion_scenarios
"""

from __future__ import annotations

import os
import tempfile

import numpy as np

from models.physical_model import PhysicalModel
from swat.fusion_scenarios import CLASSES, RULE_REASONS, and_gate, build_scenarios, four_branch, naive_lookup, sample_rows
from swat.loader import load_stream
from swat.physical_features import ACTUATORS, SENSORS
from tests.swat_fixture import make_swat_archive

fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global fails
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    fails += 0 if cond else 1


print("FOUR-BRANCH TABLE")
check("cyber ok + physical ok -> PASS", four_branch(False, False) == "PASS")
check("cyber fail + physical fail -> DROP", four_branch(True, True) == "DROP")
check("cyber fail + physical ok -> DROP", four_branch(True, False) == "DROP")
check("cyber ok + physical fail -> ALERT", four_branch(False, True) == "ALERT")

print("\nSCENARIO SET (fixture, promoted physical model)")
d = tempfile.mkdtemp(prefix="fusion-test-")
make_swat_archive(d, seed=0)
stream, _ = load_stream(d, SENSORS + ACTUATORS)
model = PhysicalModel.load()
df = build_scenarios(stream, model, seed=7)
df2 = build_scenarios(stream, model, seed=7)
real, cons = df[df.source == "swat_real"], df[df.source == "constructed"]
check("only the two sources exist", set(df.source) == {"swat_real", "constructed"})
check("decisions are in the three classes", set(df.decision) <= set(CLASSES))
check("every real row assumes the cyber layer passes (SWaT cannot evaluate the rules) and is never DROP",
      bool((real.cyber_pass == 1).all()) and bool((real.decision != "DROP").all()))
check("every constructed row has a failing cyber rule, a named reason, and is DROP",
      bool((cons.cyber_pass == 0).all()) and bool(cons.cyber_reason.isin(RULE_REASONS).all()) and bool((cons.decision == "DROP").all()))
check("real labels follow ground truth: attack window -> ALERT, benign window -> PASS",
      bool(((real.truth_physical_fail) == (real.decision == "ALERT")).all()))
check("label is ground truth, NOT a function of the observed flags (misses and false alarms exist)",
      int(((real.decision == "ALERT") & (real.physical_pass == 1)).sum()) > 0 and int(((real.decision == "PASS") & (real.physical_pass == 0)).sum()) > 0)
check("constructed rows inherit the block of their real window (no cross-block mixing)",
      set(cons.block) <= {"train", "val", "test"} and cons[cons.segment > 0].groupby("segment").block.nunique().max() == 1)
check("deterministic for a fixed seed", df.equals(df2))
check("the naive lookup on observed flags is NOT the truth on real rows (headroom exists)", float((naive_lookup(real) != real.decision.to_numpy()).mean()) > 0.0)
check("the AND-gate has no ALERT class", set(and_gate(df)) <= {"PASS", "DROP"})
s = sample_rows(df, 20)
check("the sample shows every kind of row (>= 5 kinds) and at most 20 rows", s.kind.nunique() >= 5 and len(s) <= 20, f"{len(s)} rows, {s.kind.nunique()} kinds")
check("no raw SWaT sensor columns leak into the scenario rows", not any(c in df.columns for c in SENSORS))

print("\nALL PASS" if fails == 0 else f"\n{fails} CHECK(S) FAILED")
raise SystemExit(1 if fails else 0)
