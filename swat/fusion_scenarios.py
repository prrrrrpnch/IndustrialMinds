"""
swat/fusion_scenarios.py - labelled scenario set for the orchestrator FUSION model (Phase 7).

THE KEY DESIGN POINT: the label is GROUND TRUTH, the model sees NOISY OBSERVATIONS.
  truth    : is the cyber layer truly failing? is the physical layer truly failing?  -> label by the four-branch table
  observed : what the detectors actually reported (rule verdict; physical model scores/flags/envelope).
If the label were computed from the observed pass flags that are also inputs, a tree would just memorise the truth
table. Here a detector miss (attack window, physical_pass = 1) or a false alarm (benign window, physical_pass = 0)
makes the correct decision differ from the naive lookup - that gap is what a learned fusion could improve on.

FOUR-BRANCH TABLE (truth):
    cyber ok,   physical ok   -> PASS
    cyber fail, physical fail -> DROP
    cyber fail, physical ok   -> DROP
    cyber ok,   physical fail -> ALERT

HONESTY: 'source' says where a row's observations come from.
  swat_real   : the physical side is the REAL output of the promoted PhysicalModel on a real SWaT window (truth = SWaT label).
                The cyber side is ASSUMED to pass (SWaT attacks are physical; SWaT has no signatures/replay/sources, so the
                rule-based cyber layer can NOT be evaluated on SWaT rows).
  constructed : the physical observation is again a real SWaT window, but the cyber layer is ASSUMED to fail (a rule such as
                HMAC_INVALID / REPLAY_DETECTED fired). Cyber rules are deterministic, so a constructed row's cyber_pass is
                always 0 and its reason names the rule. The cyber half of these rows is a scenario, not data.
Consequence: real-data evidence in this set concerns the PHYSICAL side only (PASS vs ALERT). The DROP class is produced by
the deterministic cyber rules, and this is reported as such.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

import numpy as np
import pandas as pd

from swat.physical_features import ACTUATORS, FEATURE_NAMES, build_windows

RULE_REASONS = ["UNTRUSTED_SOURCE", "INVALID_FUNCTION_CODE", "INVALID_REGISTER", "RATE_LIMIT_EXCEEDED",
                "HMAC_MISSING", "HMAC_INVALID", "HMAC_EXPIRED", "REPLAY_DETECTED"]
CLASSES = ["PASS", "ALERT", "DROP"]
FEATURES = ["cyber_pass", "cyber_reason_code", "phys_if_score", "phys_p_attack", "physical_pass",
            "env_violations", "env_max_excess", "act_toggles", "flow_balance"]
_IDX = {n: i for i, n in enumerate(FEATURE_NAMES)}
_TOGGLES = [_IDX[f"{a}.toggles"] for a in ACTUATORS]


def four_branch(cyber_fail: bool, physical_fail: bool) -> str:
    if cyber_fail:
        return "DROP"                       # cyber fail (with or without a physical failure)
    return "ALERT" if physical_fail else "PASS"


def physical_observations(model: Any, X: np.ndarray) -> pd.DataFrame:
    """Real PhysicalModel outputs for window features X (the same quantities the live pipeline reports)."""
    s_if, p = model.anomaly_scores(X), model.attack_probability(X)
    flag = (s_if > model.threshold) | (p > model.clf_threshold)
    n_out = X[:, _IDX["sensors_outside_envelope"]]
    return pd.DataFrame({
        "phys_if_score": s_if, "phys_p_attack": p,
        "physical_pass": (~(flag | (n_out > 0))).astype(int),
        "env_violations": n_out, "env_max_excess": X[:, _IDX["max_envelope_excess"]],
        "act_toggles": X[:, _TOGGLES].sum(axis=1), "flow_balance": X[:, _IDX["flow_balance_101_201"]],
    })


def build_scenarios(stream: pd.DataFrame, model: Any, seed: int = 7, stride: int = 5,
                    constructed_fraction: float = 0.25) -> pd.DataFrame:
    """Real rows (every SWaT window) + constructed rows (cyber failures paired with real windows)."""
    X, meta = build_windows(stream, model.norm, stride=stride)
    obs = physical_observations(model, X)
    base = pd.concat([meta.reset_index(drop=True), obs], axis=1)
    rng = np.random.default_rng(seed)

    real = base.copy()
    real["source"] = "swat_real"
    real["truth_cyber_fail"] = False
    real["truth_physical_fail"] = real["label"].astype(bool)
    real["cyber_pass"], real["cyber_reason"] = 1, "OK"

    n_c = int(round(constructed_fraction * len(real)))
    ben, att = np.flatnonzero(~base["label"].to_numpy()), np.flatnonzero(base["label"].to_numpy())
    pick = np.concatenate([rng.choice(ben, n_c // 2), rng.choice(att, n_c - n_c // 2)]) if len(att) else rng.choice(ben, n_c)
    cons = base.iloc[pick].copy().reset_index(drop=True)
    cons["source"] = "constructed"
    cons["truth_cyber_fail"] = True
    cons["truth_physical_fail"] = cons["label"].astype(bool)
    cons["cyber_pass"] = 0
    cons["cyber_reason"] = rng.choice(RULE_REASONS, len(cons))

    df = pd.concat([real, cons], ignore_index=True)
    df["cyber_reason_code"] = df["cyber_reason"].map({"OK": 0, **{r: i + 1 for i, r in enumerate(RULE_REASONS)}})
    df["decision"] = [four_branch(c, p) for c, p in zip(df["truth_cyber_fail"], df["truth_physical_fail"])]
    df = df.rename(columns={"seg": "segment"})
    df.insert(0, "scenario_id", np.arange(len(df)))
    return df


def naive_lookup(df: pd.DataFrame) -> np.ndarray:
    """The four-branch table applied to the OBSERVED pass flags (what a non-learned fusion would output)."""
    return np.array([four_branch(c == 0, p == 0) for c, p in zip(df["cyber_pass"], df["physical_pass"])])


def and_gate(df: pd.DataFrame) -> np.ndarray:
    """The CURRENT orchestrator: DROP if either layer fails, else PASS (it has no ALERT class)."""
    return np.where((df["cyber_pass"] == 0) | (df["physical_pass"] == 0), "DROP", "PASS")


def sample_rows(df: pd.DataFrame, n: int = 20, seed: int = 3) -> pd.DataFrame:
    """A stratified, readable sample showing every kind of row the training set contains."""
    rng = np.random.default_rng(seed)
    real = df["source"] == "swat_real"
    kinds: List[Tuple[str, pd.Series, int]] = [
        ("real benign, physical passed (PASS)", real & (df.truth_physical_fail == False) & (df.physical_pass == 1), 4),
        ("real benign, FALSE ALARM physical failed (still PASS)", real & (df.truth_physical_fail == False) & (df.physical_pass == 0), 2),
        ("real attack, physical caught it (ALERT)", real & df.truth_physical_fail & (df.physical_pass == 0), 4),
        ("real attack, physical MISSED it (ALERT)", real & df.truth_physical_fail & (df.physical_pass == 1), 4),
        ("constructed: cyber rule fails, benign window (DROP)", (~real) & (df.truth_physical_fail == False), 3),
        ("constructed: cyber rule fails, attack window (DROP)", (~real) & df.truth_physical_fail, 3),
    ]
    parts = []
    for name, mask, k in kinds:
        idx = np.flatnonzero(mask.to_numpy())
        if len(idx):
            take = rng.choice(idx, min(k, len(idx)), replace=False)
            part = df.iloc[take].copy()
            part.insert(1, "kind", name)
            parts.append(part)
    return pd.concat(parts, ignore_index=True)
