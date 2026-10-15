"""
swat/alarm_logic.py - turning per-window scores into ALARMS: persistence (K flags in the last M windows) and the false-alarm budget.

A single window flag is noisy: healthy plants produce isolated blips, while real attacks usually keep the score high for a while.
"K of the last M windows" suppresses isolated blips (fewer false alarms) at the cost of a slightly later alarm. Windows are consecutive
only inside a run spaced exactly `stride` seconds apart; a gap restarts the run (the same rule the feature builder uses for chunks).

Pure NumPy, no scikit-learn: shared by the experiment trainer now and by a live decision rule later.
"""

from __future__ import annotations

from typing import Dict, Optional, Tuple

import numpy as np

STRIDE_S = 5
EPISODE_GAP_S = 30.0


def persist(flags: np.ndarray, epoch: np.ndarray, k: int, m: int, stride: int = STRIDE_S) -> np.ndarray:
    """True where at least k of the last m windows (same run, `stride` apart, current one included) are flagged. flags must be time ordered."""
    flags = np.asarray(flags, bool)
    n = flags.size
    if n == 0:
        return flags.copy()
    if k <= 1 and m <= 1:
        return flags.copy()
    new_run = np.concatenate(([True], np.diff(epoch) != stride))
    idx = np.arange(n)
    run_start = np.maximum.accumulate(np.where(new_run, idx, 0))
    cum = np.concatenate(([0], np.cumsum(flags.astype(np.int64))))
    j = np.maximum(idx - m + 1, run_start)
    return (cum[idx + 1] - cum[j]) >= k


def episodes(epoch: np.ndarray, flagged: np.ndarray, gap_s: float = EPISODE_GAP_S) -> int:
    """Alarm episodes: runs of flagged windows separated from the next by more than gap_s."""
    t = np.sort(np.asarray(epoch)[np.asarray(flagged, bool)])
    return 0 if t.size == 0 else int(1 + (np.diff(t) > gap_s).sum())


def benign_hours(epoch: np.ndarray, y: np.ndarray, stride: int = STRIDE_S) -> float:
    return max(float((~np.asarray(y, bool)).sum()) * stride / 3600.0, 1e-9)


def threshold_for_budget(score: np.ndarray, epoch: np.ndarray, y: np.ndarray, k: int, m: int, budget: float,
                         n_candidates: int = 60) -> Optional[float]:
    """Smallest threshold whose alarm episodes per BENIGN hour (after persistence) stay within `budget`; None if none does."""
    y = np.asarray(y, bool)
    hours = benign_hours(epoch, y)
    cands = np.unique(np.quantile(score[~y], np.linspace(0.80, 0.99999, n_candidates)))
    for thr in cands:                                    # ascending: the first feasible threshold is the most sensitive one
        fl = persist(score > thr, epoch, k, m)
        if episodes(epoch[~y], fl[~y]) / hours <= budget:
            return float(thr)
    return None


def segment_balanced_recall(flags: np.ndarray, y: np.ndarray, seg: np.ndarray) -> float:
    """Mean over attack segments of the fraction of that segment's windows flagged (every segment counts equally)."""
    y = np.asarray(y, bool)
    fr = [float(flags[(seg == s) & y].mean()) for s in np.unique(seg[y])]
    return float(np.mean(fr)) if fr else 0.0


def best_alarm_rule(score: np.ndarray, epoch: np.ndarray, y: np.ndarray, seg: np.ndarray, budget: float,
                    grid: Tuple[Tuple[int, int], ...] = ((1, 1), (2, 2), (2, 3), (3, 4), (3, 6), (4, 6), (5, 8))) -> Dict[str, float]:
    """Among the (k, m) rules, the one that detects the most (segment-balanced recall) while meeting the false-alarm budget. Chosen on DEV only."""
    best: Dict[str, float] = {}
    for k, m in grid:
        thr = threshold_for_budget(score, epoch, y, k, m, budget)
        if thr is None:
            continue
        rec = segment_balanced_recall(persist(score > thr, epoch, k, m), y, seg)
        if not best or rec > best["segment_balanced_recall"]:
            best = {"k": k, "m": m, "threshold": thr, "segment_balanced_recall": rec, "budget": budget}
    return best
