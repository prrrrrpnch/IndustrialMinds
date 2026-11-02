"""
swat/scoring.py - ONE place that scores per-window alarm flags against labelled attack segments, five ways, with confidence intervals.

Why five: published SWaT detectors are usually reported with POINT-ADJUST scoring (one flagged window inside an attack counts the whole
attack as caught), which can make even random alarms look state-of-the-art (Kim et al., AAAI 2022). We therefore always report the same
alarms under every scheme, side by side, so the reader can compare with the literature AND see what the strict number is:

  strict      every window scored on its own (the number we headline)
  composite   precision per window (false alarms still hurt), recall per ATTACK (Garg et al. 2021)
  PA%K        an attack counts as caught only if more than K % of its windows are flagged (Kim et al. 2022); K = 20 / 50 / 80
  point-adjust  K = 0: one flagged window credits the whole attack
  event-level  attacks detected / total, detection delay, false-alarm episodes per benign hour, share of alarm episodes that were real

Everything is computed from SUFFICIENT STATISTICS (`Counts`): per-attack-segment window counts and per-benign-hour false-alarm counts.
That is what makes the cluster bootstrap cheap (resample attacks and benign hours, not windows: windows inside one attack are not
independent) and lets the same code re-score a saved report that only kept per-segment aggregates (`from_report_block`).

Pure NumPy. No scikit-learn, no I/O.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

STRIDE_S = 5
EPISODE_GAP_S = 30.0
CLUSTER_S = 3600
PAK_LEVELS = (20, 50, 80)
CI_KEYS = ("precision", "recall", "f1", "accuracy", "composite_f1", "pa_f1", "pak50_f1", "event_recall", "segment_balanced_recall",
           "false_alarm_episodes_per_hour", "median_latency_s")


@dataclass
class Counts:
    """Sufficient statistics of one scored run. Attack side: one entry per attack segment. Benign side: one entry per cluster (an hour)."""
    seg_id: np.ndarray
    seg_n: np.ndarray            # attack windows in the segment
    seg_hit: np.ndarray          # of those, flagged
    seg_lat: np.ndarray          # seconds from the segment's first window to its first flagged window (NaN if never flagged)
    ben_n: np.ndarray            # benign windows in the cluster
    ben_fp: np.ndarray           # of those, flagged
    ben_ep: np.ndarray           # alarm episodes (flags closer than EPISODE_GAP_S merge) among the cluster's benign windows
    ben_hours: np.ndarray        # benign time of the cluster
    ep_true: Optional[int] = None    # alarm episodes (over ALL flagged windows) that contain at least one attack window
    ep_total: Optional[int] = None

    def subset_segments(self, keep: np.ndarray) -> "Counts":
        return Counts(self.seg_id[keep], self.seg_n[keep], self.seg_hit[keep], self.seg_lat[keep], self.ben_n, self.ben_fp, self.ben_ep, self.ben_hours)


def episode_ids(epoch: np.ndarray, flagged: np.ndarray, gap_s: float = EPISODE_GAP_S) -> np.ndarray:
    """Episode number (0..) of every FLAGGED window, in time order of the flagged windows' own epochs (input need not be sorted)."""
    t = np.asarray(epoch, float)[np.asarray(flagged, bool)]
    if t.size == 0:
        return np.empty(0, int)
    order = np.argsort(t, kind="stable")
    ids = np.empty(t.size, int)
    ids[order] = np.concatenate(([0], np.cumsum(np.diff(t[order]) > gap_s)))
    return ids


def count_episodes(epoch: np.ndarray, flagged: np.ndarray, gap_s: float = EPISODE_GAP_S) -> int:
    ids = episode_ids(epoch, flagged, gap_s)
    return int(ids.max() + 1) if ids.size else 0


def counts_from_flags(flag: np.ndarray, y: np.ndarray, seg: np.ndarray, epoch: np.ndarray, stride: int = STRIDE_S,
                      cluster_s: int = CLUSTER_S) -> Counts:
    """Build the sufficient statistics from window arrays (all aligned). `seg` > 0 marks attack segments, `y` the attack label."""
    flag, y = np.asarray(flag, bool), np.asarray(y, bool)
    seg, epoch = np.asarray(seg), np.asarray(epoch, float)
    ids, n, hit, lat = [], [], [], []
    for s in np.unique(seg[y]):
        m = (seg == s) & y
        h = m & flag
        ids.append(int(s)), n.append(int(m.sum())), hit.append(int(h.sum()))
        lat.append(float(epoch[h].min() - epoch[m].min()) if h.any() else np.nan)
    ben = ~y
    cl = np.floor(epoch[ben] / cluster_s).astype(np.int64)
    bn, bfp, bep, bh = [], [], [], []
    be, bf = epoch[ben], flag[ben]
    for c in np.unique(cl):
        mc = cl == c
        bn.append(int(mc.sum())), bfp.append(int(bf[mc].sum())), bep.append(count_episodes(be[mc], bf[mc]))
        bh.append(mc.sum() * stride / 3600.0)
    ep_true = ep_total = None
    if flag.any():
        eid = episode_ids(epoch, flag)
        ep_total = int(eid.max() + 1)
        ep_true = int(np.unique(eid[y[flag]]).size)                      # eid is aligned with the flagged windows in input order
    else:
        ep_true = ep_total = 0
    return Counts(np.array(ids, int), np.array(n, np.int64), np.array(hit, np.int64), np.array(lat, float),
                  np.array(bn, np.int64), np.array(bfp, np.int64), np.array(bep, np.int64), np.array(bh, float), ep_true, ep_total)


def _f1(p: Optional[float], r: Optional[float]) -> Optional[float]:
    if r is None:
        return None
    if p is None:                       # no alarms at all: precision is undefined, nothing was caught, F1 is 0 by convention
        return 0.0
    return 0.0 if p + r == 0 else 2 * p * r / (p + r)


def _ratio(a: float, b: float) -> Optional[float]:
    return None if b <= 0 else float(a) / float(b)


def _r(v: Optional[float], nd: int = 4) -> Optional[float]:
    return None if v is None or (isinstance(v, float) and np.isnan(v)) else round(float(v), nd)


def metrics(c: Counts) -> Dict[str, Any]:
    """Every score family from one Counts. Values are rounded to 4 places; None where a ratio is undefined (no attacks / no alarms)."""
    A, tp = int(c.seg_n.sum()), int(c.seg_hit.sum())
    fp, nben = int(c.ben_fp.sum()), int(c.ben_n.sum())
    tn, fn = nben - fp, A - tp
    n = A + nben
    det = c.seg_hit > 0
    nseg, ndet = int(c.seg_id.size), int(det.sum())
    hours = float(c.ben_hours.sum())

    def family(tp_x: float) -> Dict[str, Optional[float]]:
        p, r = _ratio(tp_x, tp_x + fp), _ratio(tp_x, A)
        return {"precision": p, "recall": r, "f1": _f1(p, r), "accuracy": _ratio(tp_x + tn, n)}

    strict = family(tp)
    spec = _ratio(tn, nben)
    event_recall = _ratio(ndet, nseg)
    out: Dict[str, Any] = {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn, "attack_windows": A, "benign_windows": nben,
        "precision": _r(strict["precision"]), "recall": _r(strict["recall"]), "f1": _r(strict["f1"]), "accuracy": _r(strict["accuracy"]),
        "balanced_accuracy": _r((strict["recall"] + spec) / 2) if strict["recall"] is not None and spec is not None else None,
        "false_positive_rate": _r(1 - spec) if spec is not None else None,
        "always_benign_accuracy": _r(_ratio(nben, n)),
        "segments_detected": ndet, "segments_total": nseg, "event_recall": _r(event_recall),
        "composite_f1": _r(_f1(strict["precision"], event_recall)),
        "segment_balanced_recall": _r(float(np.mean(c.seg_hit / np.maximum(c.seg_n, 1))) if nseg else None),
        "median_latency_s": _r(float(np.nanmedian(c.seg_lat)) if det.any() else None, 1),
        "false_alarm_episodes_per_hour": _r(_ratio(float(c.ben_ep.sum()), hours), 3),
        "benign_hours": _r(hours, 2),
    }
    if c.ep_total is not None:
        out["alarm_episodes"] = int(c.ep_total)
        out["episode_precision"] = _r(_ratio(c.ep_true or 0, c.ep_total))
    pa = family(float(c.seg_n[det].sum()))
    out.update({"pa_precision": _r(pa["precision"]), "pa_recall": _r(pa["recall"]), "pa_f1": _r(pa["f1"]), "pa_accuracy": _r(pa["accuracy"])})
    for k in PAK_LEVELS:
        credited = np.where(c.seg_hit > (k / 100.0) * c.seg_n, c.seg_n, c.seg_hit)
        fk = family(float(credited.sum()))
        out[f"pak{k}_precision"], out[f"pak{k}_recall"], out[f"pak{k}_f1"] = _r(fk["precision"]), _r(fk["recall"]), _r(fk["f1"])
    return out


def bootstrap(c: Counts, n_boot: int = 2000, seed: int = 0, keys: Sequence[str] = CI_KEYS) -> Dict[str, Any]:
    """95 % percentile intervals by CLUSTER bootstrap: attack segments and benign hours are resampled with replacement (a window is not an
    independent unit). With only a few attacks the intervals are wide - that is the honest statement of how much the test can tell."""
    rng = np.random.default_rng(seed)
    ns, nb = c.seg_id.size, c.ben_n.size
    if ns == 0 or nb == 0:
        return {}
    samples: Dict[str, List[float]] = {k: [] for k in keys}
    for _ in range(n_boot):
        si, bi = rng.integers(0, ns, ns), rng.integers(0, nb, nb)
        m = metrics(Counts(c.seg_id[si], c.seg_n[si], c.seg_hit[si], c.seg_lat[si], c.ben_n[bi], c.ben_fp[bi], c.ben_ep[bi], c.ben_hours[bi]))
        for k in keys:
            if m.get(k) is not None:
                samples[k].append(m[k])
    out: Dict[str, Any] = {"n_boot": n_boot, "resampled": f"{ns} attack segments, {nb} benign clusters"}
    for k, v in samples.items():
        if len(v) >= max(20, n_boot // 10):
            lo, hi = np.percentile(v, [2.5, 97.5])
            out[k] = [round(float(lo), 4), round(float(hi), 4)]
        else:
            out[k] = None
    return out


def random_alarm_flags(n: int, p_flagged: float, run_len: float, rng: np.random.Generator) -> np.ndarray:
    """A chance-level alarm process with the SAME flagged-window share and the SAME mean alarm length as a reference detector:
    onsets arrive independently per window, each raises the alarm for `run_len` consecutive windows."""
    L = max(1, int(round(run_len)))
    p = float(np.clip(p_flagged, 0.0, 0.999))
    q = 1.0 - (1.0 - p) ** (1.0 / L)
    onset = (rng.random(n) < q).astype(np.int64)
    cs = np.concatenate(([0], np.cumsum(onset)))
    j = np.maximum(np.arange(n) - L + 1, 0)
    return (cs[np.arange(n) + 1] - cs[j]) > 0


def mean_run_length(flag: np.ndarray) -> float:
    f = np.asarray(flag, bool)
    if not f.any():
        return 1.0
    starts = int((f & ~np.concatenate(([False], f[:-1]))).sum())
    return float(f.sum()) / max(starts, 1)


def random_baseline(flag_ref: np.ndarray, y: np.ndarray, seg: np.ndarray, epoch: np.ndarray, trials: int = 200, seed: int = 0) -> Dict[str, Any]:
    """Score chance-level alarms (matched to `flag_ref`) under every scheme: mean and 2.5-97.5 percentile over `trials` draws.
    Windows must be in time order (the alarm length is measured along the array)."""
    rng = np.random.default_rng(seed)
    p, L = float(np.mean(flag_ref)), mean_run_length(flag_ref)
    rows = [metrics(counts_from_flags(random_alarm_flags(len(y), p, L, rng), y, seg, epoch)) for _ in range(trials)]
    out: Dict[str, Any] = {"trials": trials, "flagged_share": round(p, 5), "mean_alarm_length_windows": round(L, 2)}
    for k in rows[0]:
        vals = [r[k] for r in rows if r.get(k) is not None]
        if vals and isinstance(vals[0], (int, float)):
            out[k] = {"mean": round(float(np.mean(vals)), 4), "lo": round(float(np.percentile(vals, 2.5)), 4), "hi": round(float(np.percentile(vals, 97.5)), 4)}
    return out


def per_attack(c: Counts, stride: int = STRIDE_S) -> List[Dict[str, Any]]:
    return [{"segment": int(i), "attack_windows": int(n), "duration_s": int(n) * stride, "flagged_windows": int(h), "flagged_share": _r(h / n if n else None),
             "detected": bool(h > 0), "latency_s": _r(None if np.isnan(l) else float(l), 1)} for i, n, h, l in zip(c.seg_id, c.seg_n, c.seg_hit, c.seg_lat)]


def from_report_block(block: Dict[str, Any], benign_hours: float, window_stride: int = STRIDE_S) -> Counts:
    """Counts from a saved report block that kept per-segment aggregates ({tp, fp, fn, tn, per_segment[{segment, attack_windows,
    flagged_windows, latency_s}], alarm_episodes_per_benign_hour}). Benign side is ONE cluster, so a bootstrap of it is degenerate: the CI
    from such a Counts covers attack-side uncertainty only (and says so)."""
    segs = block["per_segment"]
    nben = block["fp"] + block["tn"]
    assert sum(s["attack_windows"] for s in segs) == block["tp"] + block["fn"], "per-segment windows do not add up to tp+fn"
    return Counts(np.array([s["segment"] for s in segs], int), np.array([s["attack_windows"] for s in segs], np.int64),
                  np.array([s["flagged_windows"] for s in segs], np.int64),
                  np.array([np.nan if s.get("latency_s") is None else s["latency_s"] for s in segs], float),
                  np.array([nben], np.int64), np.array([block["fp"]], np.int64),
                  np.array([int(round(block["alarm_episodes_per_benign_hour"] * benign_hours))], np.int64), np.array([benign_hours], float))


def scheme_table(m: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The rows every report shows, in the order: strict first, point-adjust last."""
    rows = [("strict (per window)", m["precision"], m["recall"], m["f1"], m["accuracy"])]
    rows.append(("composite (window precision, attack recall)", m["precision"], m["event_recall"], m["composite_f1"], None))
    for k in PAK_LEVELS:
        rows.append((f"PA%K, K={k}", m[f"pak{k}_precision"], m[f"pak{k}_recall"], m[f"pak{k}_f1"], None))
    rows.append(("point-adjust (literature comparison only)", m["pa_precision"], m["pa_recall"], m["pa_f1"], m["pa_accuracy"]))
    return [{"scheme": s, "precision": p, "recall": r, "f1": f, "accuracy": a} for s, p, r, f, a in rows]
