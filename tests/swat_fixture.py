"""Deterministic generator of a SYNTHETIC, SWaT-SHAPED archive (NOT real SWaT data).

Reproduces the structure/quirks of the real iTrust SWaT CSVs so a loader and a
training pipeline can be tested without the licensed dataset. Never cite anything
derived from this as real-data performance.

Usage:  python -m tests.swat_fixture <out_dir> [seed]
"""
import os
import sys
from datetime import datetime, timedelta

import numpy as np
import pandas as pd

TAGS = ("FIT101 LIT101 MV101 P101 P102 "
        "AIT201 AIT202 AIT203 FIT201 MV201 P201 P202 P203 P204 P205 P206 "
        "DPIT301 FIT301 LIT301 MV301 MV302 MV303 MV304 P301 P302 "
        "AIT401 AIT402 FIT401 LIT401 P401 P402 P403 P404 UV401 "
        "AIT501 AIT502 AIT503 AIT504 FIT501 FIT502 FIT503 FIT504 P501 P502 "
        "PIT501 PIT502 PIT503 FIT601 P601 P602 P603").split()
LABEL = "Normal/Attack"
LEADING_SPACE = {"FIT101", "P202", "AIT503"}
NAN_COLUMNS = ["MV101", "AIT201", "MV201", "P201", "P202", "P204", "MV303"]
VALVES = {"MV101", "MV201", "MV301", "MV302", "MV303", "MV304"}
PUMPS = {"P101", "P102", "P201", "P202", "P203", "P204", "P205", "P206", "P301", "P302",
         "P401", "P402", "P403", "P404", "P501", "P502", "P601", "P602", "P603", "UV401"}
DISCRETE = VALVES | PUMPS
CONST1 = {"P102", "P206", "P301", "P401", "P403", "P404", "P502", "P601", "P603"}
RARE_DIP = {"P402", "P501", "UV401"}
FAST_TOGGLE = ["P101", "P203", "P205", "P302", "MV302"]      # few toggles/hour normally
RATE = {"P101": 4, "P203": 4, "P205": 4, "P302": 4, "MV302": 4}  # others: 1/h
# tag: (mean, amplitude, noise, period_s)
SENSORS = {
    "FIT101": (1.3, 1.2, .02, 1800), "LIT101": (540, 260, .6, 4000),
    "AIT201": (250, 8, .3, 5000), "AIT202": (8.6, .25, .01, 6000),
    "AIT203": (320, 15, .5, 5500), "FIT201": (2.4, .08, .01, 2000),
    "DPIT301": (10, 9, .2, 1500), "FIT301": (2.2, .15, .01, 2500),
    "LIT301": (850, 120, 1, 3500), "AIT401": (148, 6, .3, 4500),
    "AIT402": (180, 35, .8, 4800), "FIT401": (1.7, .1, .01, 2700),
    "LIT401": (850, 120, 1, 3300), "AIT501": (7.4, .1, .005, 6000),
    "AIT502": (140, 60, 1, 5200), "AIT503": (260, 25, .6, 5800),
    "AIT504": (12, 6, .3, 4100), "FIT501": (1.75, .05, .01, 2300),
    "FIT502": (1.2, .05, .01, 2400), "FIT503": (.73, .03, .005, 2600),
    "FIT504": (.3, .02, .005, 2900), "PIT501": (251, 6, .4, 1900),
    "PIT502": (.2, .15, .02, 2100), "PIT503": (193, 5, .3, 2000),
    "FIT601": (.1, .1, .01, 3000),
}
SHIFTS = [("LIT301", 200.0), ("LIT401", -150.0), ("AIT402", 30.0), ("PIT501", 10.0),
          ("DPIT301", 5.0)]
SEG_PER_DATE = [9, 8, 4, 4, 5, 5]      # 28/12, 29/12, 30/12, 31/12, 1/1, 2/1  (17,4,4,5,5)
KIND_POOL = ["toggle"] * 14 + ["force_off"] * 7 + ["sensor_shift"] * 5 + ["subtle"] * 9
_E = datetime(1970, 1, 1)


def _ep(dt):
    return int((dt - _E).total_seconds())


def _fmt(e):
    dt = _E + timedelta(seconds=int(e))
    return "%d/%d/%d %d:%02d:%02d %s" % (dt.day, dt.month, dt.year, dt.hour % 12 or 12,
                                         dt.minute, dt.second, "AM" if dt.hour < 12 else "PM")


def _toggle_state(n, rate_h, rng, start=2):
    ev = rng.random(n) < rate_h / 3600.0
    return np.where(np.cumsum(ev) % 2 == 0, start, 3 - start).astype(np.int64)


def _valve_state(n, rate_h, rng):
    s = _toggle_state(n, rate_h, rng, 1)
    ch = np.flatnonzero(np.diff(s)) + 1
    for k in range(3):                       # 0 = ~3 s transitional state
        idx = ch + k
        s[idx[idx < n]] = 0
    return s


def _block(epoch, rng):
    """One period's 51 tag arrays (numpy)."""
    n = len(epoch)
    t = epoch.astype(np.float64)
    out = {}
    for tag in TAGS:
        if tag in SENSORS:
            m, a, nz, per = SENSORS[tag]
            v = m + a * np.sin(2 * np.pi * t / per + rng.random() * 6.28) + nz * rng.normal(size=n)
            out[tag] = np.round(np.clip(v, 0, None), 4)
        elif tag in CONST1:
            out[tag] = np.ones(n, dtype=np.int64)
        elif tag in RARE_DIP:
            s = np.full(n, 2, dtype=np.int64)
            if rng.random() < 0.5:
                p = int(rng.integers(0, max(1, n - 20)))
                s[p:p + 20] = 1
            out[tag] = s
        elif tag in VALVES:
            out[tag] = _valve_state(n, RATE.get(tag, 1), rng)
        else:
            out[tag] = _toggle_state(n, RATE.get(tag, 1), rng)
    return out


def _chunk_epochs(starts, n):
    return np.concatenate([np.arange(_ep(s), _ep(s) + n, dtype=np.int64) for s in starts])


def _plan_segments(rng, n_chunk):
    kinds = [str(k) for k in rng.permutation(KIND_POOL)]
    segs, sid = [], 0
    for i, k in enumerate(SEG_PER_DATE):
        lens = rng.integers(100, 901, k)
        if i == 3:                           # 31/12: one long ~3000 s segment
            lens[0] = 3000
            lens[1:] = rng.integers(100, 600, k - 1)
        budget = n_chunk - 60 * (k + 1)
        if lens.sum() > budget:
            lens = np.maximum(20, lens * budget // lens.sum())
        slack = max(0, n_chunk - int(lens.sum()) - 60 * (k + 1))
        w = rng.random(k + 1) + 0.05
        gaps = 60 + (slack * w / w.sum()).astype(int)
        pos = i * n_chunk + int(gaps[0])
        for j in range(k):
            s, e = pos, pos + int(lens[j])
            sid += 1
            segs.append({"id": sid, "s": s, "e": e, "date_i": i, "kind": kinds[sid - 1]})
            pos = e + int(gaps[j + 1])
    return segs


def _overwrite_toggle(arr, s, e, rng, valve):
    t, state = s, 2
    while t < e:
        dur = int(rng.integers(5, 26))
        arr[t:min(t + dur, e)] = state
        if valve:
            arr[t:min(t + 3, e)] = 0
        state = 3 - state
        t += dur


def make_swat_archive(out_dir, seed=0, hours_per_day=1.5, dup_identical=True):
    assert hours_per_day >= 0.25
    rng = np.random.default_rng(seed)
    os.makedirs(out_dir, exist_ok=True)
    n_chunk = int(hours_per_day * 3600)

    # ---- normal period: 22/12 16:00 -> 28/12 09:59:59 (one chunk per date) ----
    nstarts = [datetime(2015, 12, 22, 16)] + [datetime(2015, 12, d, 10) for d in range(23, 28)]
    nstarts.append(datetime(2015, 12, 28, 10) - timedelta(seconds=n_chunk))
    ep_n = _chunk_epochs(nstarts, n_chunk)
    blk_n = _block(ep_n, rng)

    # ---- attack period: 28/12 10:00 -> 02/01 14:59:59 ----
    astarts = [datetime(2015, 12, 28, 10), datetime(2015, 12, 29, 10), datetime(2015, 12, 30, 10),
               datetime(2015, 12, 31, 10), datetime(2016, 1, 1, 10),
               datetime(2016, 1, 2, 15) - timedelta(seconds=n_chunk)]
    ep_a = _chunk_epochs(astarts, n_chunk)
    blk_a = _block(ep_a, rng)
    is_att = np.zeros(len(ep_a), dtype=bool)

    segs_out = []
    for sg in _plan_segments(rng, n_chunk):
        s, e, kind = sg["s"], sg["e"], sg["kind"]
        acts, extra = [], {}
        if kind == "toggle":
            tag = FAST_TOGGLE[int(rng.integers(len(FAST_TOGGLE)))]
            _overwrite_toggle(blk_a[tag], s, e, rng, tag in VALVES)
            acts = [tag]
        elif kind == "force_off":
            tag = sorted(RARE_DIP)[int(rng.integers(3))]
            blk_a[tag][s:e] = 1
            acts = [tag]
        elif kind == "sensor_shift":
            tag, d = SHIFTS[int(rng.integers(len(SHIFTS)))]
            blk_a[tag][s:e] = blk_a[tag][s:e] + d
            extra = {"sensor": tag, "delta": d}
        is_att[s:e] = True
        d0 = _E + timedelta(seconds=int(ep_a[s]))
        segs_out.append(dict(id=sg["id"], start=_fmt(ep_a[s]), end=_fmt(ep_a[e - 1]),
                             rows=e - s, date="%d/%d/%d" % (d0.day, d0.month, d0.year),
                             kind=kind, actuators=acts, **extra))

    def to_df(epoch, blk, nan_cols, label):
        data = {"Timestamp": [_fmt(e) for e in epoch]}
        n = len(epoch)
        for tag in TAGS:
            if tag in nan_cols:
                data[tag] = (pd.array([pd.NA] * n, dtype="Int64") if tag in DISCRETE
                             else np.full(n, np.nan))
            elif tag in DISCRETE:
                data[tag] = pd.array(blk[tag], dtype="Int64")
            else:
                data[tag] = blk[tag]
        data[LABEL] = label
        return pd.DataFrame(data)

    df_np = to_df(ep_n, blk_n, set(NAN_COLUMNS), "Normal")
    df_a = to_df(ep_a, blk_a, set(), np.where(is_att, "Attack", "Normal"))
    att_rows = df_a[is_att]
    att_normal = df_a[~is_att]
    copy_a = df_np
    copy_b = df_np.iloc[1800:].copy().reset_index(drop=True)   # starts 30 min later
    if not dup_identical:
        r = np.random.default_rng(seed + 1)
        for i in r.choice(len(copy_b), 5, replace=False):
            copy_b.loc[i, "LIT101"] = copy_b.loc[i, "LIT101"] + 1.5
    normal = pd.concat([att_normal, copy_a, copy_b], ignore_index=True)

    header = ["Timestamp"] + [(" " + t if t in LEADING_SPACE else t) for t in TAGS] + [LABEL]
    p_n, p_a, p_m = (os.path.join(out_dir, f) for f in ("normal.csv", "attack.csv", "merged.csv"))
    normal.to_csv(p_n, index=False, header=header, lineterminator="\n")
    att_rows.to_csv(p_a, index=False, header=header, lineterminator="\n")
    with open(p_n, "rb") as f:
        nb = f.read()
    with open(p_a, "rb") as f:
        ab = f.read()
    with open(p_m, "wb") as f:                      # merged = normal rows + attack rows
        f.write(nb + ab[ab.index(b"\n") + 1:])

    return {"segments": segs_out, "n_segments": len(segs_out),
            "n_rows": {"normal": len(normal), "attack": len(att_rows),
                       "merged": len(normal) + len(att_rows)},
            "duplicate_timestamps": int(normal["Timestamp"].duplicated().sum()),
            "nan_columns": list(NAN_COLUMNS)}


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: python -m tests.swat_fixture <out_dir> [seed]")
    t = make_swat_archive(sys.argv[1], seed=int(sys.argv[2]) if len(sys.argv) > 2 else 0)
    print({k: v for k, v in t.items() if k != "segments"})
