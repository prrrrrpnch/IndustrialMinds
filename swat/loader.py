"""
swat/loader.py - build ONE clean chronological stream from the local SWaT archive.

The archive (see CLAUDE.md "SWaT archive facts") ships as normal.csv / attack.csv / merged.csv
that are NOT chronological, where normal.csv holds the 22-28 Dec normal period twice. This module:

  1. reads normal.csv + attack.csv (merged.csv is only their concatenation; it is used alone
     only if the other two are missing), parsing '%d/%m/%Y %I:%M:%S %p' timestamps strictly;
  2. sorts by time and DE-DUPLICATES identical timestamps, recording whether the copies were
     exact duplicates or conflicted (a conflict keeps the Attack-labelled row, else the first);
  3. cuts the stream into CHUNKS wherever consecutive rows are > gap_s apart (feature state must
     never be carried across missing data);
  4. numbers the ATTACK SEGMENTS (maximal runs of attack rows inside one chunk);
  5. assigns each row to a held-out BLOCK by calendar date (a segment goes wholly to the block of
     its first row), so a split never cuts an attack in two and never shuffles rows.

Nothing here is written back to disk; the licensed data never leaves the folder it is in.
"""

from __future__ import annotations

import os
import re
from datetime import date, datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

import numpy as np
import pandas as pd

TS_FORMAT = "%d/%m/%Y %I:%M:%S %p"
ATTACK_PERIOD_START = datetime(2015, 12, 28, 10, 0, 0)

# Calendar-block split agreed at the Phase 4 gate:
#   train 22-29 Dec 2015, validation 30-31 Dec 2015, test 1-2 Jan 2016.
DEFAULT_BLOCKS: List[Tuple[str, date]] = [("train", date(2015, 12, 29)), ("val", date(2015, 12, 31)), ("test", date(2016, 1, 2))]

LABEL_COL = "Normal/Attack"


class SwatDataError(RuntimeError):
    pass


def _find(data_dir: str, name: str) -> Optional[str]:
    for f in os.listdir(data_dir):
        if f.lower() == name:
            return os.path.join(data_dir, f)
    return None


def _label_to_bool(s: pd.Series) -> Tuple[np.ndarray, Dict[str, int]]:
    """'Normal'/'Attack' (and SWaT's historical 'A ttack' typo, 0/1 spellings) -> bool."""
    counts = {str(k): int(v) for k, v in s.value_counts(dropna=False).items()}
    key = s.astype(str).str.lower().str.replace(r"\s+", "", regex=True)
    attack = key.isin({"attack", "1", "1.0", "true", "anomaly", "abnormal"})
    normal = key.isin({"normal", "0", "0.0", "false", "benign"})
    if (~(attack | normal)).any():
        raise SwatDataError(f"unrecognised label spellings: {counts}")
    return attack.to_numpy(), counts


def _read_one(path: str, value_columns: Iterable[str]) -> pd.DataFrame:
    head = pd.read_csv(path, nrows=0, skipinitialspace=True)
    raw_names = {str(c).strip(): c for c in head.columns}
    ts_name = next((k for k in raw_names if k.lower() == "timestamp"), None)
    if ts_name is None or LABEL_COL not in raw_names:
        raise SwatDataError(f"{path}: need 'Timestamp' and '{LABEL_COL}' columns, found {list(raw_names)[:6]}...")
    want = [c for c in value_columns if c in raw_names]
    missing = [c for c in value_columns if c not in raw_names]
    if missing:
        raise SwatDataError(f"{path}: columns not found: {missing}")
    df = pd.read_csv(path, usecols=[raw_names[ts_name], raw_names[LABEL_COL]] + [raw_names[c] for c in want],
                     low_memory=False, skipinitialspace=True)
    df.columns = [str(c).strip() for c in df.columns]
    df = df.rename(columns={ts_name: "ts"})
    stamp = pd.to_datetime(df["ts"].astype(str).str.strip(), format=TS_FORMAT, errors="coerce")
    bad = int(stamp.isna().sum())
    if bad:
        raise SwatDataError(f"{path}: {bad} timestamps do not match {TS_FORMAT!r}")
    df["ts"] = stamp
    for c in want:
        df[c] = pd.to_numeric(df[c], errors="coerce").astype(np.float32)
    df["label"], _ = _label_to_bool(df[LABEL_COL])
    return df.drop(columns=[LABEL_COL])


def block_of(d: date, blocks: List[Tuple[str, date]]) -> str:
    for name, last_day in blocks:
        if d <= last_day:
            return name
    return blocks[-1][0]


def load_stream(data_dir: str, columns: Iterable[str], gap_s: float = 5.0,
                blocks: Optional[List[Tuple[str, date]]] = None) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Returns (stream, info). stream columns:
      ts (datetime64), epoch (float seconds), label (bool), seg (0 = normal, 1..K attack segment),
      chunk (int, new id after any gap > gap_s), block ('train'/'val'/'test'),
      period ('normal_period'/'attack_period'), plus the requested value columns (float32).
    """
    blocks = blocks or DEFAULT_BLOCKS
    columns = list(columns)
    if not os.path.isdir(data_dir):
        raise SwatDataError(f"not a directory: {data_dir}")
    normal, attack, merged = (_find(data_dir, n) for n in ("normal.csv", "attack.csv", "merged.csv"))
    if normal and attack:
        paths = [normal, attack]
    elif merged:
        paths = [merged]
    else:
        raise SwatDataError(f"{data_dir}: need normal.csv + attack.csv (or merged.csv)")

    frames = []
    info: Dict[str, Any] = {"files": {}}
    for order, p in enumerate(paths):
        f = _read_one(p, columns)
        f["_src"], f["_row"] = order, np.arange(len(f))
        info["files"][os.path.basename(p)] = {"rows": int(len(f)), "attack_rows": int(f["label"].sum())}
        frames.append(f)
    df = pd.concat(frames, ignore_index=True)
    info["rows_read"] = int(len(df))

    # chronological; on identical timestamps the ATTACK-labelled row sorts first
    df["_nl"] = ~df["label"]
    df = df.sort_values(["ts", "_nl", "_src", "_row"], kind="mergesort").reset_index(drop=True)

    # ---- de-duplicate identical timestamps -------------------------------------------------
    value_cols = [c for c in columns]
    ts_dup = df.duplicated(subset=["ts"], keep="first")
    full_dup = df.duplicated(subset=["ts", "label"] + value_cols, keep="first")
    info["duplicate_timestamps_dropped"] = int(ts_dup.sum())
    info["duplicates_exact"] = int((ts_dup & full_dup).sum())
    info["duplicates_conflicting"] = int((ts_dup & ~full_dup).sum())
    df = df[~ts_dup].reset_index(drop=True)
    info["rows"] = int(len(df))

    df["epoch"] = (df["ts"] - pd.Timestamp("1970-01-01")).dt.total_seconds()
    dt = df["epoch"].diff()
    df["chunk"] = (dt > gap_s).cumsum().astype(np.int32)
    info["chunks"] = int(df["chunk"].nunique())
    info["largest_gap_s"] = float(dt.max()) if len(dt) > 1 else 0.0

    # ---- attack segments: runs of attack rows inside one chunk ---------------------------------
    lab = df["label"].to_numpy()
    new_run = np.zeros(len(df), bool)
    new_run[0] = lab[0]
    new_run[1:] = lab[1:] & (~lab[:-1] | (df["chunk"].to_numpy()[1:] != df["chunk"].to_numpy()[:-1]))
    seg = np.cumsum(new_run) * lab
    df["seg"] = seg.astype(np.int32)
    info["n_segments"] = int(seg.max())

    # ---- blocks: by calendar date; a segment goes wholly to the block of its first row ----------
    row_block = df["ts"].dt.date.map(lambda d: block_of(d, blocks))
    seg_first = df[df["seg"] > 0].groupby("seg").head(1)
    seg_block = {int(r.seg): block_of(r.ts.date(), blocks) for r in seg_first.itertuples()}
    df["block"] = np.where(df["seg"] > 0, df["seg"].map(seg_block).fillna(row_block), row_block)
    df["period"] = np.where(df["ts"] >= pd.Timestamp(ATTACK_PERIOD_START), "attack_period", "normal_period")

    segs: List[Dict[str, Any]] = []
    crossing = 0
    for sid, g in df[df["seg"] > 0].groupby("seg"):
        if g["ts"].dt.date.nunique() > 1:
            crossing += 1
        segs.append({"id": int(sid), "start": str(g["ts"].iloc[0]), "end": str(g["ts"].iloc[-1]), "rows": int(len(g)),
                     "block": seg_block[int(sid)]})
    info["segments"] = segs
    info["segments_crossing_midnight"] = crossing
    info["blocks"] = {b: {"rows": int((df["block"] == b).sum()), "attack_rows": int(((df["block"] == b) & df["label"]).sum()),
                          "segments": int(sum(1 for s in segs if s["block"] == b))} for b, _ in blocks}
    info["nan_share"] = {c: round(float(df[c].isna().mean()), 4) for c in value_cols if df[c].isna().any()}

    keep = ["ts", "epoch", "label", "seg", "chunk", "block", "period"] + value_cols
    return df[keep], info
