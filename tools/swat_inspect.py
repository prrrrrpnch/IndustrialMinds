#!/usr/bin/env python3
"""
tools/swat_inspect.py - Phase 4 inspection of a locally stored SWaT download.

Run it ON THE MACHINE THAT HOLDS THE DATA (nothing is uploaded anywhere):

    python tools/swat_inspect.py "C:\\IndustrialMind\\SWaT_dataset\\archive"
    python tools/swat_inspect.py "C:\\IndustrialMind\\SWaT_dataset\\archive" --out inspect_out --hash

Needs: python 3.8+, pandas, numpy, and openpyxl only if the files are .xlsx
(xlsx files with ~450k rows take a few minutes to read; CSV is much faster).

What it answers (the Phase 4 questions):
  1. which files are present (sizes, optional sha256)
  2. columns, per-column ranges measured on NORMAL rows, and the discrete states of actuators
  3. label scheme, row counts, attack windows (start/end/duration, most-deviating columns)
  4. the attack list, if present: attack count, target points, SS/MS-SP/MP class
  5. which of this project's 20 twin tags exist in the data
  6. whether ANY network-level information exists (pcap files, Modbus/CIP/IP/port/function-code
     columns) - this decides how the cyber-model feature adapter can be built

LICENSE NOTE: the report contains only aggregate statistics, column names, counts and tag names.
It never prints raw data rows and never includes attack-list descriptions, so it is safe to paste
back. Do not paste or commit the dataset itself (iTrust terms forbid redistribution).

Outputs (in --out, default ./swat_inspection):  swat_inspection_report.txt  swat_manifest.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

# The 20 points of this project's twin (docs/interfaces.py) - SWaT tag names.
OUR_TAGS = ["MV101", "P101", "LIT101", "FIT101", "P203", "P205", "AIT202", "FIT201",
            "MV302", "P302", "LIT301", "DPIT301", "P401", "UV401", "LIT401", "AIT402",
            "P501", "MV503", "PIT501", "FIT501"]

TAG_RE = re.compile(r"\b([A-Za-z]{1,5})\s*-?\s*(\d{3})\b")
TABLE_EXT = {".csv", ".xlsx", ".xls", ".txt"}
NETWORK_FILE_EXT = {".pcap", ".pcapng", ".cap", ".argus", ".bro", ".zeek", ".tshark", ".nfcapd"}
NETWORK_COL_WORDS = ["modbus", "cip", "enip", "protocol", "proto", "src", "dst", "srcip", "dstip",
                     "ip_", "port", "packet", "pkt", "frame", "function", "funccode", "fc_",
                     "flag", "tcp", "udp", "bytes", "length", "payload", "mac", "latency", "rtt"]
STAMP_FORMATS = ["%d/%m/%Y %I:%M:%S %p", "%Y-%m-%d %H:%M:%S", "%d/%m/%Y %H:%M:%S",
                 "%m/%d/%Y %I:%M:%S %p", "%Y-%m-%d %H:%M:%S.%f", "%d-%m-%Y %H:%M:%S"]

OUT: List[str] = []


def emit(line: str = "") -> None:
    print(line)
    OUT.append(line)


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:,.1f} {unit}"
        n /= 1024.0
    return str(n)


# --------------------------------------------------------------------------- loading
def _detect_header_row(raw: pd.DataFrame) -> int:
    """SWaT files sometimes have a blank/title row above the header."""
    for i in range(min(len(raw), 6)):
        cells = [str(c).strip().lower() for c in raw.iloc[i].tolist()]
        hits = sum(1 for c in cells if c == "timestamp" or c in {t.lower() for t in OUR_TAGS})
        if hits >= 1:
            return i
    return 0


def load_table(path: Path) -> pd.DataFrame:
    ext = path.suffix.lower()
    if ext in (".xlsx", ".xls"):
        raw = pd.read_excel(path, header=None, nrows=6)
        hdr = _detect_header_row(raw)
        df = pd.read_excel(path, header=hdr)
    else:
        raw = pd.read_csv(path, header=None, nrows=6, low_memory=False, skipinitialspace=True,
                          on_bad_lines="skip", encoding_errors="replace")
        hdr = _detect_header_row(raw)
        df = pd.read_csv(path, header=hdr, low_memory=False, skipinitialspace=True,
                         on_bad_lines="skip", encoding_errors="replace")
    df.columns = [str(c).strip() for c in df.columns]
    return df


def parse_timestamps(s: pd.Series) -> Tuple[Optional[pd.Series], str]:
    """Returns (parsed series or None, description of the chosen format / ambiguity)."""
    txt = s.astype(str).str.strip()
    step = max(1, len(txt) // 20000)
    sample = txt.iloc[::step]
    ratios = {fmt: float(pd.to_datetime(sample, format=fmt, errors="coerce").notna().mean()) for fmt in STAMP_FORMATS}
    best = max(ratios, key=lambda k: ratios[k])
    if ratios[best] > 0.95:
        good = [f for f, r in ratios.items() if r > 0.95]
        note = f"format {best!r}" + (f"  AMBIGUOUS: {good} all parse (day/month order cannot be told from the data)"
                                    if len(good) > 1 else "")
        return pd.to_datetime(txt, format=best, errors="coerce"), note
    out = pd.to_datetime(txt, dayfirst=True, errors="coerce")
    ok = float(out.notna().mean())
    return (out if ok > 0.5 else None), f"fallback dayfirst parser, {ok:.0%} parsed; best fixed-format ratios {max(ratios.values()):.0%}"


def find_label_column(df: pd.DataFrame) -> Optional[str]:
    names = {"normal/attack", "label", "class", "attack", "normal", "target", "y", "attack_label"}
    for c in df.columns:
        if c.lower() in names or "normal/attack" in c.lower():
            return c
    for c in df.columns:
        if df[c].dtype == object and 1 < df[c].nunique(dropna=True) <= 6:
            return c
    return None


def label_to_bool(s: pd.Series) -> Tuple[np.ndarray, Dict[str, int]]:
    """Normalise label spellings (SWaT famously contains 'A ttack')."""
    counts: Dict[str, int] = {str(k): int(v) for k, v in s.value_counts(dropna=False).items()}
    key = s.astype(str).str.lower().str.replace(r"\s+", "", regex=True)
    attack = key.isin({"attack", "1", "1.0", "true", "anomaly", "abnormal"})
    normal = key.isin({"normal", "0", "0.0", "false", "benign"})
    other = ~(attack | normal)
    if other.any():
        counts["<unrecognised spellings>"] = int(other.sum())
    return attack.to_numpy(), counts


# --------------------------------------------------------------------------- analysis
def runs(mask: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
    m = np.concatenate(([0], mask.astype(np.int8), [0]))
    d = np.diff(m)
    return np.where(d == 1)[0], np.where(d == -1)[0] - 1


def merge_runs(starts: np.ndarray, ends: np.ndarray, gap: int) -> List[Tuple[int, int]]:
    out: List[List[int]] = []
    for s, e in zip(starts.tolist(), ends.tolist()):
        if out and s - out[-1][1] - 1 <= gap:
            out[-1][1] = e
        else:
            out.append([s, e])
    return [(a, b) for a, b in out]


def stage_of(tag: str) -> Optional[int]:
    m = re.search(r"(\d)\d\d$", tag)
    return int(m.group(1)) if m else None


def segments_of(attack: np.ndarray, ts: Optional[pd.Series], args: argparse.Namespace) -> List[Tuple[int, int]]:
    """Attack segments = runs of attack rows, broken by row gaps (> merge-gap) or by TIMESTAMP gaps
    (> seg-gap seconds, which is how an attack-only file separates its windows)."""
    idx = np.flatnonzero(attack)
    if idx.size == 0:
        return []
    brk = (np.diff(idx) - 1) > args.merge_gap
    if ts is not None:
        t = ts.to_numpy()[idx]
        dt = np.diff(t).astype("timedelta64[s]").astype(float)
        brk |= np.abs(np.nan_to_num(dt, nan=0.0)) > args.seg_gap
    cut = np.flatnonzero(brk)
    starts = idx[np.concatenate(([0], cut + 1))]
    ends = idx[np.concatenate((cut, [len(idx) - 1]))]
    return list(zip(starts.tolist(), ends.tolist()))


def report_segments(name: str, num: pd.DataFrame, ts: Optional[pd.Series], attack: np.ndarray, base: Dict[str, Any],
                    info: Dict[str, Any], args: argparse.Namespace) -> None:
    segs = segments_of(attack, ts, args)
    emit(f"  ATTACK SEGMENTS (attack rows split by row gaps > {args.merge_gap} or time gaps > {args.seg_gap}s): {len(segs)}")
    mu, sd, lo, hi = base["mu"], base["sd"], base["lo"], base["hi"]
    wins: List[Dict[str, Any]] = []
    emit(f"    {'#':>3s} {'start':19s} {'end':19s} {'rows':>6s} {'#|z|>3':>6s} {'class*':7s} most-shifted columns (z vs NORMAL baseline from {base['source']})")
    for i, (s0, e0) in enumerate(segs, 1):
        z = ((num.iloc[s0:e0 + 1].mean() - mu) / sd).dropna()
        order = z.abs().sort_values(ascending=False).index
        top = z.reindex(order)[:3]
        shifted = [c for c in z.index if abs(z[c]) > 3.0]
        stages = {stage_of(c) for c in shifted if stage_of(c) is not None}
        cls = ("SS" if len(stages) <= 1 else "MS") + "-" + ("SP" if len(shifted) <= 1 else "MP")
        t0 = str(ts.iloc[s0]) if ts is not None else f"row {s0}"
        t1 = str(ts.iloc[e0]) if ts is not None else f"row {e0}"
        wins.append({"index": i, "start_row": int(s0), "end_row": int(e0), "rows": int(e0 - s0 + 1), "start": t0, "end": t1,
                     "n_columns_shifted_gt3sd": len(shifted), "stages_shifted": sorted(stages), "derived_class": cls,
                     "top_shifted": {k: float(v) for k, v in top.items()}})
        if i <= args.max_windows:
            tops = ", ".join(f"{k}({v:+.1f})" for k, v in top.items())
            emit(f"    {i:3d} {t0:19.19s} {t1:19.19s} {e0 - s0 + 1:6d} {len(shifted):6d} {cls:7s} {tops}")
    if len(wins) > args.max_windows:
        emit(f"    ... {len(wins) - args.max_windows} more segments in the JSON manifest")
    emit("    * class is DERIVED from this data (columns shifted > 3 sd from normal; SS/MS = single/multi stage, "
         "SP/MP = single/multi point) - it is not the official attack list")
    if wins:
        durs = [w["rows"] for w in wins]
        emit(f"  segment length (rows ~ seconds): min {min(durs)}, median {int(np.median(durs))}, max {max(durs)}")
    info["attack_segments"] = wins

    # regime-confound indicator: how many attack rows sit outside the normal envelope, column by column
    att = num[attack]
    outside = ((att.lt(lo)) | (att.gt(hi))).mean().sort_values(ascending=False)
    emit("  fraction of ATTACK rows outside the NORMAL [p0.5, p99.5] envelope, top 10 columns "
         "(high = attack rows come from a different operating regime than normal -> leakage risk):")
    emit("    " + ", ".join(f"{k}:{v:.0%}" for k, v in outside[:10].items()))
    zall = ((att.mean() - mu) / sd).dropna()
    emit("  mean shift of all attack rows (z, top 8): " + ", ".join(
        f"{k}({zall[k]:+.1f})" for k in zall.abs().sort_values(ascending=False).index[:8]))
    info["attack_vs_normal_envelope_top10"] = {k: float(v) for k, v in outside[:10].items()}


def analyse_data(name: str, df: pd.DataFrame, report: Dict[str, Any], args: argparse.Namespace,
                 state: Dict[str, Any]) -> None:
    info: Dict[str, Any] = {"rows": int(len(df)), "columns": list(df.columns)}
    emit(f"  rows={len(df):,}  columns={len(df.columns)}")

    ts_col = next((c for c in df.columns if "time" in c.lower()), None)
    ts, ts_note = (None, "no timestamp column")
    if ts_col:
        ts, ts_note = parse_timestamps(df[ts_col])
        raw = df[ts_col].astype(str).str.strip()
        emit(f"  timestamp col '{ts_col}': {ts_note}")
        emit(f"    raw samples (first 2 / last 2): {raw.iloc[:2].tolist()} ... {raw.iloc[-2:].tolist()}")
    if ts is not None:
        d = ts.diff().dt.total_seconds().dropna()
        med = float(d.median()) if len(d) else float("nan")
        big = d[d > max(1.5 * med, 1.5)]
        back = int((d < 0).sum())
        info["timestamp"] = {"column": ts_col, "note": ts_note, "first": str(ts.iloc[0]), "last": str(ts.iloc[-1]),
                             "min": str(ts.min()), "max": str(ts.max()), "median_step_s": med, "gaps_over_1.5x": int(len(big)),
                             "max_gap_s": float(d.max()) if len(d) else None, "backwards_steps": back,
                             "unparsed": int(ts.isna().sum())}
        emit(f"    first {ts.iloc[0]}  last {ts.iloc[-1]}  | min {ts.min()}  max {ts.max()}  | unparsed {int(ts.isna().sum()):,}")
        emit(f"    median step {med:g}s  forward gaps>1.5x: {len(big)}  max gap {info['timestamp']['max_gap_s']:g}s  "
             f"BACKWARD steps (non-monotonic): {back}")
        per_day = ts.dt.date.value_counts().sort_index()
        info["rows_per_date"] = {str(k): int(v) for k, v in per_day.items()}
        shown = [f"{k}:{v:,}" for k, v in per_day.items()]
        emit(f"    rows per calendar date ({len(per_day)} dates): " + " ".join(shown[:40]) + (" ..." if len(shown) > 40 else ""))

    lab_col = find_label_column(df)
    attack = None
    if lab_col:
        attack, counts = label_to_bool(df[lab_col])
        info["label"] = {"column": lab_col, "raw_value_counts": counts,
                         "attack_rows": int(attack.sum()), "normal_rows": int((~attack).sum())}
        emit(f"  label col '{lab_col}': raw values {counts}")
        emit(f"    -> attack rows {int(attack.sum()):,}, other rows {int((~attack).sum()):,}")
    else:
        emit("  label col: NONE FOUND (cannot derive attack windows from this file)")

    num_cols = [c for c in df.columns if c not in (ts_col, lab_col)]
    num = df[num_cols].apply(pd.to_numeric, errors="coerce")
    bad = [c for c in num_cols if num[c].isna().mean() > 0.5]
    categorical: Dict[str, Any] = {}
    for c in bad:
        fixed = pd.to_numeric(df[c].astype(str).str.strip().str.replace(",", ".", regex=False), errors="coerce")
        if fixed.notna().mean() > 0.9:
            num[c] = fixed
            emit(f"  column {c}: recovered as numeric after whitespace/decimal-comma cleanup")
            continue
        vc = df[c].astype(str).str.strip().value_counts(dropna=False)
        categorical[c] = {str(k): int(v) for k, v in vc[:10].items()}
        emit(f"  NON-NUMERIC column {c}: {len(vc)} distinct raw values; top: {categorical[c]}")
    info["non_numeric_columns"] = categorical
    num = num.drop(columns=list(categorical))

    base_mask = ~attack if attack is not None else np.ones(len(df), bool)
    base_df = num[base_mask]
    n_base = int(base_mask.sum())
    emit(f"  per-column statistics measured on {'NORMAL-labelled' if attack is not None else 'ALL'} rows ({n_base:,})"
         + (" [table omitted by --brief; see JSON]:" if args.brief else ":"))
    if not args.brief and n_base:
        emit(f"    {'column':10s} {'uniq':>5s} {'min':>9s} {'p0.5':>9s} {'p99.5':>9s} {'max':>9s} {'mean':>9s} {'std':>9s}  states(if <=6 values)")
    cols: Dict[str, Any] = {}
    near_const: List[str] = []
    for c in num.columns:
        x = base_df[c].dropna()
        if x.empty:
            continue
        uniq = int(num[c].nunique(dropna=True))
        st = {"unique": uniq, "min": float(x.min()), "p0.5": float(x.quantile(0.005)),
              "p99.5": float(x.quantile(0.995)), "max": float(x.max()),
              "mean": float(x.mean()), "std": float(x.std(ddof=0))}
        states = ""
        if uniq <= 6:
            vc = num[c].value_counts(dropna=True).sort_index()
            st["state_counts_all_rows"] = {str(k): int(v) for k, v in vc.items()}
            states = " ".join(f"{k:g}:{v:,}" for k, v in vc.items())
            if vc.max() / vc.sum() >= 0.995:
                near_const.append(c)
        cols[c] = st
        if not args.brief:
            emit(f"    {c:10s} {uniq:5d} {st['min']:9.2f} {st['p0.5']:9.2f} {st['p99.5']:9.2f} {st['max']:9.2f} "
                 f"{st['mean']:9.2f} {st['std']:9.2f}  {states}")
    info["columns_stats"] = cols
    info["near_constant_discrete_columns"] = near_const
    emit(f"  discrete columns that are >=99.5% one state (little information): {near_const or 'none'}")

    present = [t for t in OUR_TAGS if t in cols]
    missing = [t for t in OUR_TAGS if t not in cols]
    gone = [t for t in missing if t in categorical]
    emit(f"  this project's 20 twin tags: {len(present)} numeric; not numeric-usable: {missing or 'none'}"
         + (f" (of which present but non-numeric: {gone})" if gone else ""))
    info["twin_tags_present"], info["twin_tags_missing"] = present, missing
    by_stage: Dict[int, List[str]] = {}
    for c in list(cols) + list(categorical):
        st_ = stage_of(c)
        if st_ is not None:
            by_stage.setdefault(st_, []).append(c)
    emit("  columns by SWaT stage (numeric + non-numeric): " + "; ".join(f"P{k}: {len(v)}" for k, v in sorted(by_stage.items())))
    info["columns_by_stage"] = {f"P{k}": sorted(v) for k, v in by_stage.items()}

    # normal-baseline for z-scores: first file with plenty of normal rows
    if "base" not in state and n_base >= 1000:
        mu, sd = base_df.mean(), base_df.std(ddof=0).replace(0, np.nan)
        state["base"] = {"mu": mu, "sd": sd, "lo": base_df.quantile(0.005), "hi": base_df.quantile(0.995), "source": name}
    if attack is not None and attack.any():
        if "base" in state:
            report_segments(name, num, ts, attack, state["base"], info, args)
        else:
            state.setdefault("deferred", []).append((name, num.copy(), ts, attack.copy(), info))
            emit("  (attack segments for this file are reported after a file with NORMAL rows has been read)")
    report["data_files"][name] = info


def analyse_attack_list(name: str, df: pd.DataFrame, report: Dict[str, Any]) -> None:
    emit(f"  attack-list-like table: {len(df)} rows; columns: {list(df.columns)}")
    point_cols = [c for c in df.columns if "point" in c.lower()] or list(df.columns)
    classes: Dict[str, int] = {}
    per: List[Dict[str, Any]] = []
    for i, row in df.iterrows():
        text = " ".join(str(row[c]) for c in point_cols if pd.notna(row[c]))
        tags = sorted({(m.group(1).upper() + m.group(2)) for m in TAG_RE.finditer(text)})
        if not tags:
            continue
        stages = {stage_of(t) for t in tags}
        cls = ("SS" if len(stages) == 1 else "MS") + "-" + ("SP" if len(tags) == 1 else "MP")
        classes[cls] = classes.get(cls, 0) + 1
        per.append({"row": int(i), "tags": tags, "class": cls})
    emit(f"  attacks with identifiable target tags: {len(per)}; class counts (SS/MS = single/multi stage, "
         f"SP/MP = single/multi point): {classes}")
    for p in per[: 60]:
        emit(f"    row {p['row']:3d}: {p['class']}  {' '.join(p['tags'])}")
    report["attack_list"][name] = {"rows": int(len(df)), "columns": list(df.columns),
                                   "classes": classes, "per_attack": per}


# --------------------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description="Inspect a local SWaT download (aggregate report only).")
    ap.add_argument("folder", help=r'e.g. "C:\IndustrialMind\SWaT_dataset\archive"')
    ap.add_argument("--out", default="swat_inspection", help="output folder for report + manifest")
    ap.add_argument("--hash", action="store_true", help="also compute sha256 of every file (slow, for provenance)")
    ap.add_argument("--merge-gap", type=int, default=1,
                    help="merge attack runs separated by <= this many rows when listing windows (default 1 = contiguous only)")
    ap.add_argument("--brief", action="store_true", help="omit the per-column table in the text report (kept in the JSON)")
    ap.add_argument("--seg-gap", type=float, default=2.0,
                    help="attack rows separated by more than this many seconds start a new segment (default 2)")
    ap.add_argument("--max-windows", type=int, default=80, help="windows printed in the text report")
    args = ap.parse_args()

    root = Path(args.folder)
    if not root.exists():
        print(f"folder not found: {root}")
        return 2
    report: Dict[str, Any] = {"folder": str(root), "files": [], "data_files": {}, "attack_list": {},
                              "network": {}, "generated": time.strftime("%Y-%m-%d %H:%M:%S")}
    t0 = time.time()
    emit("=" * 78)
    emit(f"SWaT inspection of: {root}")
    emit("=" * 78)

    # 1. file inventory ---------------------------------------------------------------------
    files = sorted(p for p in root.rglob("*") if p.is_file())
    emit(f"\n[1] FILES ({len(files)})")
    ext_count: Dict[str, int] = {}
    net_files: List[str] = []
    for p in files:
        rel = str(p.relative_to(root))
        size = p.stat().st_size
        rec: Dict[str, Any] = {"path": rel, "bytes": size}
        if args.hash:
            h = hashlib.sha256()
            with open(p, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            rec["sha256"] = h.hexdigest()
        report["files"].append(rec)
        ext_count[p.suffix.lower()] = ext_count.get(p.suffix.lower(), 0) + 1
        if p.suffix.lower() in NETWORK_FILE_EXT:
            net_files.append(rel)
        if len(files) <= 60:
            emit(f"    {human(size):>11s}  {rel}" + (f"  sha256={rec['sha256'][:16]}..." if args.hash else ""))
    if len(files) > 60:
        emit(f"    (showing extension summary only; full list in JSON) {ext_count}")
    total = sum(r["bytes"] for r in report["files"])
    emit(f"    total {human(total)}; by extension: {ext_count}")

    # 2-4. tables -----------------------------------------------------------------------------
    tables = [p for p in files if p.suffix.lower() in TABLE_EXT]
    net_cols: Dict[str, List[str]] = {}
    state: Dict[str, Any] = {}
    emit(f"\n[2] TABLES ({len(tables)})")
    for p in tables:
        rel = str(p.relative_to(root))
        emit(f"\n--- {rel}")
        try:
            tt = time.time()
            df = load_table(p)
            emit(f"  loaded in {time.time() - tt:.1f}s")
        except Exception as exc:  # report and continue with the next file
            emit(f"  COULD NOT READ: {type(exc).__name__}: {str(exc)[:160]}")
            if p.suffix.lower() in (".xlsx", ".xls"):
                emit("  (xlsx needs openpyxl: pip install openpyxl)")
            continue
        hits = [c for c in df.columns if any(w in c.lower() for w in NETWORK_COL_WORDS)]
        if hits:
            net_cols[rel] = hits
        tagish = sum(1 for c in df.columns if TAG_RE.fullmatch(c))
        if len(df) < 500 and tagish < 5:
            analyse_attack_list(rel, df, report)
        else:
            analyse_data(rel, df, report, args, state)
        del df

    # deferred attack-segment reports (files that had no normal rows of their own)
    for name, num, ts, attack, info in state.get("deferred", []):
        emit(f"\n--- {name} (attack segments, baseline from {state['base']['source'] if 'base' in state else 'NONE AVAILABLE'})")
        if "base" in state:
            report_segments(name, num, ts, attack, state["base"], info, args)
        else:
            emit("  no file with enough normal rows to build a baseline")

    # cross-file consistency
    rows = {n: i["rows"] for n, i in report["data_files"].items()}
    names = {n.lower(): n for n in rows}
    if {"merged.csv", "normal.csv", "attack.csv"} <= set(names):
        tot = rows[names["normal.csv"]] + rows[names["attack.csv"]]
        emit(f"\ncross-check: normal.csv + attack.csv = {tot:,} rows; merged.csv = {rows[names['merged.csv']]:,} -> "
             f"{'MATCH (merged is just the concatenation)' if tot == rows[names['merged.csv']] else 'DIFFERENT'}")

    # 5. network-level fields ---------------------------------------------------------------------
    emit("\n[3] NETWORK-LEVEL INFORMATION (decides the cyber-model adapter)")
    report["network"] = {"capture_files": net_files, "suspicious_columns": net_cols}
    emit(f"    capture files (pcap/argus/...): {net_files or 'NONE'}")
    if net_cols:
        for k, v in net_cols.items():
            emit(f"    columns whose names look network-related in {k}: {v}")
    else:
        emit("    network-looking column names: NONE")
    verdict = ("NETWORK DATA PRESENT - cyber adapter can use real network fields"
               if net_files else
               "NO NETWORK CAPTURES FOUND - only physical process data (cyber features must be derived "
               "from actuator state-change timing or dropped)")
    emit(f"    => {verdict}")
    report["network"]["verdict"] = verdict

    emit(f"\nDone in {time.time() - t0:.0f}s.")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "swat_inspection_report.txt").write_text("\n".join(OUT), encoding="utf-8")
    (out / "swat_manifest.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    print(f"\nWrote {out / 'swat_inspection_report.txt'} and {out / 'swat_manifest.json'}")
    print("Paste swat_inspection_report.txt back (aggregates only - no raw rows).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
