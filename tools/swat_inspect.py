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


def parse_timestamps(s: pd.Series) -> Optional[pd.Series]:
    txt = s.astype(str).str.strip()
    sample = txt.dropna().iloc[:2000]
    for fmt in STAMP_FORMATS:
        ok = pd.to_datetime(sample, format=fmt, errors="coerce").notna().mean()
        if ok > 0.95:
            return pd.to_datetime(txt, format=fmt, errors="coerce")
    out = pd.to_datetime(txt, dayfirst=True, errors="coerce")
    return out if out.notna().mean() > 0.5 else None


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


def analyse_data(name: str, df: pd.DataFrame, report: Dict[str, Any], args: argparse.Namespace) -> None:
    info: Dict[str, Any] = {"rows": int(len(df)), "columns": list(df.columns)}
    emit(f"  rows={len(df):,}  columns={len(df.columns)}")

    ts_col = next((c for c in df.columns if "time" in c.lower()), None)
    ts = parse_timestamps(df[ts_col]) if ts_col else None
    if ts is not None:
        d = ts.diff().dt.total_seconds().dropna()
        med = float(d.median()) if len(d) else float("nan")
        gaps = int((d > max(1.5 * med, 1.5)).sum()) if len(d) else 0
        info["timestamp"] = {"column": ts_col, "first": str(ts.iloc[0]), "last": str(ts.iloc[-1]),
                             "median_step_s": med, "gaps_over_1.5x": gaps,
                             "max_gap_s": float(d.max()) if len(d) else None}
        emit(f"  timestamp col '{ts_col}': {ts.iloc[0]} -> {ts.iloc[-1]}  median step {med:g}s  "
             f"gaps>1.5x: {gaps}  max gap {info['timestamp']['max_gap_s']:g}s")
    else:
        emit(f"  timestamp: {'column ' + repr(ts_col) + ' could not be parsed' if ts_col else 'no timestamp column'}")

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
    non_numeric = [c for c in num_cols if num[c].isna().mean() > 0.5]
    if non_numeric:
        emit(f"  non-numeric columns (>50% unparsable): {non_numeric}")
    num = num.drop(columns=non_numeric)

    base_mask = ~attack if attack is not None else np.ones(len(df), bool)
    base = num[base_mask]
    emit(f"  per-column statistics measured on {'NORMAL-labelled' if attack is not None else 'ALL'} rows ({int(base_mask.sum()):,})"
         + (" [table omitted by --brief; see JSON]:" if args.brief else ":"))
    if not args.brief:
        emit(f"    {'column':10s} {'uniq':>5s} {'min':>9s} {'p0.5':>9s} {'p99.5':>9s} {'max':>9s} {'mean':>9s} {'std':>9s}  states(if <=6 values)")
    cols: Dict[str, Any] = {}
    for c in num.columns:
        x = base[c].dropna()
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
        cols[c] = st
        if not args.brief:
            emit(f"    {c:10s} {uniq:5d} {st['min']:9.2f} {st['p0.5']:9.2f} {st['p99.5']:9.2f} {st['max']:9.2f} "
                 f"{st['mean']:9.2f} {st['std']:9.2f}  {states}")
    info["columns_stats"] = cols

    present = [t for t in OUR_TAGS if t in cols]
    missing = [t for t in OUR_TAGS if t not in cols]
    info["twin_tags_present"], info["twin_tags_missing"] = present, missing
    emit(f"  this project's 20 twin tags: {len(present)} present; missing: {missing or 'none'}")
    by_stage: Dict[int, List[str]] = {}
    for c in cols:
        s = stage_of(c)
        if s is not None:
            by_stage.setdefault(s, []).append(c)
    emit("  columns by SWaT stage: " + "; ".join(f"P{k}: {len(v)}" for k, v in sorted(by_stage.items())))

    if attack is not None and attack.any():
        starts, ends = runs(attack)
        emit(f"  attack windows (contiguous attack-labelled runs): {len(starts)}")
        emit("  windows if nearby runs are merged: " + ", ".join(
            f"gap<={g}s -> {len(merge_runs(starts, ends, g))}" for g in (1, 10, 60, 300)))
        mu, sd = base.mean(), base.std(ddof=0).replace(0, np.nan)
        wins: List[Dict[str, Any]] = []
        emit(f"    {'#':>3s} {'start':19s} {'end':19s} {'rows':>6s}  most-shifted columns (z vs normal mean)")
        for i, (s, e) in enumerate(merge_runs(starts, ends, args.merge_gap), 1):
            z = ((num.iloc[s:e + 1].mean() - mu) / sd).dropna()
            top = z.reindex(z.abs().sort_values(ascending=False).index)[:3]
            tops = ", ".join(f"{k}({v:+.1f})" for k, v in top.items())
            t0 = str(ts.iloc[s]) if ts is not None else f"row {s}"
            t1 = str(ts.iloc[e]) if ts is not None else f"row {e}"
            wins.append({"index": i, "start_row": int(s), "end_row": int(e), "rows": int(e - s + 1),
                         "start": t0, "end": t1, "top_shifted": {k: float(v) for k, v in top.items()}})
            if i <= args.max_windows:
                emit(f"    {i:3d} {t0:19.19s} {t1:19.19s} {e - s + 1:6d}  {tops}")
        if len(wins) > args.max_windows:
            emit(f"    ... {len(wins) - args.max_windows} more windows in the JSON manifest")
        info["attack_windows"] = wins
        durs = [w["rows"] for w in wins]
        emit(f"  window length (rows ~ seconds): min {min(durs)}, median {int(np.median(durs))}, max {max(durs)}")
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
            analyse_data(rel, df, report, args)
        del df

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
