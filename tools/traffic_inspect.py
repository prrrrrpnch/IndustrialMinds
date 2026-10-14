#!/usr/bin/env python3
"""
tools/traffic_inspect.py - onboarding inspection of a labelled NETWORK-TRAFFIC dataset for the CyberModel.

Run it ON THE MACHINE THAT HOLDS THE DATA (nothing is uploaded anywhere):

    python tools/traffic_inspect.py "C:\\path\\to\\dataset_folder_or_file.csv" --out traffic_inspection
    python tools/traffic_inspect.py data.csv --label-col Label --time-col Time --max-rows 2000000

Needs: python 3.8+, pandas, numpy (scikit-learn optional, enables the leakage screen).

It answers, in aggregate form only (no raw rows are printed, source/destination addresses are anonymised
to S1, S2, ...):
  1. files present, sizes, capture files (pcap/pcapng) that must be converted to CSV first
  2. column ROLES guessed by name (time, source, destination, protocol, port, Modbus function code,
     register/address, value/data, length, label) - check them, override with --label-col / --time-col
  3. label scheme, class balance, timestamp parsing, ordering, exact-duplicate rows (also across labels)
  4. attack segments (runs of attack rows broken by time gaps) and whether ONE segment dominates
  5. function-code / protocol distribution per class
  6. LEAKAGE SCREEN: single numeric columns that separate the classes almost perfectly (IDs, ports,
     counters) - these must not become features
  7. which of the CyberModel's original 13 feature ideas the data could support

Outputs (in --out): traffic_inspection_report.txt  traffic_manifest.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

TABLE_EXT = {".csv", ".tsv", ".txt", ".gz"}
CAPTURE_EXT = {".pcap", ".pcapng", ".cap", ".argus"}
ROLE_WORDS: Dict[str, List[str]] = {
    "time": ["time", "timestamp", "ts", "date", "stamp", "epoch"],
    "src": ["srcip", "src_ip", "ip.src", "source", "src", "sip", "saddr", "src_addr"],
    "dst": ["dstip", "dst_ip", "ip.dst", "destination", "dst", "dip", "daddr", "dst_addr"],
    "proto": ["proto", "protocol"],
    "port": ["port", "sport", "dport"],
    "func_code": ["func", "function", "fc", "modbus.func", "func_code", "funccode"],
    "register": ["addr", "address", "reference", "register", "reg", "start_addr", "coil"],
    "value": ["value", "data", "word", "payload", "regs", "quantity", "val"],
    "length": ["len", "length", "size", "bytes", "pktlen"],
    "label": ["label", "attack", "class", "malicious", "anomaly", "target", "category", "normal", "is_attack", "type"],
}
ATTACK_WORDS = {"attack", "malicious", "anomaly", "abnormal", "1", "1.0", "true", "yes", "anomalous", "intrusion"}
NORMAL_WORDS = {"normal", "benign", "0", "0.0", "false", "no", "legit", "legitimate", "clean"}
OUT: List[str] = []


def emit(line: str = "") -> None:
    print(line)
    OUT.append(line)


def guess_roles(cols: List[str]) -> Dict[str, List[str]]:
    roles: Dict[str, List[str]] = {r: [] for r in ROLE_WORDS}
    for c in cols:
        low = c.lower()
        for role, words in ROLE_WORDS.items():
            if any(low == w or re.search(r"(^|[._ \-])" + re.escape(w) + r"($|[._ \-])", low) or (len(w) > 3 and w in low) for w in words):
                roles[role].append(c)
    return roles


LABEL_PRIORITY = ["attack_label", "label", "attack_type", "attack_category", "traffic_category", "class", "target", "category", "type"]
LABEL_AVOID = ("icmp", "tcp", "udp", "http", "ip_", "dns", "frame", "eth", "arp", "mqtt", "modbus", "tls", "quic", "flags", "opcode")


def rank_label_candidates(df: pd.DataFrame, cols: List[str]) -> List[str]:
    """Label-like columns, best first: exact priority names win, protocol-header fields (icmp_type, tcp_flags...) are avoided."""
    scored = []
    for c in cols:
        low = c.lower()
        if any(low.startswith(a) or f"_{a}" in low for a in LABEL_AVOID):
            continue
        for rank, name in enumerate(LABEL_PRIORITY):
            if low == name or low.endswith("_" + name) or low.endswith(name):
                if df[c].nunique(dropna=True) <= 60:
                    scored.append((rank, c))
                break
    return [c for _, c in sorted(scored)]


def to_attack(s: pd.Series) -> Tuple[Optional[np.ndarray], Dict[str, int]]:
    counts = {str(k): int(v) for k, v in s.value_counts(dropna=False).head(15).items()}
    key = s.astype(str).str.strip().str.lower().str.replace(r"\s+", "", regex=True)
    if key.nunique() > 30:
        return None, counts
    attack = key.isin(ATTACK_WORDS)
    normal = key.isin(NORMAL_WORDS)
    if not (attack | normal).all():
        # multi-class label: everything that is not a "normal" word counts as attack
        attack = ~normal
    return attack.to_numpy(), counts


def read_table(path: Path, max_rows: int) -> Tuple[pd.DataFrame, bool]:
    seps = ["\t", ","] if path.suffix.lower() == ".tsv" else [",", "\t", ";", "|"]
    df = None
    for sep in seps:                      # first separator that yields more than one column
        try:
            cand = pd.read_csv(path, nrows=max_rows + 1, low_memory=False, sep=sep, skipinitialspace=True,
                               on_bad_lines="skip", encoding_errors="replace")
        except Exception:
            continue
        if cand.shape[1] > 1:
            df = cand
            break
    if df is None:
        raise ValueError("no delimiter produced more than one column")
    truncated = len(df) > max_rows
    df = df.iloc[:max_rows]
    df.columns = [str(c).strip() for c in df.columns]
    return df, truncated


def parse_time(s: pd.Series) -> Tuple[Optional[pd.Series], str]:
    num = pd.to_numeric(s, errors="coerce")
    if num.notna().mean() > 0.95:
        v = num.astype(float)
        scale = 1e9 if v.median() > 1e17 else 1e6 if v.median() > 1e14 else 1e3 if v.median() > 1e11 else 1.0
        return v / scale, "numeric (seconds-like)"
    t = pd.to_datetime(s.astype(str).str.strip(), errors="coerce", dayfirst=True)
    if t.notna().mean() > 0.9:
        return (t - pd.Timestamp("1970-01-01")).dt.total_seconds(), "datetime"
    return None, "unparsable"


def main() -> int:
    ap = argparse.ArgumentParser(description="Aggregate-only inspection of a labelled network-traffic dataset.")
    ap.add_argument("path", help="file or folder")
    ap.add_argument("--out", default="traffic_inspection")
    ap.add_argument("--label-col")
    ap.add_argument("--time-col")
    ap.add_argument("--focus-protocol", help="e.g. Modbus: also analyse only the rows of that protocol (label mix, protocol-specific fields)")
    ap.add_argument("--max-rows", type=int, default=3_000_000, help="rows read per file (default 3,000,000)")
    ap.add_argument("--seg-gap", type=float, default=5.0, help="seconds: attack rows farther apart start a new segment")
    a = ap.parse_args()

    root = Path(a.path)
    if not root.exists():
        print(f"not found: {root}")
        return 2
    files = [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file())
    report: Dict[str, Any] = {"path": str(root), "files": [], "tables": {}, "generated": time.strftime("%Y-%m-%d %H:%M:%S")}
    emit("=" * 78)
    emit(f"Traffic dataset inspection: {root}")
    emit("=" * 78)
    emit(f"\n[1] FILES ({len(files)})")
    caps = []
    for p in files:
        report["files"].append({"path": str(p.relative_to(root)) if root.is_dir() else p.name, "bytes": p.stat().st_size})
        if p.suffix.lower() in CAPTURE_EXT:
            caps.append(p.name)
        if len(files) <= 40:
            emit(f"    {p.stat().st_size / 1e6:10.1f} MB  {p.name}")
    emit(f"    total {sum(f['bytes'] for f in report['files']) / 1e6:,.1f} MB")
    if caps:
        emit(f"    CAPTURE FILES: {caps}  -> convert to CSV first, e.g.:")
        emit('      tshark -r in.pcap -T fields -E header=y -E separator=, -e frame.time_epoch -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport '
             '-e modbus.func_code -e modbus.reference_num -e modbus.word_cnt -e modbus.regval_uint16 -e frame.len > out.csv')

    tables = [p for p in files if p.suffix.lower() in TABLE_EXT]
    emit(f"\n[2] TABLES ({len(tables)})")
    for p in tables:
        emit(f"\n--- {p.name}")
        try:
            df, trunc = read_table(p, a.max_rows)
        except Exception as exc:
            emit(f"  COULD NOT READ: {type(exc).__name__}: {str(exc)[:150]}")
            continue
        info: Dict[str, Any] = {"rows_read": int(len(df)), "truncated": trunc, "columns": list(df.columns)}
        emit(f"  rows read {len(df):,}{' (TRUNCATED at --max-rows)' if trunc else ''}; columns {len(df.columns)}")
        roles = guess_roles(list(df.columns))
        if a.label_col:
            roles["label"] = [a.label_col]
        if a.time_col:
            roles["time"] = [a.time_col]
        info["roles"] = roles
        emit("  COLUMNS (name | kind | non-null | distinct | values if <= 8 distinct):")
        for c in df.columns:
            nn = float(df[c].notna().mean())
            nu = int(df[c].nunique(dropna=True))
            vals = ""
            if nu <= 8:
                vals = " " + str({str(k): int(v) for k, v in df[c].value_counts().items()})
            emit(f"    {c[:34]:34s} {str(df[c].dtype):8s} {nn:6.1%} {nu:9,d}{vals}"[:200])
        for r, cs in roles.items():
            emit(f"  role {r:10s}: {cs[:6] if cs else '-'}")

        # ---- label
        attack = None
        cands = rank_label_candidates(df, list(df.columns))
        info["label_candidates"] = cands
        emit(f"  label candidates (best first): {cands or '-'}")
        for cc in cands[:4]:
            emit(f"    '{cc}': " + str({str(k): int(v) for k, v in df[cc].value_counts(dropna=False).head(12).items()}))
        lab = a.label_col or (cands[0] if cands else (roles["label"][0] if roles["label"] else None))
        if lab:
            attack, counts = to_attack(df[lab])
            info["label"] = {"column": lab, "raw_value_counts": counts}
            emit(f"  label '{lab}': {counts}")
            if attack is not None:
                rate = float(attack.mean())
                info["label"].update({"attack_rows": int(attack.sum()), "attack_rate": rate})
                emit(f"    -> attack rows {int(attack.sum()):,} ({rate:.2%}); normal {int((~attack).sum()):,}")
        else:
            emit("  NO LABEL COLUMN found (pass --label-col): a supervised model needs labels")

        # ---- time
        ts = None
        tcol = roles["time"][0] if roles["time"] else None
        if tcol:
            ts, how = parse_time(df[tcol])
            if ts is not None:
                d = ts.diff().dropna()
                info["time"] = {"column": tcol, "parsed_as": how, "span_s": float(ts.max() - ts.min()),
                                "median_gap_s": float(d.median()), "backward_steps": int((d < 0).sum())}
                emit(f"  time '{tcol}' ({how}): span {info['time']['span_s']:,.0f} s, median gap {info['time']['median_gap_s']:.6g} s, "
                     f"backward steps {info['time']['backward_steps']:,} (non-chronological if > 0)")
            else:
                emit(f"  time '{tcol}': could not be parsed")

        # ---- anonymised sources
        for role in ("src", "dst"):
            if roles[role]:
                vc = df[roles[role][0]].value_counts()
                info[f"{role}_unique"] = int(len(vc))
                shares = [f"{'S' if role == 'src' else 'D'}{i + 1}:{v / len(df):.1%}" for i, v in enumerate(vc.head(5))]
                emit(f"  {role} '{roles[role][0]}': {len(vc):,} unique; top shares {shares}")

        # ---- function codes / protocol vs label
        for role in ("func_code", "proto"):
            if roles[role]:
                c = roles[role][0]
                emit(f"  {role} '{c}' top values: " + str({str(k): int(v) for k, v in df[c].value_counts().head(8).items()}))
                if attack is not None and df[c].nunique() <= 60:
                    ct = pd.crosstab(df[c].astype(str), attack)
                    ct.columns = ["normal" if not x else "attack" for x in ct.columns]
                    emit("    by class (top 8): " + str(ct.sort_values(ct.columns[-1], ascending=False).head(8).to_dict("index")))

        # ---- protocol x label, and a focus slice (e.g. Modbus)
        if attack is not None and roles["proto"]:
            pc = roles["proto"][0]
            ct = pd.crosstab(df[pc].astype(str), df[lab].astype(str))
            top = ct.assign(_n=ct.sum(axis=1)).sort_values("_n", ascending=False).head(10).drop(columns="_n")
            emit(f"  protocol x label (top 10 protocols), columns = {list(top.columns)[:12]}:")
            for k, row in top.iterrows():
                emit(f"    {k[:14]:14s} " + " ".join(f"{int(v):>8,d}" for v in row.values[:12]))
        if a.focus_protocol and roles["proto"]:
            pc = roles["proto"][0]
            m = df[pc].astype(str).str.contains(a.focus_protocol, case=False, na=False).to_numpy()
            emit(f"\n  FOCUS '{a.focus_protocol}' (rows whose '{pc}' contains it): {int(m.sum()):,} of {len(df):,}")
            if m.any():
                sub_df = df[m]
                if lab:
                    emit(f"    label '{lab}' inside the slice: " + str({str(k): int(v) for k, v in sub_df[lab].value_counts(dropna=False).head(12).items()}))
                for extra in [c for c in cands[:3] if c != lab]:
                    emit(f"    label '{extra}' inside the slice: " + str({str(k): int(v) for k, v in sub_df[extra].value_counts(dropna=False).head(12).items()}))
                if ts is not None:
                    tt = ts[m]
                    emit(f"    time span of the slice {float(tt.max() - tt.min()):,.0f} s; median gap {float(tt.sort_values().diff().median()):.4g} s")
                # columns that are (nearly) empty overall but populated inside the slice = protocol-specific fields
                spec = [(c, float(sub_df[c].notna().mean()), float(df[c].notna().mean())) for c in df.columns
                        if sub_df[c].notna().mean() > 0.5 and df[c].notna().mean() < 0.2]
                emit("    slice-specific fields (populated in the slice, rare elsewhere): " + (", ".join(f"{c}({a_:.0%} vs {b_:.1%})" for c, a_, b_ in spec[:25]) or "-"))
                for c, _, _ in spec[:12]:
                    if sub_df[c].nunique() <= 25:
                        emit(f"      {c}: " + str({str(k): int(v) for k, v in sub_df[c].value_counts().head(10).items()}))

        # ---- duplicates
        dup = int(df.duplicated().sum())
        info["exact_duplicate_rows"] = dup
        emit(f"  exact duplicate rows: {dup:,} ({dup / max(1, len(df)):.2%})")
        if lab and attack is not None and dup:
            cols = [c for c in df.columns if c != lab]
            g = df.assign(_a=attack).groupby(cols, dropna=False)["_a"].nunique()
            emit(f"  identical feature rows labelled BOTH ways (label noise): {int((g > 1).sum()):,}")

        # ---- attack segments
        if attack is not None and ts is not None and attack.any():
            idx = np.flatnonzero(attack)
            t = ts.to_numpy()[idx]
            order = np.argsort(t)
            t = t[order]
            brk = np.diff(t) > a.seg_gap
            sizes = np.diff(np.concatenate(([0], np.flatnonzero(brk) + 1, [len(t)])))
            info["attack_segments"] = {"count": int(len(sizes)), "rows_min": int(sizes.min()), "rows_median": int(np.median(sizes)),
                                       "rows_max": int(sizes.max()), "largest_segment_share": float(sizes.max() / sizes.sum())}
            emit(f"  attack segments (gap > {a.seg_gap:g} s): {len(sizes)}; rows per segment min/median/max "
                 f"{sizes.min()}/{int(np.median(sizes))}/{sizes.max()}; largest segment = {sizes.max() / sizes.sum():.0%} of attack rows")

        # ---- leakage screen: univariate AUC of each numeric column against the label
        if attack is not None and 0 < attack.sum() < len(attack):
            try:
                from sklearn.metrics import roc_auc_score
                sample = df.sample(min(len(df), 200_000), random_state=0) if len(df) > 200_000 else df
                y = attack[sample.index.to_numpy()]
                aucs = {}
                for c in sample.columns:
                    if c == lab:
                        continue
                    x = pd.to_numeric(sample[c], errors="coerce")
                    if x.notna().mean() > 0.9 and x.nunique() > 1:
                        aucs[c] = float(roc_auc_score(y, x.fillna(x.median())))
                top = sorted(aucs.items(), key=lambda kv: -abs(kv[1] - 0.5))[:8]
                info["leakage_screen_auc"] = dict(top)
                emit("  LEAKAGE SCREEN (single-column ROC-AUC; 0.5 = no signal, near 0 or 1 = suspicious): "
                     + ", ".join(f"{k}={v:.3f}" for k, v in top))
                sus = [k for k, v in top if abs(v - 0.5) > 0.45]
                if sus:
                    emit(f"  !! near-perfect single-column separators: {sus} - check they are not IDs/counters/ports before using them")
            except ImportError:
                emit("  (leakage screen skipped: scikit-learn not installed)")

        # ---- which original features this data could support
        have = {r: bool(roles[r]) for r in ("time", "src", "func_code", "register", "value", "length")}
        emit("  could support the legacy cyber features: "
             f"function-code one-hot {'YES' if have['func_code'] else 'NO'}; register known / value position {'YES' if have['register'] and have['value'] else 'NO'}; "
             f"inter-arrival & request rates {'YES' if have['time'] else 'NO'}; per-source rates {'YES' if have['src'] and have['time'] else 'NO'}; "
             "signature_present/age NO (no public traffic data has HMAC)")
        report["tables"][p.name] = info

    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "traffic_inspection_report.txt").write_text("\n".join(OUT), encoding="utf-8")
    (out / "traffic_manifest.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    print(f"\nWrote {out / 'traffic_inspection_report.txt'} and {out / 'traffic_manifest.json'}")
    print("Paste traffic_inspection_report.txt back (aggregates only; addresses anonymised).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
