"""
tools/wire_correlate.py - match packets seen on the wire (tshark) to the dashboard's Packet Tracer entries.

The tx_id is generated INSIDE the middleware, so it is not on the wire. What is on the wire, in every signed command frame,
is the 64-bit nonce (words 3..6 of the FC16 write to register 100). The tracer records the same nonce, so the two are matched
by nonce. This proves the traffic is real and independent of the dashboard: a DROPped (tampered/replayed/forged) frame IS
visible on the middleware leg and is ABSENT from the PLC leg; a forwarded one appears on both.

1. Capture (see docs/wireshark_setup.md; the field order below is fixed):
     middleware leg:  tshark -i <if> -f "tcp port <MW_PORT>" -o mbtcp.tcp.port:<MW_PORT> -Y "mbtcp" -T fields \\
                        -e frame.number -e frame.time_epoch -e ip.src -e tcp.dstport -e modbus.func_code \\
                        -e modbus.reference_num -e modbus.regval_uint16 -e modbus.data  > mw.tsv
     PLC leg (optional): same with the PLC port > plc.tsv
2.  python -m tools.wire_correlate --mw mw.tsv [--plc plc.tsv] [--dashboard-url http://<dashboard>:5050]
    (--traces-json <file> instead of --dashboard-url for offline use)

Addresses come from docs/netconfig.py (env IM_DASHBOARD_URL, IM_MIDDLEWARE_PORT, IM_PLC_PORT) or the flags.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from docs import netconfig
from docs.interfaces import FRAME_BASE, FRAME_LEN

COLUMNS = ["frame", "time", "src", "dstport", "func", "reference", "regvals", "data"]


def _rows(path: str) -> List[Dict[str, str]]:
    out = []
    with open(path) as fh:
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 5 or parts[0].lower() in ("", "frame.number"):
                continue
            parts += [""] * (len(COLUMNS) - len(parts))
            out.append(dict(zip(COLUMNS, parts)))
    return out


def middleware_frames(path: str, mw_port: int) -> List[Dict[str, Any]]:
    """Signed command frames (FC16, register 100, 27 words) with their nonce words."""
    frames = []
    for r in _rows(path):
        if r["func"] != "16" or r["dstport"] != str(mw_port) or r["reference"] != str(FRAME_BASE):
            continue
        words = [int(w) for w in r["regvals"].split(",") if w != ""]
        if len(words) != FRAME_LEN:
            continue
        frames.append({"frame": r["frame"], "time": float(r["time"] or 0), "src": r["src"], "register": words[1],
                       "raw": words[2], "nonce": tuple(words[3:7])})
    return frames


def plc_writes(path: str, plc_port: int) -> List[Tuple[int, int]]:
    """Forwarded single-register writes (FC6) as (register, raw value)."""
    out = []
    for r in _rows(path):
        if r["func"] == "6" and r["dstport"] == str(plc_port) and r["data"]:
            try:
                out.append((int(r["reference"]), int(r["data"], 16)))
            except ValueError:
                continue
    return out


def load_traces(dashboard_url: Optional[str], traces_json: Optional[str]) -> List[Dict[str, Any]]:
    if traces_json:
        with open(traces_json) as fh:
            return json.load(fh)
    get = lambda p: json.load(urllib.request.urlopen(dashboard_url.rstrip("/") + p, timeout=5))
    return [get("/api/trace/" + t["short_id"]) for t in get("/api/traces")]


def correlate(frames: List[Dict[str, Any]], traces: List[Dict[str, Any]], plc: Optional[List[Tuple[int, int]]]) -> List[Dict[str, Any]]:
    by_nonce: Dict[Tuple[int, ...], List[Dict[str, Any]]] = defaultdict(list)
    for t in sorted(traces, key=lambda x: x.get("time") or 0):
        arr = next((h for h in t["hops"] if h["hop"] == "arrival"), None)
        if arr and arr["values"].get("nonce_words"):
            by_nonce[tuple(arr["values"]["nonce_words"])].append(t)
    used: Dict[Tuple[int, ...], int] = defaultdict(int)
    pool = list(plc) if plc is not None else None
    rows = []
    for f in sorted(frames, key=lambda x: x["time"]):
        cands = by_nonce.get(f["nonce"], [])
        t = cands[used[f["nonce"]]] if used[f["nonce"]] < len(cands) else None
        used[f["nonce"]] += 1
        row = {"frame": f["frame"], "src": f["src"], "register": f["register"], "raw": f["raw"],
               "tx": t["short_id"] if t else None, "verdict": t["verdict"] if t else None, "reason": (t["reason"] if t else "")[:60],
               "on_plc_leg": None, "consistent": None}
        if t is None:
            row["consistent"] = False
            row["reason"] = "no tracer entry with this nonce (dashboard reset, or frame never reached the middleware logic)"
        elif pool is not None:
            forwarded = t["verdict"] in ("PASS", "ALERT")
            seen = (f["register"], f["raw"]) in pool
            if seen and forwarded:
                pool.remove((f["register"], f["raw"]))
            row["on_plc_leg"] = seen
            row["consistent"] = (seen == forwarded)
        else:
            row["consistent"] = True
        rows.append(row)
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description="Correlate tshark captures with Packet Tracer entries by frame nonce.")
    ap.add_argument("--mw", required=True, help="tshark TSV of the middleware leg")
    ap.add_argument("--plc", help="tshark TSV of the PLC leg (optional)")
    ap.add_argument("--dashboard-url", default=netconfig.DASHBOARD_URL)
    ap.add_argument("--traces-json", help="offline: JSON list of full traces instead of querying the dashboard")
    ap.add_argument("--mw-port", type=int, default=netconfig.MIDDLEWARE_PORT)
    ap.add_argument("--plc-port", type=int, default=netconfig.PLC_PORT)
    a = ap.parse_args()
    rows = correlate(middleware_frames(a.mw, a.mw_port), load_traces(a.dashboard_url, a.traces_json),
                     plc_writes(a.plc, a.plc_port) if a.plc else None)
    print(f"{'wire#':>6} {'src':<15} {'reg':>3} {'raw':>5}  {'tx':<7} {'verdict':<6} {'on PLC leg':<10} reason")
    for r in rows:
        leg = "n/a" if r["on_plc_leg"] is None else ("yes" if r["on_plc_leg"] else "NO")
        flag = "" if r["consistent"] else "   <-- MISMATCH"
        print(f"{r['frame']:>6} {r['src']:<15} {r['register']:>3} {r['raw']:>5}  {str(r['tx']):<7} {str(r['verdict']):<6} {leg:<10} {r['reason']}{flag}")
    bad = [r for r in rows if not r["consistent"]]
    print(f"\n{len(rows)} signed frame(s) on the wire, {len(rows) - len(bad)} consistent with the tracer"
          + ("" if a.plc else " (no PLC leg given: forward/drop not cross-checked)") + f", {len(bad)} mismatch(es).")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
