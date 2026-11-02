"""Checks for the synthetic SWaT-shaped fixture. Run: python -m tests.test_swat_fixture"""
import os
import sys
import tempfile
import time
from datetime import datetime

import pandas as pd

from tests.swat_fixture import make_swat_archive, NAN_COLUMNS

FMT = "%d/%m/%Y %I:%M:%S %p"
failures = []


def check(name, ok, detail=""):
    print("[%s] %s %s" % ("PASS" if ok else "FAIL", name, detail))
    if not ok:
        failures.append(name)


def main():
    with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2, \
            tempfile.TemporaryDirectory() as d3:
        t0 = time.time()
        truth = make_swat_archive(d1, seed=0)
        dt = time.time() - t0
        paths = {k: os.path.join(d1, k + ".csv") for k in ("normal", "attack", "merged")}
        check("3 files exist", all(os.path.isfile(p) for p in paths.values()))
        n, a, m = (pd.read_csv(paths[k]) for k in ("normal", "attack", "merged"))
        for df in (n, a, m):
            df.columns = [c.strip() for c in df.columns]
        check("53 columns", n.shape[1] == a.shape[1] == m.shape[1] == 53)
        check("leading-space header present",
              any(c.startswith(" ") for c in pd.read_csv(paths["normal"], nrows=0).columns))
        check("merged rows == normal + attack", len(m) == len(n) + len(a) == truth["n_rows"]["merged"],
              "(%d)" % len(m))
        check("merged order (normal then attack)",
              m["Timestamp"].iloc[0] == n["Timestamp"].iloc[0]
              and m["Timestamp"].iloc[-1] == a["Timestamp"].iloc[-1])
        check("attack.csv all Attack", (a["Normal/Attack"] == "Attack").all())
        check("normal.csv all Normal", (n["Normal/Attack"] == "Normal").all())
        check("7 NaN columns", all(
            n[c].isna().sum() == 991_800 or (n[c].isna().sum() > 0 and a[c].notna().all())
            for c in NAN_COLUMNS) and a[NAN_COLUMNS].notna().all().all())
        nn = n[n[NAN_COLUMNS].isna().all(axis=1)]
        check("NaN rows are the normal-period rows", 0 < len(nn) < len(n), "(%d)" % len(nn))
        ok = True
        try:
            ts = [datetime.strptime(s, FMT) for s in n["Timestamp"].iloc[::97]]
            ts += [datetime.strptime(s, FMT) for s in a["Timestamp"].iloc[::97]]
        except ValueError:
            ok = False
        check("timestamps parse with strptime format", ok)
        check("starts with attack-period normal rows",
              n["Timestamp"].iloc[0] == "28/12/2015 10:00:00 AM")
        check("duplicated timestamps > 0", truth["duplicate_timestamps"] > 0
              and n["Timestamp"].duplicated().sum() == truth["duplicate_timestamps"])
        check("35 segments", truth["n_segments"] == 35 == len(truth["segments"]))
        check("rows in truth match attack.csv", sum(s["rows"] for s in truth["segments"]) == len(a))
        kinds = {s["kind"] for s in truth["segments"]}
        check("all attack kinds planted", kinds == {"toggle", "force_off", "sensor_shift", "subtle"})
        sizes = [os.path.getsize(p) for p in paths.values()]
        check("file sizes small (<80 MB each)", max(sizes) < 80e6, str([s // 10**6 for s in sizes]))
        check("generation < 10 s", dt < 10, "(%.1fs)" % dt)

        make_swat_archive(d2, seed=0)
        same = all(open(os.path.join(d1, f), "rb").read() == open(os.path.join(d2, f), "rb").read()
                   for f in ("normal.csv", "attack.csv", "merged.csv"))
        check("deterministic (same seed -> identical bytes)", same)
        make_swat_archive(d3, seed=0, dup_identical=False)
        n3 = pd.read_csv(os.path.join(d3, "normal.csv"))
        d = n3[n3["Timestamp"].duplicated(keep=False)].drop_duplicates()
        check("dup_identical=False yields conflicting duplicates",
              d["Timestamp"].duplicated().sum() > 0)
        print("row counts:", truth["n_rows"], "dups:", truth["duplicate_timestamps"])

    print("\n%s" % ("ALL PASSED" if not failures else "FAILED: %s" % failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
