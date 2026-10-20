"""
tools/sim_four_laptops.py - run the whole four-laptop demo on ONE machine, over real Modbus/TCP, with a real packet capture, and
write a verification report that cross-checks four independent records of the same traffic.

    python -m tools.sim_four_laptops                 # full run (needs ~6 min: the physical model warms up for 120 s)
    python -m tools.sim_four_laptops --no-capture    # skip tshark (no capture privileges)
    python -m tools.sim_four_laptops --out <dir>     # keep the logs, captures and snapshot somewhere specific

Each role gets its own loopback address, so the cyber agent really does see four different peers - exactly what it will see when
the roles move to four laptops. Nothing here is mocked: real processes, real sockets, real HMAC frames.

    127.0.0.1:5021   Mac A      middleware (+ dashboard on :5050)
    127.0.0.2:5020   Windows A  PLC digital twin
    127.0.0.3        Mac B      SCADA operator       (trusted)
    127.0.0.4        Windows B  attacker             (on the trusted segment, but malicious)
    127.0.0.9        -          rogue host           (not in the trusted list)

The report answers four questions per command: where it came from, how far it got, why it stopped, and whether it reached the PLC.
Four records are compared and must agree: the packet capture (tshark), the middleware's Packet Tracer, the blocked-attack log, and
the dashboard's flow view. The capture is matched to the tracer by the frame NONCE, which is on the wire; the tx_id is not.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from typing import Any, Dict, List, Optional

ROOT = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
MW, PLC = "127.0.0.1", "127.0.0.2"
MW_PORT, PLC_PORT, DASH_PORT = 5021, 5020, 5050
SCADA_IP, ATTACKER_IP, ROGUE_IP = "127.0.0.3", "127.0.0.4", "127.0.0.9"
FIELDS = ["frame.number", "frame.time_epoch", "ip.src", "tcp.dstport", "modbus.func_code",
          "modbus.reference_num", "modbus.regval_uint16", "modbus.data"]

# The operator: four ordinary signed setpoint changes, sent from the SCADA address.
OPERATOR = r"""
import sys, time
sys.path.insert(0, %r)
from attacker import attacker as A
from docs.interfaces import MACHINE_BY_NAME
A._SOURCE_IP = sys.argv[1]
c = A.connect(A.MIDDLEWARE_HOST, A.MIDDLEWARE_PORT)
if c is None:
    raise SystemExit("operator could not reach the middleware")
for tag, v in (("P101", 72.0), ("MV101", 57.0), ("P302", 68.0), ("UV401", 72.0)):
    A.write_signed(c, MACHINE_BY_NAME[tag]["register"], v)
    time.sleep(1.2)
c.close()
""" % ROOT


class Sim:
    def __init__(self, out: str, capture: bool, warmup_s: int) -> None:
        self.out, self.capture, self.warmup_s = out, capture, warmup_s
        self.procs: List[Any] = []
        self.lines: List[str] = []
        self.env = dict(
            os.environ, PYTHONPATH=ROOT, PYTHONUNBUFFERED="1", IM_LOG_DIR=out,
            IM_PLC_HOST=PLC, IM_PLC_PORT=str(PLC_PORT), IM_PLC_LISTEN_HOST=PLC, IM_PLC_LISTEN_PORT=str(PLC_PORT),
            IM_MIDDLEWARE_HOST=MW, IM_MIDDLEWARE_PORT=str(MW_PORT), IM_LISTEN_HOST=MW, IM_LISTEN_PORT=str(MW_PORT),
            IM_DASHBOARD_HOST=MW, IM_DASHBOARD_PORT=str(DASH_PORT), IM_DASHBOARD_BIND_HOST=MW,
            IM_TRUSTED_SOURCES=f"{SCADA_IP},{ATTACKER_IP}",
            IM_HOST_LABELS=f"{SCADA_IP}=SCADA operator (Mac B),{ATTACKER_IP}=Attacker laptop (Windows B)",
            IM_HMAC_SECRET="four-laptop-simulation-shared-secret",
        )
        for leftover in ("IM_QUARANTINE", "IM_POLICY_FILE", "IM_DASHBOARD_TOKEN", "IM_HMAC_KEYS", "IM_HMAC_KEYS_FILE"):
            self.env.pop(leftover, None)

    # ----------------------------------------------------------------- plumbing
    def say(self, text: str = "") -> None:
        print(text)
        self.lines.append(text)

    def _spawn(self, args: List[str], name: str) -> subprocess.Popen:
        p = subprocess.Popen(args, cwd=ROOT, env=self.env,
                             stdout=open(os.path.join(self.out, f"{name}.log"), "w"), stderr=subprocess.STDOUT)
        self.procs.append((name, p))
        return p

    @staticmethod
    def _wait_port(host: str, port: int, timeout: float = 40.0) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            with socket.socket() as s:
                s.settimeout(0.4)
                if s.connect_ex((host, port)) == 0:
                    return True
            time.sleep(0.3)
        return False

    def _get(self, path: str) -> Any:
        with urllib.request.urlopen(f"http://{MW}:{DASH_PORT}{path}", timeout=5) as r:
            return json.loads(r.read().decode())

    def _tshark(self, port: int, name: str) -> None:
        cmd = ["tshark", "-i", "lo", "-l", "-f", f"tcp port {port}", "-o", f"mbtcp.tcp.port:{port}", "-Y", "mbtcp", "-T", "fields"]
        for f in FIELDS:
            cmd += ["-e", f]
        p = subprocess.Popen(cmd, stdout=open(os.path.join(self.out, f"{name}.tsv"), "w"),
                             stderr=open(os.path.join(self.out, f"{name}.err"), "w"))
        self.procs.append((name, p))

    def _pcap(self) -> None:
        p = subprocess.Popen(["tshark", "-i", "lo", "-f", f"tcp port {MW_PORT} or tcp port {PLC_PORT}",
                              "-w", os.path.join(self.out, "capture.pcapng")],
                             stdout=subprocess.DEVNULL, stderr=open(os.path.join(self.out, "pcap.err"), "w"))
        self.procs.append(("pcap", p))

    # ------------------------------------------------------------------- phases
    def phase(self, label: str, args: List[str], settle: float = 2.0) -> Dict[str, Any]:
        seq0 = self._get("/api/flow")["last_seq"]
        t0 = time.time()
        r = subprocess.run([sys.executable] + args, cwd=ROOT, env=self.env, capture_output=True, text=True, timeout=240)
        time.sleep(settle)
        events = self._get(f"/api/flow?since={seq0}")["events"]
        if r.returncode != 0:
            self.say(f"  !! {label} exited {r.returncode}: {(r.stderr or '')[-300:]}")
        return {"label": label, "t0": t0, "events": events, "rc": r.returncode, "stderr": (r.stderr or "")[-600:]}

    def run(self) -> Dict[str, Any]:
        self.say("Starting the four roles")
        self._spawn([sys.executable, "-m", "plc.plc"], "plc")
        self._spawn([sys.executable, "dashboard/app.py"], "dashboard")
        if not (self._wait_port(PLC, PLC_PORT) and self._wait_port(MW, DASH_PORT)):
            raise SystemExit(f"PLC or dashboard did not start - see {self.out}")
        if self.capture:
            self._tshark(MW_PORT, "wire_middleware")
            self._tshark(PLC_PORT, "wire_plc")
            self._pcap()
            time.sleep(2.0)
        self._spawn([sys.executable, "-m", "middleware.middleware_server"], "middleware")
        if not self._wait_port(MW, MW_PORT):
            raise SystemExit(f"middleware did not start - see {self.out}")
        self.say(f"  PLC {PLC}:{PLC_PORT} | middleware {MW}:{MW_PORT} | dashboard {MW}:{DASH_PORT}")
        self.say(f"  trusted sources: {SCADA_IP} (operator), {ATTACKER_IP} (attacker). {ROGUE_IP} is not trusted.")

        self.say(f"\nWaiting up to {self.warmup_s}s for the physical model's 120 s window to fill")
        mwlog = os.path.join(self.out, "middleware.log")
        for _ in range(self.warmup_s // 2):
            time.sleep(2)
            tail = open(mwlog).read()[-4000:]
            if "plant=NORMAL" in tail or "plant=ALERT" in tail:
                break
        self.say("  model is warm" if "plant=WARMING_UP" not in open(mwlog).read()[-1500:] else "  still warming (the model will abstain)")

        atk = ["-m", "attacker.attacker", "--host", MW, "--port", str(MW_PORT), "--plc-host", PLC, "--plc-port", str(PLC_PORT)]
        frm = lambda ip: ["--source-ip", ip]
        plan = [
            ("1. legitimate operator commands (Mac B)", ["-c", OPERATOR, SCADA_IP], 2.0),
            ("2. cyber layer: forged HMAC (Windows B)", atk + ["hmac-tamper"] + frm(ATTACKER_IP), 2.0),
            ("3. physical layer: impossible command (Windows B)", atk + ["impossible-command"] + frm(ATTACKER_IP), 2.0),
            ("4. bypass: direct write to the PLC (Windows B)", atk + ["false-injection"] + frm(ATTACKER_IP), 6.0),
            ("5. replay of a captured frame", atk + ["replay"] + frm(ATTACKER_IP), 2.0),
            ("6. rate-limit flood", atk + ["flood"] + frm(ATTACKER_IP), 2.0),
            ("7. unsigned command", atk + ["hmac-missing"] + frm(ATTACKER_IP), 2.0),
            ("8. rogue host outside the trusted list", atk + ["impossible-command"] + frm(ROGUE_IP), 2.0),
            ("9. operator commands while the plant is displaced", ["-c", OPERATOR, SCADA_IP], 3.0),
        ]
        phases = []
        for label, args, settle in plan:
            self.say(f"\n{label}")
            ph = self.phase(label, args, settle)
            for e in ph["events"]:
                self.say(f"    {e['tx']:7s} src={e['source_ip']:<10s} {str(e['command']):20s} -> {e['verdict']:5s} "
                         f"stopped_at={str(e['stopped_at']):8s} to_plc={str(e['forwarded']):5s}  {e['reason'][:70]}")
            if not ph["events"]:
                self.say("    (nothing reached the middleware - for phase 4 that IS the finding)")
            phases.append(ph)

        traces = {}
        for t in self._get("/api/traces"):
            try:
                traces[t["tx_id"]] = self._get(f"/api/trace/{t['tx_id']}")
            except Exception:
                pass
        snapshot = {"roles": {"middleware": f"{MW}:{MW_PORT}", "plc": f"{PLC}:{PLC_PORT}", "dashboard": f"{MW}:{DASH_PORT}",
                              "scada": SCADA_IP, "attacker": ATTACKER_IP, "rogue": ROGUE_IP},
                    "phases": [{k: v for k, v in p.items() if k != "stderr"} for p in phases],
                    "traces": traces, "incidents": self._get("/api/incidents"), "model": self._get("/api/model")}
        json.dump(snapshot, open(os.path.join(self.out, "snapshot.json"), "w"), indent=1, default=str)
        return snapshot

    def stop(self) -> None:
        time.sleep(1.5)
        for name, p in self.procs:
            p.send_signal(signal.SIGINT if name.startswith(("wire_", "pcap")) else signal.SIGTERM)
        time.sleep(1.5)
        for _, p in self.procs:
            if p.poll() is None:
                p.kill()


# --------------------------------------------------------------------- reporting
def cross_check(out: str, snapshot: Dict[str, Any]) -> Dict[str, Any]:
    """Compare the capture, the tracer, the blocked-attack log and the dashboard flow."""
    from tools import wire_correlate as wc
    res: Dict[str, Any] = {}
    mw_tsv, plc_tsv = os.path.join(out, "wire_middleware.tsv"), os.path.join(out, "wire_plc.tsv")
    if os.path.exists(mw_tsv):
        frames = wc.middleware_frames(mw_tsv, MW_PORT)
        plc = wc.plc_writes(plc_tsv, PLC_PORT) if os.path.exists(plc_tsv) else None
        rows = wc.correlate(frames, list(snapshot["traces"].values()), plc)
        res["correlation"] = {"frames": len(rows), "consistent": sum(1 for r in rows if r["consistent"]),
                              "mismatches": [r for r in rows if not r["consistent"]], "rows": rows}
        if os.path.exists(plc_tsv):
            bypass = [r for r in wc._rows(plc_tsv) if r["src"] not in (MW, PLC) and r["func"] in ("6", "16")]
            res["bypass_writes_on_plc_leg"] = bypass
    log_path = os.path.join(out, "blocked_attacks.jsonl")
    if os.path.exists(log_path):
        recs = [json.loads(l) for l in open(log_path) if l.strip()]
        res["blocked_log"] = {"records": len(recs),
                              "by_type": {t: sum(1 for r in recs if r.get("attack_type") == t)
                                          for t in sorted({r.get("attack_type") for r in recs})}}
    verdicts = [e["verdict"] for p in snapshot["phases"] for e in p["events"]]
    res["verdicts"] = {v: verdicts.count(v) for v in sorted(set(verdicts))}
    dropped = sum(1 for p in snapshot["phases"] for e in p["events"] if e["verdict"] == "DROP")
    res["drops_match_log"] = (res.get("blocked_log", {}).get("records") == dropped) if "blocked_log" in res else None
    return res


def render(snapshot: Dict[str, Any], checks: Dict[str, Any], out: str) -> str:
    r = snapshot["roles"]
    L = ["# Four-laptop system-flow verification", "",
         "Generated by `python -m tools.sim_four_laptops`. Four roles on one machine, each on its own loopback address, over real "
         "Modbus/TCP. Nothing is mocked and nothing is replayed from a fixture.", "",
         f"| role | address |", "|---|---|",
         f"| Mac A - middleware | {r['middleware']} |", f"| Mac A - dashboard | {r['dashboard']} |",
         f"| Windows A - PLC twin | {r['plc']} |", f"| Mac B - SCADA operator | {r['scada']} (trusted) |",
         f"| Windows B - attacker | {r['attacker']} (trusted segment, malicious) |",
         f"| rogue host | {r['rogue']} (not trusted) |", "",
         "## What each command did", "",
         "| phase | source | command | verdict | stopped at | reached the PLC | why |", "|---|---|---|---|---|---|---|"]
    for p in snapshot["phases"]:
        for e in p["events"]:
            L.append(f"| {p['label'].split('.')[0]} | {e['source_ip']} | {e['command']} = {e['value']} | **{e['verdict']}** | "
                     f"{e['stopped_at'] or '-'} | {'yes' if e['forwarded'] else 'no'} | {e['reason'][:70]} |")
        if not p["events"]:
            L.append(f"| {p['label'].split('.')[0]} | - | - | - | - | - | nothing reached the middleware |")
    L += ["", f"Verdicts: {checks['verdicts']}.", ""]
    c = checks.get("correlation")
    if c:
        L += ["## Cross-check: the capture against the Packet Tracer", "",
              "The tx_id is generated inside the middleware and is never on the wire. The 64-bit frame nonce is, so the two records are "
              "matched by nonce. A dropped frame must be present on the middleware leg and absent from the PLC leg.", "",
              f"**{c['frames']} signed frames captured, {c['consistent']} consistent with the tracer, {len(c['mismatches'])} mismatches.**", "",
              "| wire # | source | register | verdict | on the PLC leg | why |", "|---|---|---|---|---|---|"]
        for row in c["rows"]:
            L.append(f"| {row['frame']} | {row['src']} | {row['register']} | {row['verdict']} | "
                     f"{'yes' if row['on_plc_leg'] else 'NO'} | {row['reason'][:60]} |")
        L.append("")
    bp = checks.get("bypass_writes_on_plc_leg")
    if bp is not None:
        L += ["## The bypass, seen on the wire", "",
              (f"{len(bp)} write(s) reached the PLC from an address that is neither the middleware nor the PLC itself: "
               + ", ".join(f"frame {b['frame']} from {b['src']} (func {b['func']}, register {b['reference']})" for b in bp)
               if bp else "No direct-to-PLC writes in this run."), "",
              "An inline control only protects the path through it. This write never appears on the middleware leg, so no rule could "
              "have stopped it; it shows up afterwards in the plant's own behaviour and in the sensor-envelope rule.", ""]
    bl = checks.get("blocked_log")
    if bl:
        L += ["## Cross-check: the blocked-attack log", "",
              f"{bl['records']} records written to `logs/blocked_attacks.jsonl`" +
              (" - one per DROP in this run." if checks.get("drops_match_log") else
               " (the file is appended to, so it may hold records from earlier runs)."), "",
              "| attack type | records |", "|---|---|"]
        L += [f"| {k} | {v} |" for k, v in bl["by_type"].items()]
        L.append("")
    if snapshot.get("incidents"):
        L += ["## Cross-check: incident correlation", ""]
        L += [f"- `{i['id']}` **{i['severity']}** ({i['status']}) - {i['summary']}" for i in snapshot["incidents"]]
        L.append("")
    m = snapshot.get("model") or {}
    if m.get("model"):
        L += ["## The model that was running", "",
              f"{m['model']} ({m.get('variant')}), {m.get('features')} features over a {m.get('window_seconds')} s window, "
              f"threshold {m.get('threshold')}. {m.get('role')}.", "",
              f"Held out on real SWaT: {m.get('held_out_result')}", ""]
    L += ["## How to watch this in Wireshark", "",
          "A `capture.pcapng` of both legs is written next to this report. Open it and set **Edit -> Preferences -> Protocols -> "
          "Modbus/TCP -> Modbus/TCP port** to `5020,5021` (one range, both ports). Setting the preference twice does not work: the "
          "second value replaces the first and the other leg is then shown as *\"Unable to classify as query or response\"*.", "",
          "Useful display filters:", "",
          "- `mbtcp` - every Modbus frame",
          "- `modbus.func_code == 16 && modbus.reference_num == 100` - signed command frames (the nonce is words 3-6)",
          "- `modbus.func_code == 6 && tcp.dstport == 5020` - commands that were actually forwarded to the PLC",
          "- `ip.src == <attacker> && tcp.dstport == 5020` - a write that bypassed the middleware", "",
          f"Artifacts: `{out}`", ""]
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description="Four-laptop simulation on one machine, with capture and cross-checks.")
    ap.add_argument("--out", default=None, help="directory for logs, captures and the report (default: a temp directory)")
    ap.add_argument("--no-capture", action="store_true", help="do not run tshark (no capture privileges)")
    ap.add_argument("--warmup-s", type=int, default=300, help="how long to wait for the physical model's window to fill")
    a = ap.parse_args()
    out = a.out or tempfile.mkdtemp(prefix="im-sim4-")
    os.makedirs(out, exist_ok=True)
    sim = Sim(out, not a.no_capture, a.warmup_s)
    try:
        snapshot = sim.run()
    finally:
        sim.stop()
    checks = cross_check(out, snapshot)
    report = render(snapshot, checks, out)
    path = os.path.join(out, "system_flow_verification.md")
    open(path, "w").write(report)
    print("\n" + report)
    bad = len(checks.get("correlation", {}).get("mismatches", []))
    print(f"\nWrote {path}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
