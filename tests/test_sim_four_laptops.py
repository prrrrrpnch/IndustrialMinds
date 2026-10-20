"""
tests/test_sim_four_laptops.py - the cross-check and reporting layer of the four-laptop simulation, on a synthetic snapshot.

No processes are started here: the live run is `python -m tools.sim_four_laptops`. What is checked is the part that decides whether
the four records (capture, tracer, blocked-attack log, dashboard flow) agree, because that is what the verification claim rests on.

    python -m tests.test_sim_four_laptops
"""

from __future__ import annotations

import json
import os
import tempfile

from core.interfaces import FRAME_BASE, FRAME_LEN
from tools import sim_four_laptops as S

fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global fails
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    fails += 0 if cond else 1


OUT = tempfile.mkdtemp(prefix="im-sim-test-")
NONCE_OK, NONCE_BAD = (1, 2, 3, 4), (5, 6, 7, 8)


def frame_row(n: int, src: str, nonce, register: int, raw: int, dstport: int = S.MW_PORT) -> str:
    words = [1, register, raw, *nonce] + [0] * (FRAME_LEN - 7)
    return "\t".join([str(n), f"17924780{n:02d}.0", src, str(dstport), "16", str(FRAME_BASE),
                      ",".join(str(w) for w in words), ""])


def trace(short: str, nonce, verdict: str, reason: str) -> dict:
    return {"short_id": short, "tx_id": short, "time": 1.0, "verdict": verdict, "reason": reason,
            "hops": [{"hop": "arrival", "values": {"nonce_words": list(nonce)}}]}


# a capture with one forwarded command and one dropped one, plus a write that bypassed the middleware
open(os.path.join(OUT, "wire_middleware.tsv"), "w").write(
    frame_row(10, S.SCADA_IP, NONCE_OK, 1, 720) + "\n" + frame_row(20, S.ATTACKER_IP, NONCE_BAD, 1, 9990) + "\n")
open(os.path.join(OUT, "wire_plc.tsv"), "w").write(
    "\t".join(["30", "1792478030.0", S.MW, str(S.PLC_PORT), "6", "1", "", "02d0"]) + "\n" +
    "\t".join(["31", "1792478031.0", S.ATTACKER_IP, str(S.PLC_PORT), "6", "0", "", "0000"]) + "\n")
open(os.path.join(OUT, "blocked_attacks.jsonl"), "w").write(
    json.dumps({"attack_type": "Impossible Command (Out of Bounds)", "source_ip": S.ATTACKER_IP}) + "\n")

snapshot = {
    "roles": {"middleware": f"{S.MW}:{S.MW_PORT}", "plc": f"{S.PLC}:{S.PLC_PORT}", "dashboard": f"{S.MW}:{S.DASH_PORT}",
              "scada": S.SCADA_IP, "attacker": S.ATTACKER_IP, "rogue": S.ROGUE_IP},
    "phases": [
        {"label": "1. legitimate operator commands", "events": [
            {"tx": "TX-001", "source_ip": S.SCADA_IP, "command": "P101 (#1)", "value": 72.0, "verdict": "PASS",
             "stopped_at": None, "forwarded": True, "reason": "OK"}]},
        {"label": "3. physical layer: impossible command", "events": [
            {"tx": "TX-002", "source_ip": S.ATTACKER_IP, "command": "P101 (#1)", "value": 999.0, "verdict": "DROP",
             "stopped_at": "physical", "forwarded": False, "reason": "OUT_OF_BOUNDS:P101=999.00"}]},
        {"label": "4. bypass: direct write to the PLC", "events": []},
    ],
    "traces": {"a": trace("TX-001", NONCE_OK, "PASS", "OK"), "b": trace("TX-002", NONCE_BAD, "DROP", "OUT_OF_BOUNDS:P101=999.00")},
    "incidents": [{"id": "INC-0001", "severity": "high", "status": "open", "summary": "127.0.0.4: 1 event"}],
    "model": {"model": "PhysicalModelV2", "variant": "v2", "features": 117, "window_seconds": 120, "threshold": 0.788,
              "role": "advisory: it can never DROP", "held_out_result": "F1 0.485"},
}

print("CROSS-CHECK")
c = S.cross_check(OUT, snapshot)
corr = c["correlation"]
check("every signed frame on the wire is matched to a tracer entry by nonce",
      corr["frames"] == 2 and corr["consistent"] == 2 and corr["mismatches"] == [], str(corr["frames"]))
rows = {r["src"]: r for r in corr["rows"]}
check("a forwarded command is found on the PLC leg", rows[S.SCADA_IP]["verdict"] == "PASS" and rows[S.SCADA_IP]["on_plc_leg"] is True)
check("a dropped command is absent from the PLC leg", rows[S.ATTACKER_IP]["verdict"] == "DROP" and rows[S.ATTACKER_IP]["on_plc_leg"] is False)
check("the direct-to-PLC write is reported as a bypass",
      len(c["bypass_writes_on_plc_leg"]) == 1 and c["bypass_writes_on_plc_leg"][0]["src"] == S.ATTACKER_IP,
      str(len(c["bypass_writes_on_plc_leg"])))
check("the middleware's own forwarded write is NOT called a bypass",
      all(b["src"] != S.MW for b in c["bypass_writes_on_plc_leg"]))
check("verdicts are counted from the dashboard flow", c["verdicts"] == {"DROP": 1, "PASS": 1}, str(c["verdicts"]))
check("the blocked-attack log is summarised by attack type", c["blocked_log"]["records"] == 1
      and c["blocked_log"]["by_type"] == {"Impossible Command (Out of Bounds)": 1})
check("one record per DROP means the log agrees with the decisions", c["drops_match_log"] is True)

print("\nCROSS-CHECK catches disagreement")
bad = dict(snapshot, traces={"a": trace("TX-001", NONCE_OK, "PASS", "OK"),
                             "b": trace("TX-002", NONCE_BAD, "PASS", "OK")})      # tracer claims the attack was forwarded
cb = S.cross_check(OUT, bad)
check("a frame the tracer calls PASS but that never reached the PLC is a mismatch",
      len(cb["correlation"]["mismatches"]) == 1, str(len(cb["correlation"]["mismatches"])))
missing = dict(snapshot, traces={"a": trace("TX-001", NONCE_OK, "PASS", "OK")})
cm = S.cross_check(OUT, missing)
check("a frame on the wire with no tracer entry at all is a mismatch",
      len(cm["correlation"]["mismatches"]) == 1 and "no tracer entry" in cm["correlation"]["mismatches"][0]["reason"])
empty = S.cross_check(tempfile.mkdtemp(prefix="im-sim-none-"), snapshot)
check("with no capture the report still works, without correlation claims",
      "correlation" not in empty and empty["verdicts"] == {"DROP": 1, "PASS": 1} and empty["drops_match_log"] is None)

print("\nREPORT")
md = S.render(snapshot, c, OUT)
check("the report names every role and its address", all(a in md for a in (S.SCADA_IP, S.ATTACKER_IP, S.ROGUE_IP, S.PLC)))
check("the per-command table says where each command stopped and whether it reached the PLC",
      "| stopped at | reached the PLC |" in md and "OUT_OF_BOUNDS:P101=999.00" in md)
check("the correlation result is stated with its counts", "2 signed frames captured, 2 consistent with the tracer, 0 mismatches" in md)
check("the bypass is reported, with the frame and the source", "## The bypass, seen on the wire" in md and "frame 31 from 127.0.0.4" in md)
check("the blocked-attack log and the incidents are both quoted", "blocked_attacks.jsonl" in md and "INC-0001" in md)
check("the model that was running is named, with its held-out result and its advisory role",
      "PhysicalModelV2" in md and "F1 0.485" in md and "never DROP" in md)
check("the Wireshark instructions give the range preference and warn about setting it twice",
      "5020,5021" in md and "second value replaces the first" in md)
check("a phase where nothing reached the middleware is still shown", "nothing reached the middleware" in md)

print("\nSETUP")
check("each role has a distinct address", len({S.MW, S.PLC, S.SCADA_IP, S.ATTACKER_IP, S.ROGUE_IP}) == 5)
check("the rogue host is deliberately outside the trusted list",
      S.ROGUE_IP not in (S.SCADA_IP, S.ATTACKER_IP))
sim = S.Sim(OUT, capture=False, warmup_s=1)
check("the simulation never inherits an opt-in setting that would change the verdicts",
      all(k not in sim.env for k in ("IM_QUARANTINE", "IM_POLICY_FILE", "IM_DASHBOARD_TOKEN", "IM_HMAC_KEYS")))
check("the trusted list is exactly the operator and the attacker", sim.env["IM_TRUSTED_SOURCES"] == f"{S.SCADA_IP},{S.ATTACKER_IP}")
check("the operator script signs its commands like SCADA does", "write_signed" in S.OPERATOR and "MACHINE_BY_NAME" in S.OPERATOR)

print("\nALL PASS" if fails == 0 else f"\n{fails} CHECK(S) FAILED")
raise SystemExit(1 if fails else 0)
