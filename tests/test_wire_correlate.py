"""
tests/test_wire_correlate.py - Phase 10: tools/wire_correlate.py matches wire frames to tracer entries by nonce and
cross-checks forward/drop against the PLC leg. Offline: the 'capture' is synthesised in tshark's exact TSV layout.

    python -m tests.test_wire_correlate
"""

from __future__ import annotations

import os
import tempfile
import time

os.environ.setdefault("IM_LOG_DIR", tempfile.mkdtemp(prefix="im-wire-"))

from core import hmac_auth# noqa: E402
from core.interfaces import FRAME_BASE, MACHINES, MV101, P101, make_command, to_raw  # noqa: E402
from core.netconfig import LOOPBACK  # noqa: E402
from middleware import cyber_agent, orchestrator, trace as tracer  # noqa: E402
from pipeline.multi_model_pipeline import MultiModelPipeline  # noqa: E402
from tools import wire_correlate as wc  # noqa: E402

orchestrator._forward_decision_to_dashboard = lambda payload: None
MW, PLC = 5021, 5020
fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global fails
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    fails += 0 if cond else 1


def state():
    regs = {m["register"]: m["initial"] for m in MACHINES}
    return {"registers": regs, "setpoints": dict(regs), "timestamp": time.time() - 10}


def cmd(frame, reg, tx):
    p = hmac_auth.parse_frame(frame)
    return make_command(tx, time.time(), LOOPBACK, 16, reg, p["raw_value"] / 10.0, raw_value=p["raw_value"], auth=p["auth"], source_port=5555)


pipe = MultiModelPipeline()
cyber_agent.reset_state()
good = hmac_auth.build_frame(MV101, 56.0)
tamp = hmac_auth.build_frame(P101, 71.0)
tamp[2] = to_raw(95.0)
sent = [("good", good, MV101, "t1"), ("tampered", tamp, P101, "t2"), ("replay-of-good", good, MV101, "t3")]
traces, mw_lines, plc_lines = [], [], []
t0 = time.time()
for i, (name, frame, reg, tx) in enumerate(sent):
    rep = pipe.process_command(cmd(frame, reg, tx), state())
    tr = rep["trace"]
    tr["short_id"] = f"TX-{i + 1:03d}"
    forwarded = rep["decision"]["verdict"] in ("PASS", "ALERT")
    tracer.add_outcome(tr, forwarded, None)
    traces.append(tr)
    mw_lines.append("\t".join([str(10 + i), f"{t0 + i:.6f}", LOOPBACK, str(MW), "16", str(FRAME_BASE), ",".join(str(w) for w in frame), ""]))
    if forwarded:
        plc_lines.append("\t".join([str(100 + i), f"{t0 + i:.6f}", LOOPBACK, str(PLC), "6", str(reg), "", f"{frame[2]:04x}"]))
mw_lines.append("\t".join(["99", f"{t0:.6f}", LOOPBACK, str(MW), "3", "0", "", ""]))     # a poll: must be ignored
d = tempfile.mkdtemp(prefix="wire-")
mw_path, plc_path = os.path.join(d, "mw.tsv"), os.path.join(d, "plc.tsv")
open(mw_path, "w").write("\n".join(mw_lines) + "\n")
open(plc_path, "w").write("\n".join(plc_lines) + "\n")

frames = wc.middleware_frames(mw_path, MW)
check("only signed FC16 frames are taken from the capture (polls ignored)", len(frames) == 3)
check("nonce words parsed from the capture equal the tracer's arrival-hop nonce words",
      frames[0]["nonce"] == tuple(traces[0]["hops"][0]["values"]["nonce_words"]))
rows = wc.correlate(frames, traces, wc.plc_writes(plc_path, PLC))
check("every wire frame is matched to its tracer entry", [r["tx"] for r in rows] == ["TX-001", "TX-002", "TX-003"])
check("forwarded frame is on the PLC leg; tampered and replayed frames are on the wire but NOT on the PLC leg",
      [r["on_plc_leg"] for r in rows] == [True, False, False], str([r["verdict"] for r in rows]))
check("everything is consistent", all(r["consistent"] for r in rows))
check("replay reuses the nonce but is matched to its own (later) trace", rows[0]["tx"] != rows[2]["tx"] and frames[0]["nonce"] == frames[2]["nonce"])

print("\nMISMATCH DETECTION")
bad = wc.correlate(frames, traces, [])           # PLC leg empty although frame 1 was forwarded
check("a forwarded command missing from the PLC capture is flagged", bad[0]["consistent"] is False)
leak = wc.correlate(frames, traces, wc.plc_writes(plc_path, PLC) + [(P101, 950)])   # a tampered value reached the PLC
check("a dropped command that reached the PLC is flagged", leak[1]["consistent"] is False and leak[1]["on_plc_leg"] is True)
unk = wc.correlate(frames, [], None)
check("a wire frame with no tracer entry is flagged", all(r["consistent"] is False for r in unk))

print("\nALL PASS" if fails == 0 else f"\n{fails} CHECK(S) FAILED")
raise SystemExit(1 if fails else 0)
