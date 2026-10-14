"""
tests/test_trace.py - Phase 9: the packet-tracer trace must match what the backend actually computed.

    python -m tests.test_trace
"""

from __future__ import annotations

import os
import tempfile
import time

os.environ.setdefault("IM_LOG_DIR", tempfile.mkdtemp(prefix="im-trace-"))

from docs import hmac_auth  # noqa: E402
from docs.interfaces import MACHINES, MV101, P101, LIT101, make_command, to_raw  # noqa: E402
from docs.netconfig import LOOPBACK  # noqa: E402
from middleware import cyber_agent, orchestrator, trace as tracer  # noqa: E402
from pipeline.multi_model_pipeline import MultiModelPipeline  # noqa: E402

orchestrator._forward_decision_to_dashboard = lambda payload: None
UNTRUSTED = "127.30.0.9"        # loopback address that is not in the trusted-source list
fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global fails
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    fails += 0 if cond else 1


def cmd_from_frame(frame, reg, tx="tx", ip=LOOPBACK, fc=16):
    p = hmac_auth.parse_frame(frame)
    return make_command(tx, time.time(), ip, fc, reg, p["raw_value"] / 10.0, raw_value=p["raw_value"], auth=p["auth"], source_port=5555)


def signed(reg, value, **kw):
    return cmd_from_frame(hmac_auth.build_frame(reg, value), reg, **kw)


def state():
    regs = {m["register"]: m["initial"] for m in MACHINES}
    return {"registers": regs, "setpoints": dict(regs), "timestamp": time.time() - 10}


pipe = MultiModelPipeline()
hop = lambda t, name: next(h for h in t["hops"] if h["hop"] == name)
res = lambda h: {c["check"]: c["result"] for c in h["checks"]}

cases = {}
cyber_agent.reset_state()
cases["legit"] = pipe.process_command(signed(MV101, 56.0, tx="a"), state())
bad = hmac_auth.build_frame(MV101, 56.0)
bad[2] = to_raw(90.0)                                   # value changed after signing
cyber_agent.reset_state()
cases["hmac_invalid"] = pipe.process_command(cmd_from_frame(bad, MV101, tx="b"), state())
cyber_agent.reset_state()
cases["untrusted"] = pipe.process_command(signed(MV101, 56.0, tx="c", ip=UNTRUSTED), state())
cyber_agent.reset_state()
cases["out_of_bounds"] = pipe.process_command(signed(P101, 999.0, tx="d"), state())
cyber_agent.reset_state()
cases["sensor_write"] = pipe.process_command(signed(LIT101, 500.0, tx="e"), state())
cyber_agent.reset_state()
f = hmac_auth.build_frame(MV101, 56.0)
first = pipe.process_command(cmd_from_frame(f, MV101, tx="f1"), state())
cases["replay"] = pipe.process_command(cmd_from_frame(f, MV101, tx="f2"), state())

print("STRUCTURE")
for name, rep in cases.items():
    t = rep["trace"]
    check(f"{name}: trace has the 6 pipeline hops in order",
          [h["hop"] for h in t["hops"]] == ["arrival", "cyber_rules", "cyber_model", "physical_rules", "physical_model", "orchestrator"])
    check(f"{name}: trace verdict/reason equal the orchestrator decision",
          t["verdict"] == rep["decision"]["verdict"] and t["reason"] == rep["decision"]["reason"] and t["tx_id"] == rep["tx_id"])

print("\nVALUES MATCH THE BACKEND")
t = cases["legit"]["trace"]
check("legit: cyber and physical rule hops PASS with every check PASS",
      hop(t, "cyber_rules")["outcome"] == "PASS" and set(res(hop(t, "cyber_rules")).values()) == {"PASS"}
      and hop(t, "physical_rules")["outcome"] == "PASS" and set(res(hop(t, "physical_rules")).values()) == {"PASS"})
arr = hop(t, "arrival")["values"]
check("arrival hop exposes the frame nonce as the 4 wire words (for Wireshark correlation)",
      arr["nonce_words"] == hmac_auth._u64_to_regs(int(arr["nonce"], 16)) and len(arr["nonce_words"]) == 4)
check("arrival hop carries the real peer, function code, register, value and signature state",
      arr["function_code"] == 16 and arr["requested_value"] == 56.0 and arr["signature"] == "present" and LOOPBACK in arr["source"])
pm_rep, pm_hop = cases["legit"]["physical"]["model"], hop(t, "physical_model")["values"]
check("physical_model hop shows the same status / plant_state / scores / flags the model returned",
      all(pm_hop[k] == pm_rep.get(k) for k in ("status", "plant_state", "anomaly_score", "attack_probability", "threat_flag", "flagged_by"))
      and pm_hop["thresholds"]["classifier"] == pm_rep.get("clf_threshold")
      and pm_hop["thresholds"]["isolation_forest"] == pm_rep.get("threshold"))
check("cyber_model hop mirrors the cyber model report (NO_MODEL: rules-only)",
      hop(t, "cyber_model")["values"]["status"] == cases["legit"]["cyber"]["model"]["status"])
fu = hop(t, "orchestrator")["values"]
check("orchestrator hop shows its real inputs and the branch taken",
      fu["inputs"]["cyber_rules_pass"] is True and fu["inputs"]["physical_rules_pass"] is True
      and fu["branch"] in ("all_clear", "rules_passed_physical_model_flagged"))


def failing(rep, hop_name):
    return [c["check"] for c in hop(rep["trace"], hop_name)["checks"] if c["result"] == "FAIL"]


check("tampered HMAC: cyber 'hmac' check FAILS, 'replay' NOT_RUN, earlier checks PASS",
      failing(cases["hmac_invalid"], "cyber_rules") == ["hmac"]
      and res(hop(cases["hmac_invalid"]["trace"], "cyber_rules"))["replay"] == "NOT_RUN"
      and res(hop(cases["hmac_invalid"]["trace"], "cyber_rules"))["rate_limit"] == "PASS")
check("tampered HMAC: orchestrator branch is cyber_rules_failed and the verdict is DROP",
      hop(cases["hmac_invalid"]["trace"], "orchestrator")["values"]["branch"] == "cyber_rules_failed"
      and cases["hmac_invalid"]["decision"]["verdict"] == "DROP")
check("untrusted source fails the FIRST check and everything after is NOT_RUN",
      failing(cases["untrusted"], "cyber_rules") == ["source_whitelist"]
      and [c["result"] for c in hop(cases["untrusted"]["trace"], "cyber_rules")["checks"]][1:] == ["NOT_RUN"] * 5)
check("out-of-bounds: physical 'bounds' check FAILS and its reason is the agent's own reason",
      failing(cases["out_of_bounds"], "physical_rules") == ["bounds"]
      and hop(cases["out_of_bounds"]["trace"], "physical_rules")["values"]["reason"] == cases["out_of_bounds"]["physical"]["rule_verdict"]["reason"])
check("sensor write: physical 'actuator_only' check FAILS", failing(cases["sensor_write"], "physical_rules") == ["actuator_only"])
check("replay: first send passes, the repeated frame fails the cyber 'replay' check",
      first["decision"]["verdict"] in ("PASS", "ALERT") and failing(cases["replay"], "cyber_rules") == ["replay"])
check("rate-limit detail shows the real limit",
      "limit 5" in next(c for c in hop(cases["legit"]["trace"], "cyber_rules")["checks"] if c["check"] == "rate_limit")["detail"])

print("\nOUTCOME HOP")
tt = tracer.add_outcome(dict(cases["out_of_bounds"]["trace"]), forwarded=False, logged_to="logs/blocked_attacks.jsonl", note="n")
o = hop(tt, "outcome")["values"]
check("DROP: outcome says not forwarded and names the log file",
      o["dropped"] is True and o["forwarded_to_plc"] is False and o["logged_to"].endswith("blocked_attacks.jsonl"))
tt = tracer.add_outcome(dict(cases["legit"]["trace"]), forwarded=True, logged_to=None)
check("forwarded command: outcome PASS, forwarded_to_plc true",
      hop(tt, "outcome")["outcome"] == "PASS" and hop(tt, "outcome")["values"]["forwarded_to_plc"] is True)
check("add_outcome is idempotent (a single outcome hop)", sum(h["hop"] == "outcome" for h in tracer.add_outcome(tt, True, None)["hops"]) == 1)

print("\nALL PASS" if fails == 0 else f"\n{fails} CHECK(S) FAILED")
raise SystemExit(1 if fails else 0)
