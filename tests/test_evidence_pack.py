"""
tests/test_evidence_pack.py - the evidence-pack analysis and report logic, on a synthetic campaign record (no processes are started and no
files are written; the live campaign itself is run with `python -m benchmark.evidence_pack`).

    python -m tests.test_evidence_pack
"""

from __future__ import annotations

from benchmark import evidence_pack as E

fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global fails
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    fails += 0 if cond else 1


def ev(verdict, reason="OK"):
    return {"verdict": verdict, "reason": reason, "seq": 1}


campaign = {"status": "OK", "label": "LIVE (synthetic record for the test)", "ports": {}, "incidents": [{"id": "INC-0001", "severity": "high", "summary": "s"}],
            "phases": [
                {"name": "legitimate operator traffic", "kind": "benign", "completed": True, "seconds": 1.0, "events": [ev("PASS")] * 10, "upstream_drops": []},
                {"name": "flood", "kind": "attack", "completed": True, "seconds": 1.0,
                 "events": [ev("PASS")] * 5 + [ev("DROP", "RATE_LIMIT_EXCEEDED")] * 5, "upstream_drops": []},
                {"name": "hmac-forged", "kind": "attack", "completed": True, "seconds": 1.0, "events": [ev("DROP", "HMAC_INVALID:x")], "upstream_drops": []},
                {"name": "false-injection", "kind": "attack", "completed": True, "seconds": 1.0, "events": [ev("PASS")], "upstream_drops": []},
                {"name": "ghost", "kind": "attack", "completed": False, "seconds": 1.0, "events": [], "upstream_drops": [{"orchestrator": {"reason": "TELEMETRY_MISMATCH:x"}}]},
            ]}
a = E.analyse_campaign(campaign)
cm = a["command_confusion"]
check("benign PASS = TN, attack flagged = TP, attack PASS = FN", (cm["tn"], cm["fp"], cm["fn"], cm["tp"]) == (10, 0, 6, 6), str((cm["tn"], cm["fp"], cm["fn"], cm["tp"])))
check("recall/precision follow from the counts", cm["recall"] == 0.5 and cm["precision"] == 1.0 and cm["false_positive_rate"] == 0.0)
rows = {r["phase"]: r for r in a["rows"]}
check("the flood's first flag is the 6th command", rows["flood"]["first_flag_at_command"] == 6 and rows["flood"]["dropped"] == 5 and rows["flood"]["passed"] == 5)
check("reasons are grouped by code", rows["hmac-forged"]["reasons"] == {"HMAC_INVALID": 1})
check("an upstream (PLC->SCADA) drop counts as detection", rows["ghost"]["detected"] and rows["ghost"]["upstream_drops"] == 1)
check("false-injection is a documented miss and is marked as bypassing the middleware", not rows["false-injection"]["detected"] and not rows["false-injection"]["traverses_middleware"])
check("campaigns detected: counted over all attacks and over those that traverse the middleware",
      a["campaigns_detected"] == "3/4" and a["campaigns_detected_through_middleware"] == "3/3", f"{a['campaigns_detected']} / {a['campaigns_detected_through_middleware']}")
check("bulky event lists are dropped from the saved record", all("events" not in p for p in a["phases"]))
a2 = E.analyse_campaign({"status": "NOT RUN: x"})
check("a campaign that did not run is passed through untouched", a2["status"] == "NOT RUN: x")

md = E.render({"live": a, "response": {"label": "r"}, "recorded": {}})
check("the report states the phase-labelling caveat and names the matrix cells", "labelled by the phase" in md and "TN 10 / FP 0 / FN 6 / TP 6" in md)
check("the report shows the false-injection note (not selective)", "BYPASSES the middleware" in md and "not selective" in md)
check("the report keeps the three kinds of evidence apart", "## 1. Live campaign" in md and "## 2. Response layer" in md and "## 3. Recorded results" in md)
check("a skipped live run is reported as not run, not as zero", "NOT RUN (--no-live)" in E.render({"live": {"status": "NOT RUN (--no-live)"}, "response": {}, "recorded": {}}))

r = E.response_demo()
q = r["quarantine"]
sp = r["spoof_resistance"]
check("response demo: 40 FORGED commands spoofing an address do NOT quarantine it (AUDIT S4)",
      sp["quarantined_after_command"] is None, str(sp))
check("response demo: the spoofed device can still command the plant afterwards",
      sp["spoofed_device_can_still_command"] and sp["incident_severity"] in ("high", "critical"), str(sp))
check("response demo: AUTHENTICATED violations are quarantined after 2 commands and the rest are refused",
      q["quarantined_after_command"] == 2 and q["refused_while_quarantined"] == 8, str(q))
check("response demo: another source keeps working and the incident is critical", q["other_source_still_works"] and q["incident_severity"] == "critical")
check("response demo: policy cases give PASS / UNAUTHORIZED_VALUE / UNAUTHORIZED_REGISTER / UNAUTHORIZED_SOURCE",
      [p["reason"] for p in r["policy"]] == ["OK", "UNAUTHORIZED_VALUE", "UNAUTHORIZED_REGISTER", "UNAUTHORIZED_SOURCE"], str(r["policy"]))
rec = E.recorded()
check("recorded results are read from the repo and labelled", "swat" in rec and "rules" in rec and "CONSTRUCTED" in rec["rules"]["label"])

print("\nALL PASS" if fails == 0 else f"\n{fails} CHECK(S) FAILED")
raise SystemExit(1 if fails else 0)
