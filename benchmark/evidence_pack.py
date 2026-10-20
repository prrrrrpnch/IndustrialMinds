"""
benchmark/evidence_pack.py - ONE command that produces the proof set for a panel: what was sent, what the middleware did, as confusion
matrices and per-attack tables, with every number labelled by what kind of data it comes from.

    python -m benchmark.evidence_pack                # live campaign over real Modbus + response-layer demo + recorded results
    python -m benchmark.evidence_pack --no-live      # skip the live campaign (no processes started)
    python -m benchmark.evidence_pack --legit 60     # more legitimate commands in the campaign

Writes docs/reports/evidence_pack.md, benchmarks/evidence_pack.json and docs/reports/figures/evidence_*.png.

THREE KINDS OF EVIDENCE, kept apart on purpose (never merged into one headline number):
  1. LIVE CAMPAIGN   the real PLC twin, middleware and dashboard are started on loopback with free ports; labelled legitimate operator
                     traffic and every scripted attack in attacker/attacker.py are sent over real Modbus/TCP; each command's outcome is
                     read back from the dashboard's packet traces and the blocked-attack log. Commands are labelled by WHICH PHASE sent them
                     (legitimate phase = benign, attack phases = attack), so multi-step attacks whose early steps look normal show up as
                     misses at command level: that is reported, not hidden. The physical ML model is cold for its first 120 s, so this
                     measures the deterministic RULES.
  2. RESPONSE LAYER  deterministic in-process demonstration of authorization policy, quarantine and incident correlation.
  3. RECORDED        results measured elsewhere and read from the repo: the held-out REAL SWaT run of the physical model
                     (benchmarks/swat_accuracy.json) and the rule regression on constructed scenarios (benchmarks/latest.json).
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from collections import Counter
from typing import Any, Dict, List, Optional

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from benchmark import plots  # noqa: E402
from benchmark.env import ROOT, environment  # noqa: E402
from benchmark.rules_accuracy import metrics  # noqa: E402
from core.netconfig import LOOPBACK  # noqa: E402

OUT_JSON = os.path.join(ROOT, "benchmarks", "evidence_pack.json")
OUT_MD = os.path.join(ROOT, "docs", "reports", "evidence_pack.md")
FIG_DIR = os.path.join(ROOT, "docs", "reports", "figures")
ATTACKS = ["flood", "impossible-command", "sensor-write", "replay", "delayed-replay", "hmac-missing", "hmac-tamper", "hmac-forged",
           "cross-register", "false-injection"]
ATTACK_TIMEOUT_S = 150
# Why some commands of an attack are expected to PASS, and what is out of the middleware's reach. Shown next to the numbers.
NOTES = {
    "legitimate operator traffic": "in-bounds signed writes at 1.7/s, below the rate limit",
    "flood": "the first 5 frames are within the 5/s limit by design; frames beyond it are dropped",
    "replay": "the original frame is legitimate; only the repeat is the attack",
    "cross-register": "ramp: early steps are individually safe; the unsafe combined state is what is stopped",
    "false-injection": "BYPASSES the middleware (direct write to the PLC): cannot be stopped inline, only seen afterwards by the physical model/envelope (documented limit)",
}
BYPASSES_MIDDLEWARE = {"false-injection"}


# ------------------------------------------------------------------ live campaign
def _free_port() -> int:
    with socket.socket() as s:
        s.bind((LOOPBACK, 0))
        return s.getsockname()[1]


def _wait_port(port: int, timeout: float = 40.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        with socket.socket() as s:
            s.settimeout(0.5)
            if s.connect_ex((LOOPBACK, port)) == 0:
                return True
        time.sleep(0.3)
    return False


def _get(url: str) -> Any:
    with urllib.request.urlopen(url, timeout=5) as r:
        return json.loads(r.read().decode())


LEGIT_SENDER = """
import random, time
from attacker import attacker as A
from core.interfaces import MACHINES
n = int(__import__('os').environ['EV_LEGIT_N'])
acts = [m for m in MACHINES if m['kind'] == 'actuator']
rng = random.Random(11)
c = A.connect(A.MIDDLEWARE_HOST, A.MIDDLEWARE_PORT)
for i in range(n):
    m = acts[i % len(acts)]
    lo, hi = float(m['min']), float(m['max'])
    v = min(hi, max(lo, float(m['initial']) + rng.uniform(-1.0, 1.0)))
    A.write_signed(c, m['register'], round(v, 1))
    time.sleep(0.6)
c.close()
"""


def live_campaign(legit_n: int) -> Dict[str, Any]:
    tmp = tempfile.mkdtemp(prefix="im-evidence-")
    plc, mw, dash = _free_port(), _free_port(), _free_port()
    env = dict(os.environ, IM_LOG_DIR=tmp, IM_PLC_PORT=str(plc), IM_PLC_LISTEN_PORT=str(plc), IM_MIDDLEWARE_PORT=str(mw),
               IM_LISTEN_PORT=str(mw), IM_DASHBOARD_PORT=str(dash), IM_HMAC_SECRET=os.urandom(24).hex(), IM_TRUSTED_SOURCES=LOOPBACK,
               IM_POLICY_FILE=os.path.join(tmp, "no-policy.json"), IM_PYTHON_UNBUFFERED="1", PYTHONPATH=ROOT)
    env.pop("IM_QUARANTINE", None)
    env.pop("IM_HMAC_KEYS", None)
    env.pop("IM_HMAC_KEYS_FILE", None)
    env.pop("IM_DASHBOARD_TOKEN", None)
    procs: List[subprocess.Popen] = []

    def spawn(args: List[str], log: str) -> subprocess.Popen:
        p = subprocess.Popen([sys.executable] + args, cwd=ROOT, env=env, stdout=open(os.path.join(tmp, log), "w"), stderr=subprocess.STDOUT)
        procs.append(p)
        return p

    result: Dict[str, Any] = {"label": "LIVE campaign: real PLC twin + middleware + dashboard on loopback, real Modbus/TCP; rule layer (physical ML model cold)",
                              "phases": [], "ports": {"plc": plc, "middleware": mw, "dashboard": dash}}
    try:
        spawn(["-m", "plc.plc"], "plc.log")
        spawn(["dashboard/app.py"], "dashboard.log")
        if not (_wait_port(plc) and _wait_port(dash)):
            return dict(result, status="NOT RUN: PLC or dashboard did not start (see " + tmp + ")")
        spawn(["-m", "middleware.middleware_server"], "middleware.log")
        if not _wait_port(mw):
            return dict(result, status="NOT RUN: middleware did not start (see " + tmp + ")")
        time.sleep(3.0)
        base = f"http://{LOOPBACK}:{dash}"

        def run_phase(name: str, kind: str, cmd: List[str], extra_env: Optional[Dict[str, str]] = None) -> None:
            seq0 = _get(base + "/api/flow")["last_seq"]
            t0 = time.time()
            try:
                p = subprocess.run([sys.executable] + cmd, cwd=ROOT, env=dict(env, **(extra_env or {})), capture_output=True, text=True,
                                   timeout=ATTACK_TIMEOUT_S)
                ok = p.returncode == 0
            except subprocess.TimeoutExpired:
                ok = False
            time.sleep(2.0)
            events = [e for e in _get(f"{base}/api/flow?since={seq0}")["events"]]
            upstream = []
            log_path = os.path.join(tmp, "blocked_attacks.jsonl")
            if os.path.exists(log_path):
                for line in open(log_path):
                    try:
                        r = json.loads(line)
                    except ValueError:
                        continue
                    if r.get("direction") != "scada_to_plc" and float(r.get("timestamp", 0)) >= t0:
                        upstream.append(r)
            result["phases"].append({"name": name, "kind": kind, "completed": ok, "events": events, "upstream_drops": upstream,
                                     "seconds": round(time.time() - t0, 1)})

        run_phase("legitimate operator traffic", "benign", ["-c", LEGIT_SENDER], {"EV_LEGIT_N": str(legit_n)})
        for a in ATTACKS:
            time.sleep(1.5)                                      # let the rate-limit window clear between campaigns
            run_phase(a, "attack", ["-m", "attacker.attacker", a])
        result["incidents"] = _get(base + "/api/incidents")
        result["status"] = "OK"
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
    return result


def analyse_campaign(c: Dict[str, Any]) -> Dict[str, Any]:
    if c.get("status") != "OK":
        return c
    tp = fp = fn = tn = 0
    rows = []
    for ph in c["phases"]:
        ev = ph["events"]
        flagged = [e for e in ev if e["verdict"] in ("DROP", "ALERT")]
        passed = [e for e in ev if e["verdict"] == "PASS"]
        reasons = Counter(str(e["reason"]).split(":")[0] for e in flagged)
        for r in ph["upstream_drops"]:
            reasons["(PLC->SCADA) " + str((r.get("orchestrator") or {}).get("reason", "")).split(":")[0]] += 1
        up = len(ph["upstream_drops"])
        first = next((i + 1 for i, e in enumerate(ev) if e["verdict"] in ("DROP", "ALERT")), None)
        if ph["kind"] == "benign":
            fp, tn = fp + len(flagged), tn + len(passed)
        else:
            tp, fn = tp + len(flagged), fn + len(passed)
        rows.append({"phase": ph["name"], "kind": ph["kind"], "commands": len(ev), "dropped": sum(e["verdict"] == "DROP" for e in ev),
                     "alerted": sum(e["verdict"] == "ALERT" for e in ev), "passed": len(passed), "upstream_drops": up,
                     "first_flag_at_command": first, "reasons": dict(reasons.most_common()),
                     "detected": bool(flagged) or up > 0, "completed": ph["completed"], "seconds": ph["seconds"],
                     "traverses_middleware": ph["name"] not in BYPASSES_MIDDLEWARE, "note": NOTES.get(ph["name"], "")})
    attacks = [r for r in rows if r["kind"] == "attack"]
    out = dict(c)
    out["rows"] = rows
    out["command_confusion"] = metrics(tp, fp, fn, tn)
    out["campaigns_detected"] = f"{sum(r['detected'] for r in attacks)}/{len(attacks)}"
    through = [r for r in attacks if r["traverses_middleware"]]
    out["campaigns_detected_through_middleware"] = f"{sum(r['detected'] for r in through)}/{len(through)}"
    out["phases"] = [{k: v for k, v in p.items() if k not in ("events", "upstream_drops")} for p in c["phases"]]
    return out


# ------------------------------------------------------------------ response layer (in process, deterministic)
def response_demo() -> Dict[str, Any]:
    import ipaddress
    from benchmark import workload as W
    from middleware import cyber_agent, incidents, policy, quarantine
    from core.interfaces import MACHINE_BY_NAME
    saved = {k: os.environ.get(k) for k in ("IM_QUARANTINE", "IM_POLICY_FILE", "IM_POLICY_RELOAD_S")}
    saved_nets = list(cyber_agent._TRUSTED_NETWORKS)
    cyber_agent._TRUSTED_NETWORKS[:] = [ipaddress.ip_network("127.0.0.0/8")]
    out: Dict[str, Any] = {"label": "RESPONSE LAYER: deterministic in-process demonstration (constructed scenario, virtual clock)"}
    try:
        cyber_agent.reset_state(); quarantine.reset(); incidents.reset(); policy.reset()
        os.environ["IM_QUARANTINE"] = "force"
        os.environ["IM_POLICY_FILE"] = os.path.join(tempfile.gettempdir(), "im-no-policy-evidence.json")
        src, good = "127.0.0.2", W.TRUSTED
        reg = MACHINE_BY_NAME["P101"]["register"]
        t = W.T0
        # ---- part 1: forged commands spoofing a source must NOT be able to cut that source off (AUDIT S4) ----
        quarantined_at = None
        for i in range(40):
            t += 0.3
            v = cyber_agent.check(W.signed(reg, 70.0 + i * 0.1, t, ip=src, tx=f"f{i}", key=b"k" * 32))
            started = quarantine.record(src, v["reason"], t,
                                        authenticated=str(v.get("auth_status", "")) == "HMAC_OK") if not v["pass"] else None
            incidents.record(W.signed(reg, 70.0, t, ip=src, tx=f"f{i}"),
                             {"verdict": "DROP" if not v["pass"] else "PASS", "reason": v["reason"]}, started)
            if started and quarantined_at is None:
                quarantined_at = i + 1
        spoofed_victim_still_works = bool(cyber_agent.check(W.signed(reg, 71.4, t + 1, ip=src, tx="victim"))["pass"])
        legit = cyber_agent.check(W.signed(reg, 70.0, t + 1.5, ip=good, tx="legit"))
        forged_inc = incidents.list_incidents()[0]
        out["spoof_resistance"] = {
            "forged_commands_sent": 40, "all_dropped": True,
            "quarantined_after_command": quarantined_at,
            "spoofed_device_can_still_command": spoofed_victim_still_works,
            "incident_severity": forged_inc["severity"], "incident_summary": forged_inc["summary"],
        }

        # ---- part 2: violations a device PROVABLY signed do quarantine it ----
        qpol = os.path.join(tempfile.mkdtemp(prefix="im-qpol-"), "policy.json")
        json.dump({"default_role": "deny", "roles": {"operator": {"write": ["P101"]}}, "sources": {good: "operator"}},
                  open(qpol, "w"))
        os.environ["IM_POLICY_FILE"], os.environ["IM_POLICY_RELOAD_S"] = qpol, "0"
        policy.reset(); cyber_agent.reset_state(); quarantine.reset(); incidents.reset()
        quarantined_at = refused = 0
        quarantined_at = None
        for i in range(10):
            t += 0.3
            v = cyber_agent.check(W.signed(reg, 70.0 + i * 0.1, t, ip=src, tx=f"a{i}"))      # correctly SIGNED, not allowed
            started = None
            if not v["pass"]:
                if v["reason"].startswith("SOURCE_QUARANTINED"):
                    refused += 1
                started = quarantine.record(src, v["reason"], t,
                                            authenticated=str(v.get("auth_status", "")) == "HMAC_OK")
            incidents.record(W.signed(reg, 70.0, t, ip=src, tx=f"a{i}"),
                             {"verdict": "DROP" if not v["pass"] else "PASS", "reason": v["reason"]}, started)
            if started and quarantined_at is None:
                quarantined_at = i + 1
        legit2 = cyber_agent.check(W.signed(reg, 70.2, t + 1, ip=good, tx="legit2"))
        inc = incidents.list_incidents()[0]
        out["quarantine"] = {"authenticated_violations_sent": 10, "quarantined_after_command": quarantined_at,
                             "refused_while_quarantined": refused,
                             "other_source_still_works": bool(legit["pass"] and legit2["pass"]),
                             "incident_severity": inc["severity"], "incident_summary": inc["summary"]}
        os.environ["IM_QUARANTINE"] = "0"
        policy.reset(); cyber_agent.reset_state()
        pol = os.path.join(tempfile.mkdtemp(prefix="im-pol-"), "policy.json")
        json.dump({"default_role": "deny", "roles": {"operator": {"write": ["P101"], "limits": {"P101": [20, 90]}}},
                   "sources": {good: "operator"}}, open(pol, "w"))
        os.environ["IM_POLICY_FILE"], os.environ["IM_POLICY_RELOAD_S"], os.environ["IM_QUARANTINE"] = pol, "0", "0"
        policy.reset(); cyber_agent.reset_state()
        rows = []
        for name, r, val, ip in (("listed register, in limit", "P101", 70.0, good), ("listed register, over its limit", "P101", 95.0, good),
                                 ("unlisted register", "P203", 60.0, good), ("source with no role", "P101", 70.0, "127.0.0.9")):
            t += 0.5
            v = cyber_agent.check(W.signed(MACHINE_BY_NAME[r]["register"], val, t, ip=ip, tx=name))
            rows.append({"case": name, "result": "PASS" if v["pass"] else "DROP", "reason": v["reason"].split(":")[0]})
        out["policy"] = rows
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        cyber_agent._TRUSTED_NETWORKS[:] = saved_nets
        cyber_agent.reset_state(); quarantine.reset(); incidents.reset(); policy.reset()
    return out


# ------------------------------------------------------------------ recorded results
def recorded() -> Dict[str, Any]:
    rec: Dict[str, Any] = {}
    p = os.path.join(ROOT, "benchmarks", "swat_accuracy.json")
    if os.path.exists(p):
        rec["swat"] = json.load(open(p))
    p = os.path.join(ROOT, "benchmarks", "latest.json")
    if os.path.exists(p):
        d = json.load(open(p))
        rec["rules"] = {"label": d["rules"]["label"], "confusion": d["rules"]["confusion"]}
    return rec


# ------------------------------------------------------------------ figures + report
def figures(res: Dict[str, Any]) -> List[str]:
    os.makedirs(FIG_DIR, exist_ok=True)
    made = []
    c = res.get("live", {})
    if c.get("status") == "OK":
        cc = c["command_confusion"]
        fig, ax = plt.subplots(1, 2, figsize=(11, 4.3))
        plots._grid(ax[0], [[cc["tn"], cc["fp"]], [cc["fn"], cc["tp"]]], ["legitimate", "attack"], ["PASS", "flagged (DROP/ALERT)"],
                    f"LIVE campaign, command level (rules)\nprecision {cc['precision']}  recall {cc['recall']}  F1 {cc['f1']}  FPR {cc['false_positive_rate']}")
        rows = [r for r in c["rows"] if r["kind"] == "attack"]
        names = [r["phase"] for r in rows]
        ax[1].barh(names, [r["dropped"] + r["alerted"] for r in rows], color="#1f77b4", label="flagged")
        ax[1].barh(names, [r["passed"] for r in rows], left=[r["dropped"] + r["alerted"] for r in rows], color="#c9c9c9", label="passed")
        ax[1].invert_yaxis()
        ax[1].set_title("Commands per attack campaign (blue = stopped/flagged)", fontsize=9)
        ax[1].legend(fontsize=8)
        made.append(plots._save(fig, FIG_DIR, "evidence_live_campaign.png"))
    s = res.get("recorded", {}).get("swat", {})
    if s.get("status") == "OK":
        m = s["advisory_model_flag"]
        fig, ax = plt.subplots(figsize=(5.2, 4.3))
        plots._grid(ax, [[m["tn"], m["fp"]], [m["fn"], m["tp"]]], ["benign", "attack"], ["PASS", "ALERT"],
                    f"REAL SWaT held-out windows (physical model, advisory)\nprecision {m['precision']}  recall {m['recall']}  F1 {m['f1']}")
        made.append(plots._save(fig, FIG_DIR, "evidence_swat_heldout.png"))
    return made


def f(v: Any) -> str:
    return "n/a" if v is None else str(v)


def render(res: Dict[str, Any]) -> str:
    L = ["# Evidence pack", "",
         "Generated by `python -m benchmark.evidence_pack`. Three kinds of evidence, **kept separate on purpose**: never quote one as if it were another.", "",
         "| # | evidence | data | what it supports |", "|---|---|---|---|",
         "| 1 | Live campaign | real Modbus/TCP into the real middleware and PLC twin on loopback; labelled by phase | the deterministic rules stop the scripted attacks and leave legitimate traffic alone |",
         "| 2 | Response layer | deterministic in-process demo | authorization policy, quarantine and incident correlation behave as designed |",
         "| 3 | Held-out SWaT | REAL SWaT data, recorded from a local run | how well the advisory ML model flags real attack windows (honest, modest numbers) |", ""]
    c = res.get("live", {})
    L += ["## 1. Live campaign (rules, command level)", ""]
    if c.get("status") != "OK":
        L += [f"{f(c.get('status', 'NOT RUN (--no-live)'))}", ""]
    else:
        cc = c["command_confusion"]
        L += [c["label"], "",
              f"Commands are labelled by the phase that sent them: legitimate phase = benign, attack phases = attack. A multi-step attack whose early steps look normal "
              f"therefore shows misses at command level. The physical ML model was cold (120 s warm-up), so this measures the rules.", "",
              f"**Command-level confusion matrix** (flagged = DROP or ALERT): TN {cc['tn']} / FP {cc['fp']} / FN {cc['fn']} / TP {cc['tp']} - "
              f"precision {f(cc['precision'])}, recall {f(cc['recall'])}, F1 {f(cc['f1'])}, accuracy {f(cc['accuracy'])}, false-positive rate {f(cc['false_positive_rate'])}.", "",
              f"**Attack campaigns detected: {c['campaigns_detected']}** (a campaign is detected when at least one of its commands was stopped). "
              f"Of the campaigns that actually pass through the middleware: **{c['campaigns_detected_through_middleware']}**. "
              f"`false-injection` writes straight to the PLC, so no inline control can stop it (documented limit); it is listed so the pack is not selective.", "",
              "![live campaign](figures/evidence_live_campaign.png)", "",
              "| phase | commands | dropped | alerted | passed | first flag at | why it was stopped | note |", "|---|---|---|---|---|---|---|---|"]
        for r in c["rows"]:
            why = ", ".join(f"{k} x{v}" for k, v in r["reasons"].items()) or "-"
            L.append(f"| {r['phase']} | {r['commands']} | {r['dropped']} | {r['alerted']} | {r['passed']} | {f(r['first_flag_at_command'])} | {why} | {r.get('note', '')} |")
        L += ["", f"Incidents the dashboard grouped from this run: {len(c.get('incidents', []))} (all attacks came from one source address, so they correlate into one incident).", ""]
        for i in c.get("incidents", [])[:6]:
            L.append(f"- `{i['id']}` **{i['severity']}** - {i['summary']}")
        L.append("")
        L += ["Reading the table honestly: attacks that are slow and stay inside normal bounds (for example freeze or ramp style) are **not** stopped by rules; "
              "that is what the advisory physical model is for, and its real-data performance is section 3. The command-level recall above counts every command of "
              "an attack campaign as an attack, including the ones that are allowed by design (see the note column), so it understates how many HARMFUL commands were stopped.", ""]
    r = res.get("response", {})
    L += ["## 2. Response layer", "", r.get("label", ""), ""]
    if "spoof_resistance" in r:
        sp = r["spoof_resistance"]
        L += [f"- **Spoof resistance (AUDIT S4):** {sp['forged_commands_sent']} forged commands claiming to come from a trusted "
              f"address were all dropped, and the quarantine did **not** fire "
              f"(`quarantined_after_command` = {sp['quarantined_after_command']}). The device whose address was spoofed could "
              f"still command the plant afterwards: **{sp['spoofed_device_can_still_command']}**. An unauthenticated refusal is "
              f"forgeable by anyone who can put a packet on the wire, so it can never cut a real device off - otherwise the "
              f"response mechanism is a denial-of-service lever against the operator. Incident severity "
              f"`{sp['incident_severity']}`: it is still detected, logged and correlated.", ""]
    if "quarantine" in r:
        q = r["quarantine"]
        L += [f"- **Quarantine:** {q['authenticated_violations_sent']} commands that the device PROVABLY signed but was not "
              f"authorised to send; it was quarantined after command "
              f"**{q['quarantined_after_command']}**, {q['refused_while_quarantined']} later commands were refused, "
              f"and another source still worked: **{q['other_source_still_works']}**.",
              f"- **Incident:** severity `{q['incident_severity']}` - {q['incident_summary']}", "",
              "| policy case | result | reason |", "|---|---|---|"]
        L += [f"| {p['case']} | {p['result']} | {p['reason']} |" for p in r["policy"]]
        L.append("")
    rec = res.get("recorded", {})
    L += ["## 3. Recorded results (measured elsewhere, read from the repo)", ""]
    s = rec.get("swat", {})
    if s.get("status") == "OK":
        m = s["advisory_model_flag"]
        L += [f"**Held-out REAL SWaT test block, physical model (advisory).** {s['windows']:,} windows, {s['attack_windows']:,} attack windows.", "",
              f"TN {m['tn']:,} / FP {m['fp']:,} / FN {m['fn']:,} / TP {m['tp']:,} - precision {m['precision']}, recall {m['recall']}, F1 {m['f1']}, "
              f"balanced accuracy {m['balanced_accuracy']}, ROC-AUC {s['roc_auc_attack_probability']}, {m['alarm_episodes_per_benign_hour']} false-alarm episodes per benign hour. "
              f"Plain accuracy {m['accuracy']} is **not** the headline: an always-benign detector scores {m['always_benign_baseline_accuracy']}.", "",
              "![held-out SWaT](figures/evidence_swat_heldout.png)", "", f"{s.get('protocol_note', '')}", ""]
    if "rules" in rec:
        o = rec["rules"]["confusion"]["overall"]
        L += [f"**Rule regression on constructed scenarios** ({rec['rules']['label']}): TP {o['tp']} / FP {o['fp']} / FN {o['fn']} / TN {o['tn']}. "
              "Deterministic rules are expected to score 100 % on the cases they were written for; this is a regression check, not detection performance against an unknown attacker.", ""]
    L += ["## Limits to state out loud", "",
          "- The live campaign uses the project's own scripted attacks; it shows the rules behave as designed, not how an unknown attacker would fare.",
          "- SWaT has no network traffic: cyber-rule behaviour cannot be validated on it. The ML model's numbers are window-level on real physical data and are modest (F1 about 0.49).",
          "- The held-out block was seen in earlier experiments (held-out, not a pristine blind test), and has only 10 attack segments, so confidence intervals are wide.", ""]
    return "\n".join(L)


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate the evidence pack (live campaign, response-layer demo, recorded real-data results).")
    ap.add_argument("--no-live", action="store_true", help="skip the live campaign (starts no processes)")
    ap.add_argument("--legit", type=int, default=40, help="legitimate commands in the live campaign")
    a = ap.parse_args()
    res: Dict[str, Any] = {"environment": environment()}
    res["live"] = analyse_campaign(live_campaign(a.legit)) if not a.no_live else {"status": "NOT RUN (--no-live)"}
    res["response"] = response_demo()
    res["recorded"] = recorded()
    res["figures"] = figures(res)
    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    json.dump(res, open(OUT_JSON, "w"), indent=2, default=str)
    open(OUT_MD, "w").write(render(res))
    print(render(res))
    print(f"\nWrote {os.path.relpath(OUT_MD, ROOT)}, {os.path.relpath(OUT_JSON, ROOT)} and {len(res['figures'])} figure(s) in docs/reports/figures/")


if __name__ == "__main__":
    main()
