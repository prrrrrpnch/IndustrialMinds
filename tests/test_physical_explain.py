"""
tests/test_physical_explain.py - the v2 model's EXPLANATION layer: stage attribution, sensor deviations, confidence, the warm-up
countdown, measured operating-point presets, the model card, and the route each of those takes to the ALERT reason, the packet
tracer and the dashboard.

Runs against the real promoted weights, but the windows are synthetic: these checks are about the explanation machinery, never
about detection performance on real data.

    python -m tests.test_physical_explain
"""

from __future__ import annotations

import os
import tempfile
import time
from typing import Dict, List, Optional

import numpy as np

os.environ.setdefault("IM_LOG_DIR", tempfile.mkdtemp(prefix="im-explain-"))

from core.interfaces import MACHINES  # noqa: E402
from middleware import orchestrator, trace as tracer  # noqa: E402
from models import explain, operating_points  # noqa: E402
from models.physical_model_v2 import PhysicalModelV2, model_card  # noqa: E402
from swat.physical_features import ACTUATORS, SENSORS  # noqa: E402

fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global fails
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    fails += 0 if cond else 1


BASE = PhysicalModelV2.load()
if BASE.status != "OK":
    print("SKIP: the v2 weights are not loadable in this environment")
    raise SystemExit(0)

rng = np.random.default_rng(7)
T0 = 1_000_000.0


def feed(m: PhysicalModelV2, n: int, t_start: float, spoof: Optional[Dict[str, float]] = None) -> None:
    """n seconds of quiet plant, optionally with some sensors held at a spoofed value."""
    for i in range(n):
        regs = {s: float(m.norm.mu[j] + 0.05 * m.norm.sd[j] * rng.standard_normal()) for j, s in enumerate(SENSORS)}
        regs.update({a: 100.0 for a in ACTUATORS})
        regs.update(spoof or {})
        m.update(regs, timestamp=t_start + i)


def sigma(m: PhysicalModelV2, tag: str, k: float) -> float:
    j = SENSORS.index(tag)
    return float(m.norm.mu[j] + k * m.norm.sd[j])


print("EXPLAIN: grouping and wording")
groups = explain.channel_groups(SENSORS, ACTUATORS)
check("every stage of the plant has a channel group", sorted(groups) == ["S1", "S2", "S3", "S4", "S5"], str(sorted(groups)))
check("every live channel belongs to exactly one stage",
      sum(len(g["sensors"]) for g in groups.values()) == len(SENSORS)
      and sum(len(g["actuators"]) for g in groups.values()) == len(ACTUATORS))
check("channels are grouped with their own stage", SENSORS.index("LIT301") in groups["S3"]["sensors"]
      and ACTUATORS.index("P501") in groups["S5"]["actuators"])
check("a stage is named in words, not as a code", explain.stage_label("S3") == "stage 3 (Ultrafiltration)", explain.stage_label("S3"))
check("confidence is 'marginal' only next to the threshold",
      explain.confidence(0.80, 0.788) == "marginal" and explain.confidence(0.97, 0.788) == "clear")
check("a stage is only called a driver above the minimum contribution",
      explain.suspect_stage({"S1": 0.5, "S2": 0.01}) == "S1" and explain.suspect_stage({"S1": 0.01, "S2": 0.0}) is None
      and explain.suspect_stage({}) is None)
devs = [{"tag": "LIT301", "stage": "S3", "z": 7.8, "direction": "above", "outside_envelope": True},
        {"tag": "FIT101", "stage": "S1", "z": -1.2, "direction": "below", "outside_envelope": False}]
check("the sentence names the stage and its own worst sensor",
      explain.sentence("S3", {"S3": 0.9}, devs) == "stage 3 (Ultrafiltration) is driving this: LIT301 7.8 sigma above normal (outside the measured envelope)",
      explain.sentence("S3", {"S3": 0.9}, devs))
check("with no dominant stage the sentence still points somewhere",
      explain.sentence(None, {"S1": 0.0}, devs) == "no single stage dominates - plant-wide deviation; worst reading is in stage 3 (Ultrafiltration): LIT301 7.8 sigma above normal (outside the measured envelope)",
      explain.sentence(None, {"S1": 0.0}, devs))
check("with no attribution at all it still reports the worst reading", explain.sentence(None, None, devs).startswith("most unusual reading: LIT301"))
check("with nothing to report it says nothing stands out", explain.sentence(None, None, []) == "no reading stands out")

print("\nEXPLAIN: attribution arithmetic (stub scorer, exact values)")
S = np.zeros((1, 120, len(SENSORS)))
A = np.zeros((1, 120, len(ACTUATORS)))
S[0, :, SENSORS.index("LIT301")] = 5.0
S[0, :, SENSORS.index("FIT101")] = 2.0
ref_S, ref_A = np.zeros_like(S), np.zeros_like(A)
contrib = explain.contributions(lambda s, a: s[:, -1, :].sum(axis=1), S, A, ref_S, ref_A, groups)
check("each stage's contribution is exactly what removing it takes away",
      contrib["S3"] == 5.0 and contrib["S1"] == 2.0 and contrib["S2"] == contrib["S4"] == contrib["S5"] == 0.0, str(contrib))
check("the window being explained is not modified", S[0, -1, SENSORS.index("LIT301")] == 5.0 and A.sum() == 0.0)

print("\nLIVE: a flag says which stage")
for tag, want in (("LIT101", "S1"), ("LIT301", "S3"), ("PIT501", "S5")):
    m = PhysicalModelV2.load()
    feed(m, 130, T0)
    quiet = m.assess()
    if tag == "LIT101":
        check("a quiet plant is not flagged and leaves a usable reference",
              quiet["status"] == "OK" and not quiet["threat_flag"] and m._ref is not None and quiet["explanation"] is None)
        check("a quiet assessment still reports confidence and the most unusual reading",
              quiet["confidence"] in ("clear", "marginal") and len(quiet["top_deviations"]) == 3)
        check("a warm model reports no warm-up left", quiet["warmup_remaining_s"] == 0 and quiet["window_fill"] == quiet["window_size"])
    feed(m, 60, T0 + 130, {tag: sigma(m, tag, 5.0)})
    t = time.perf_counter()
    r = m.assess()
    ms = (time.perf_counter() - t) * 1000.0
    check(f"spoofing {tag} is flagged and attributed to {want}",
          r["threat_flag"] and r["suspect_stage"] == want, f"suspect {r['suspect_stage']}, p={r['attack_probability']}")
    check(f"{want} contributes more than every other stage",
          max(r["stage_contributions"], key=r["stage_contributions"].get) == want, str(r["stage_contributions"]))
    check(f"the sentence for {tag} names the stage and the sensor",
          explain.stage_label(want) in r["explanation"] and tag in r["explanation"], r["explanation"])
    check(f"explaining a flag on {tag} stays inside the decision-path budget (< 25 ms)", ms < 25.0, f"{ms:.1f} ms")
    check(f"the reference used for {tag} has an age in seconds", isinstance(r["reference_age_s"], float) and r["reference_age_s"] > 0)

print("\nLIVE: a cascade blames no single stage")
casc = PhysicalModelV2.load()
feed(casc, 130, T0)
casc.assess()
feed(casc, 60, T0 + 130, {t: sigma(casc, t, 6.0) for t in ("LIT101", "AIT202", "LIT301", "LIT401", "PIT501")})
rc = casc.assess()
check("when every stage is abnormal, no single stage is blamed",
      rc["threat_flag"] and rc["suspect_stage"] is None and max(rc["stage_contributions"].values()) < explain.MIN_CONTRIBUTION,
      str(rc["stage_contributions"]))
check("...and the sentence says it is plant-wide, naming where the worst reading is",
      rc["explanation"].startswith("no single stage dominates") and "worst reading is in stage" in rc["explanation"], rc["explanation"])

print("\nLIVE: warm-up, abstention and the reference")
m = PhysicalModelV2.load()
feed(m, 40, T0)
w = m.assess()
check("during warm-up the report counts the seconds still needed",
      w["status"] == "WARMING_UP" and w["warmup_remaining_s"] == w["window_size"] - 40 and w["window_fill"] == 40, str(w["warmup_remaining_s"]))
check("a warming model explains nothing and flags nothing", w["explanation"] is None and not w["threat_flag"])
cold = PhysicalModelV2.load()
feed(cold, 130, T0, {"LIT301": sigma(cold, "LIT301", 6.0)})
r = cold.assess()
check("a flag before any normal window says it has no reference, and still names the worst reading",
      r["threat_flag"] and r["explanation"].startswith("no normal reference yet") and "LIT301" in r["explanation"], r["explanation"])
check("without a reference no stage is blamed", r["suspect_stage"] is None and r["stage_contributions"] is None)
m2 = PhysicalModelV2.load()
feed(m2, 130, T0)
m2.assess()
before = m2._ref
rep = {"threat_flag": False, "bounds_violations": [{"tag": "LIT301"}], "top_deviations": []}
m2._explain(rep, np.ones((1, 120, len(SENSORS))), np.ones((1, 120, len(ACTUATORS))), T0 + 999)
check("a window with a bounds violation never becomes the 'things look fine' reference", m2._ref is before)
nm = PhysicalModelV2()
check("a model with no weights abstains and explains nothing", nm.assess()["status"] == "NO_MODEL" and nm.assess()["explanation"] is None)

print("\nOPERATING POINTS (only what was measured)")
pts = operating_points.measured()
check("the measured points come from the held-out report, quietest first",
      len(pts) >= 2 and [p["budget"] for p in pts] == sorted(p["budget"] for p in pts), str([p["budget"] for p in pts]))
check("every measured point carries a threshold and its measured cost",
      all(p["threshold"] and p["measured"].get("alarm_episodes_per_benign_hour") is not None for p in pts))
pres = operating_points.presets()
check("the shipped point is named 'balanced' and matches the weights' threshold",
      "balanced" in pres and abs(pres["balanced"]["threshold"] - BASE.clf_threshold) < 1e-9, str(sorted(pres)))
check("a louder measured point is offered as 'sensitive' and has a lower threshold",
      "sensitive" in pres and pres["sensitive"]["threshold"] < pres["balanced"]["threshold"], str(sorted(pres)))
check("no tier is invented when no budget was measured for it", "cautious" not in pres or pres["cautious"]["budget"] < 0.5)
check("a point resolves by name and by its budget",
      operating_points.resolve("sensitive")["threshold"] == operating_points.resolve("1.0")["threshold"])
check("an unmeasured choice resolves to nothing", operating_points.resolve("reckless") is None and operating_points.resolve("0.01") is None)
check("describe() states the cost in operator terms", "alerts/h" in operating_points.describe(pres["balanced"]))
saved = {k: os.environ.get(k) for k in ("IM_PHYSICAL_SENSITIVITY", "IM_PHYSICAL_THRESHOLD")}
try:
    os.environ["IM_PHYSICAL_SENSITIVITY"] = "sensitive"
    m3 = PhysicalModelV2.load()
    check("IM_PHYSICAL_SENSITIVITY moves the live threshold to the measured point",
          abs(m3.clf_threshold - pres["sensitive"]["threshold"]) < 1e-9 and m3.metadata["operating_point"]["name"] == "sensitive")
    check("the shipped threshold is remembered alongside it", abs(m3.metadata["shipped_threshold"] - BASE.clf_threshold) < 1e-9)
    os.environ["IM_PHYSICAL_THRESHOLD"] = "0.42"
    m4 = PhysicalModelV2.load()
    check("an explicit IM_PHYSICAL_THRESHOLD wins over the preset",
          abs(m4.clf_threshold - 0.42) < 1e-9 and abs(m4.metadata["shipped_threshold"] - BASE.clf_threshold) < 1e-9, str(m4.clf_threshold))
    del os.environ["IM_PHYSICAL_THRESHOLD"]
    os.environ["IM_PHYSICAL_SENSITIVITY"] = "reckless"
    m5 = PhysicalModelV2.load()
    check("an unmeasured sensitivity is ignored and the shipped point stands", abs(m5.clf_threshold - BASE.clf_threshold) < 1e-9)
finally:
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v

print("\nMODEL CARD")
card = model_card(BASE)
check("the card names the model, its window and its feature count",
      card["model"] == "PhysicalModelV2" and card["window_seconds"] == 120 and card["features"] == 117, str(card["features"]))
check("the card states that the model can never block", "never" in card["role"].lower() and "advisory" in card["role"].lower())
check("the card carries the held-out result", card["held_out_result"] and "F1" in str(card["held_out_result"]))
check("the card lists the operating points that were measured", "balanced" in card["available_operating_points"])
check("the card lists known limits, including the non-blind test block and the bypass",
      len(card["known_limits"]) >= 5 and any("blind" in l for l in card["known_limits"]) and any("bypass" in l for l in card["known_limits"]))
check("a card for a model with no weights still renders", model_card(PhysicalModelV2())["status"] == "NO_MODEL")

print("\nWIRING: reason, fusion record and packet tracer")
orchestrator._forward_decision_to_dashboard = lambda payload: None
ok = {"tx_id": "t1", "pass": True, "reason": "OK", "agent": "cyber"}
pv = {"tx_id": "t1", "pass": True, "reason": "OK", "agent": "physical"}
adv = {"threat_flag": True, "flagged_by": ["classifier"], "suspect_stage": "S3",
       "explanation": "stage 3 (Ultrafiltration) is driving this: LIT301 7.8 sigma above normal", "plant_state": "ALERT"}
d = orchestrator.decide(dict(ok), dict(pv), time.time(), physical_advisory=adv)
check("an ALERT reason names the stage, so the dashboard row and the log carry it",
      d["verdict"] == "ALERT" and d["reason"] == "PHYSICAL_MODEL:classifier S3", d["reason"])
check("the fusion record keeps the stage and the sentence",
      d["fusion"]["inputs"]["physical_model_suspect_stage"] == "S3" and "Ultrafiltration" in d["fusion"]["inputs"]["physical_model_explanation"])
d2 = orchestrator.decide(dict(ok), dict(pv), time.time(), physical_advisory={"threat_flag": True, "flagged_by": ["classifier"]})
check("a flag with no stage keeps the old reason unchanged", d2["reason"] == "PHYSICAL_MODEL:classifier", d2["reason"])
cmd = {"tx_id": "t1", "timestamp": time.time(), "source_ip": "127.0.0.1", "source_port": 1, "function_code": 16,
       "register": 0, "value": 55.0, "raw_value": 550, "auth": None}
regs = {mm["register"]: mm["initial"] for mm in MACHINES}
state = {"registers": regs, "setpoints": dict(regs), "timestamp": time.time()}
full_adv = dict(adv, confidence="clear", stage_contributions={"S3": 0.89}, top_deviations=[{"tag": "LIT301", "z": 7.8}],
                warmup_remaining_s=0, status="OK", attack_probability=0.97)
tr = tracer.build_trace(cmd, state, ok, ok, {"status": "NO_MODEL"}, pv, full_adv, d, {"total": 1.0}, "MONITOR")
hop = next(h for h in tr["hops"] if h["hop"] == "physical_model")
check("the packet tracer shows why, where and how confident, next to the probability",
      hop["values"]["why"] and hop["values"]["suspect_stage"] == "S3" and hop["values"]["confidence"] == "clear"
      and hop["values"]["stage_contributions"] == {"S3": 0.89} and hop["values"]["most_unusual"]["tag"] == "LIT301")
check("the tracer hop is marked ALERT when the model flags", hop["outcome"] == "ALERT")

print("\nDASHBOARD")
from dashboard import app as dash  # noqa: E402
c = dash.app.test_client()
check("before the middleware publishes anything the card is empty, not an error", c.get("/api/model").get_json() == {})
check("the middleware can publish the live card", c.post("/api/model", json=card).status_code == 200)
got = c.get("/api/model").get_json()
check("the dashboard serves the published card", got["model"] == "PhysicalModelV2" and got["known_limits"])
check("a body that is not a card is rejected", c.post("/api/model", json={"nope": 1}).status_code == 400)
page = c.get("/").data
check("the page has the model panel and its script", b"model-strip" in page and b"model_card.js" in page)
check("the panel script is served", c.get("/static/model_card.js").status_code == 200)

print("\nALL PASS" if fails == 0 else f"\n{fails} CHECK(S) FAILED")
raise SystemExit(1 if fails else 0)
