"""
tools/investigate.py - run the investigator over an incident by hand, from the analyst's laptop.

    python -m tools.investigate --list
    python -m tools.investigate --incident INC-0001                 # read it from a running dashboard
    python -m tools.investigate --incident INC-0001 --offline       # deterministic summary, no model, no network
    python -m tools.investigate --from-file incident.json

Why a CLI as well as the automatic path: the middleware needs no API key to run the demo, and you may not want it making
outbound calls at all on the lab network. This way the investigation runs where the analyst is, reading the same evidence the
dashboard already holds, and prints the finding (optionally posting it back so it appears in the panel).

It never changes anything. Recommendations are proposals a person applies.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from core import netconfig
from middleware import investigator


def _get(url: str) -> Any:
    with urllib.request.urlopen(url, timeout=8) as r:
        return json.loads(r.read().decode())


def fetch(dashboard: str, incident_id: Optional[str]) -> Dict[str, Any]:
    base = dashboard.rstrip("/")
    incidents: List[Dict[str, Any]] = _get(f"{base}/api/incidents")
    if not incidents:
        raise SystemExit("the dashboard holds no incidents yet")
    if incident_id:
        inc = next((i for i in incidents if i.get("id") == incident_id), None)
        if inc is None:
            raise SystemExit(f"{incident_id} not found. Known: {', '.join(i['id'] for i in incidents)}")
    else:
        inc = incidents[0]
    traces = {}
    for t in _get(f"{base}/api/traces"):
        try:
            traces[t["tx_id"]] = _get(f"{base}/api/trace/{t['tx_id']}")
        except Exception:
            pass
    return {"incident": inc, "traces": traces,
            "plant_state": {"physical_model": _get(f"{base}/api/model"), "note": "model card; live registers are on the PLC leg"}}


def render(f: Dict[str, Any]) -> str:
    L = [f"\n{f['incident_id']}  [{f['engine']}]  severity {f['severity']}  confidence {f['confidence']}"
         + ("  REACHED THE PLC" if f.get("reached_plc") else ""),
         "=" * 100, f"\n{f['headline']}\n",
         f"What happened     {f['what_happened']}", f"Hypothesis        {f['attack_hypothesis']}"]
    if f.get("affected_stages"):
        L.append(f"Stages            {', '.join(f['affected_stages'])}")
    L.append("\nProposed actions (none applied - a person approves each one):")
    for a in f.get("recommended_actions") or []:
        L.append(f"  - {a['action']}" + (f" -> {a['target']}" if a.get("target") else ""))
        L.append(f"      {a['why']}")
        L.append(f"      means: {a['means']}")
    if f.get("rejected_actions"):
        L.append(f"\nDiscarded (outside the allow-list): {', '.join(f['rejected_actions'])}")
    L.append(f"\nCaveats           {f['caveats']}")
    if f.get("evidence_used"):
        L.append("Evidence read     " + " -> ".join(e["tool"] for e in f["evidence_used"]))
    if f.get("seconds"):
        L.append(f"Took              {f['seconds']}s")
    L.append(f"\n{f['advisory']}")
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description="Investigate one incident (analysis only; nothing is applied).")
    ap.add_argument("--incident", help="incident id, e.g. INC-0001 (default: the newest)")
    ap.add_argument("--from-file", help="a JSON file holding the incident, instead of asking a dashboard")
    ap.add_argument("--dashboard-url", default=netconfig.DASHBOARD_URL)
    ap.add_argument("--offline", action="store_true", help="deterministic summary only: no model, no network")
    ap.add_argument("--list", action="store_true", help="list the incidents the dashboard holds")
    ap.add_argument("--publish", action="store_true", help="post the finding back so it shows in the dashboard panel")
    ap.add_argument("--json", action="store_true", help="print the finding as JSON")
    a = ap.parse_args()

    if a.list:
        for i in _get(a.dashboard_url.rstrip("/") + "/api/incidents"):
            print(f"{i['id']:10s} {i['severity']:8s} {i['status']:6s} {i['summary']}")
        return 0

    if a.from_file:
        ctx = {"incident": json.load(open(a.from_file)), "traces": {}, "plant_state": {}}
    else:
        try:
            ctx = fetch(a.dashboard_url, a.incident)
        except urllib.error.URLError as exc:
            raise SystemExit(f"cannot reach the dashboard at {a.dashboard_url}: {exc}")

    if not a.offline and not investigator.enabled():
        print("note: IM_INVESTIGATOR is not set, so this is the deterministic summary. "
              "Set IM_INVESTIGATOR=1 and an API key for a real investigation.\n", file=sys.stderr)
    finding = investigator.investigate(ctx["incident"], ctx.get("traces"), ctx.get("plant_state"), force_offline=a.offline)
    print(json.dumps(finding, indent=1, default=str) if a.json else render(finding))

    if a.publish:
        req = urllib.request.Request(a.dashboard_url.rstrip("/") + "/api/investigation",
                                     data=json.dumps(finding, default=str).encode(),
                                     headers={"Content-Type": "application/json"})
        import os
        token = os.environ.get("IM_DASHBOARD_TOKEN", "").strip()
        if token:
            req.add_header("X-IM-Token", token)
        try:
            urllib.request.urlopen(req, timeout=5)
            print("\npublished to the dashboard panel")
        except Exception as exc:
            print(f"\ncould not publish: {exc}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
