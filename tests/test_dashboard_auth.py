"""
tests/test_dashboard_auth.py - optional shared-token auth on the dashboard's
state-changing POST endpoints, and the unauthenticated /api/health probe.

Default (no IM_DASHBOARD_TOKEN): POSTs are open (loopback demo, unchanged).
With a token: a POST to /api/* needs the matching X-IM-Token header; GETs and
/api/health stay open.

    python -m tests.test_dashboard_auth
"""

from __future__ import annotations

from dashboard import app as dash

fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global fails
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    fails += 0 if cond else 1


client = dash.app.test_client()
TRACE = {"tx_id": "t1", "hops": [{"hop": "arrival", "values": {}}]}

# --- health is always open ---
r = client.get("/api/health")
check("/api/health returns 200 with no auth", r.status_code == 200 and r.get_json()["status"] == "ok")
check("/api/health reports auth mode", r.get_json().get("auth") in ("open", "token"))

# --- default (no token): POST is open ---
dash._DASHBOARD_TOKEN = ""
r = client.post("/api/trace", json=TRACE)
check("no token configured -> POST /api/trace is accepted (200)", r.status_code == 200, str(r.status_code))

# --- token configured ---
dash._DASHBOARD_TOKEN = "secret-token-value"
try:
    r = client.post("/api/trace", json=TRACE)
    check("token set, no header -> POST rejected 401", r.status_code == 401, str(r.status_code))

    r = client.post("/api/trace", json=TRACE, headers={"X-IM-Token": "wrong"})
    check("token set, wrong header -> POST rejected 401", r.status_code == 401, str(r.status_code))

    r = client.post("/api/trace", json=TRACE, headers={"X-IM-Token": "secret-token-value"})
    check("token set, correct header -> POST accepted 200", r.status_code == 200, str(r.status_code))

    r = client.get("/api/health")
    check("token set, GET /api/health still open", r.status_code == 200)

    r = client.get("/api/flow?since=0")
    check("token set, GET /api/flow still open", r.status_code == 200)

    r = client.get("/api/health")
    check("token set, /api/health reports auth=token", r.get_json().get("auth") == "token")
finally:
    dash._DASHBOARD_TOKEN = ""

print("\nALL PASS" if fails == 0 else f"\n{fails} CHECK(S) FAILED")
raise SystemExit(1 if fails else 0)
