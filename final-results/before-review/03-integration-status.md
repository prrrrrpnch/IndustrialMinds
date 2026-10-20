# 03 - Integration status

Each one was reached and exercised, not inferred from configuration.

| Integration | Status | Evidence |
|---|---|---|
| PLC Modbus server :5020 | **CONNECTED** | listening=True |
| Dashboard HTTP :5050 | **CONNECTED** | listening=True |
| Middleware Modbus :5021 | **CONNECTED** | listening=True |
| GET /api/health | **CONNECTED** | {'auth': 'open', 'status': 'ok', 'traces': 0, 'uptime_seconds': 7.9} in 25 ms |
| Model card published by middleware | **CONNECTED** | PhysicalModelV2 status=OK threshold=0.7880311957440195 |
| GET /api/health while the PLC is down | **CONNECTED** | {'auth': 'open', 'status': 'ok', 'traces': 4, 'uptime_seconds': 22.9} - health does NOT report PLC reachability |
| Blocked-attack log file | **CONNECTED** | 50 records at /home/user/IndustrialMinds/final-results/before-review/_raw/run/blocked_attacks.jsonl |

## Dashboard HTTP surface (from the live Flask url_map)

| Route | Methods | Purpose |
|---|---|---|
| / | GET | the UI |
| /api/health | GET | liveness of the dashboard process ONLY |
| /api/dashboard | GET | counters, events, telemetry |
| /api/traces, /api/trace/<tx> | GET | packet tracer |
| /api/flow | GET | network flow view |
| /api/incidents | GET | correlated incidents |
| /api/model | GET + POST | model card: middleware pushes, UI reads |
| /api/investigations | GET | investigator findings |
| /api/blocked-ips | GET | blocked source summary |
| /api/security-event, /api/trace, /api/telemetry, /api/incident, /api/investigation | POST | ingest from the middleware |
| /api/reset | POST | clears dashboard state |

## External dependencies at runtime

| Dependency | Status | Detail |
|---|---|---|
| Google Fonts CDN | **BROKEN offline** | `fonts.googleapis.com` - fails on an isolated lab network |
| Font Awesome CDN | **BROKEN offline** | `cdnjs.cloudflare.com` - icon set fails to load |
| Chart.js CDN | **BROKEN offline** | `cdn.jsdelivr.net/npm/chart.js@4.4.0` - the CPU chart silently never renders |
| Anthropic API | MISSING (by design) | optional; the investigator falls back to its deterministic engine |
| SWaT archive | MISSING | not in this environment; blocks any re-measurement of model accuracy |
| tshark 4.2.2 | CONNECTED | present; used by the capture tooling |

Browser console on a real page load: `['Failed to load resource: net::ERR_TUNNEL_CONNECTION_FAILED', 'Failed to load resource: net::ERR_TUNNEL_CONNECTION_FAILED', 'Chart.js is not loaded.', 'Chart.js is not loaded.', 'Chart.js is not loaded.', 'Chart.js is not loaded.', 'Chart.js is not loaded.']`

Three of the dashboard's five external assets fail without internet. The lab is four laptops on an isolated network. This is a
real deployment defect, not a cosmetic one - see `05`.
