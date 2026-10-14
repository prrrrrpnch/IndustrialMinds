# Industrial Mind

SCADA -> Middleware (Cyber Agent + Physical Agent + Orchestrator) -> PLC security demo.

## Setup

    python -m venv venv && source venv/bin/activate
    pip install -r requirements.txt

HMAC secret (shared by SCADA and middleware). Pick one:

    export IM_HMAC_SECRET="$(python -c 'import secrets;print(secrets.token_hex(32))')"   # in BOTH terminals
    # or leave unset: config/hmac_secret.key is generated on first run (mode 0600, git-ignored)

Hosts and ports (single machine: defaults work; resolved in `docs/netconfig.py`, CLI flags override):

    IM_PLC_HOST / IM_PLC_PORT                 # middleware/attacker -> PLC          (default loopback:5020)
    IM_PLC_LISTEN_HOST / IM_PLC_LISTEN_PORT   # PLC bind                            (default 0.0.0.0:5020)
    IM_MIDDLEWARE_HOST / IM_MIDDLEWARE_PORT   # SCADA/attacker -> middleware        (default loopback:5021)
    IM_LISTEN_HOST / IM_LISTEN_PORT           # middleware bind                     (default 0.0.0.0:5021)
    IM_DASHBOARD_HOST / IM_DASHBOARD_PORT     # middleware -> dashboard             (default loopback:5050)
    IM_DASHBOARD_URL                          # full URL override for the above
    IM_DASHBOARD_BIND_HOST                    # dashboard bind                      (default loopback)

Entry points also take flags: `plc.plc --host --port`, `middleware.middleware_server --listen-host
--listen-port --plc-host --plc-port --dashboard-url`, `dashboard/app.py --host --port`,
`scada.scada --host --port`, `attacker.attacker --host --port --plc-host --plc-port`.

Optional settings:

    IM_TRUSTED_SOURCES="<scada-ip-or-cidr>"       # SCADA whitelist (default: this machine only)
    IM_LOG_DIR=logs                               # where blocked_attacks.jsonl is written
    IM_HMAC_MAX_SKEW_SECONDS=30                   # signed-command freshness window

## Models (one-time, deterministic)

    python -m models.train_models      # writes models/weights/*.joblib (shipped pre-trained too)

See MODELS_RATIONALE.md. Without weights the middleware still runs on the
deterministic rules alone (models report NO_MODEL).

    IM_CYBER_MODEL_ENFORCE=1          # let a CyberModel anomaly DROP commands (default: monitor only)
    IM_HEALTH_REFRESH_SECONDS=1       # how often machine health / RUL is recomputed
    IM_TELEMETRY_LOG_SECONDS=5        # how often the middleware logs live telemetry + health
    IM_LOG_LEVEL=INFO

## Run (one terminal each, from the project root)

    python -m plc.plc
    python dashboard/app.py                # http://<IM_DASHBOARD_BIND_HOST>:5050
    python -m middleware.middleware_server
    python -m scada.scada

## Attacks

    python attacker/attacker.py flood | impossible-command | replay | false-injection
    python attacker/attacker.py cross-register
    python attacker/attacker.py hmac-missing | hmac-tamper | hmac-forged | delayed-replay
    python attacker/attacker.py hmac-missing --source-ip 127.0.0.2,127.0.0.3   # several attacking IPs

On macOS, add loopback aliases first: `sudo ifconfig lo0 alias 127.0.0.2 up`.
The dashboard Attacks panel has the same buttons plus an optional source-IP box.

Every blocked command is appended to `logs/blocked_attacks.jsonl` and shown in the
Blocked IPs / Blocked Sources section at the bottom of the dashboard.

## Tests

    python -m tests.test_cyber_agent
    python -m tests.test_physical_agent
    python -m tests.test_orchestrator
    python -m tests.test_models
    python -m tests.test_pipeline
    python -m plc.plc &  python -m tests.pipeline_test     # needs a running PLC

## Middleware stress test

    python -m tests.test_middleware_efficiency                       # 2400 msgs @ 300/s + 2000 capacity
    python -m tests.test_middleware_efficiency --payloads 40000 --rate 400   # soak

Writes logs/middleware_benchmark_<timestamp>.json and appends logs/middleware_benchmark.csv.

## System efficiency (offline, not on the dashboard)

    python evaluation/evaluate_system.py               # runs every case in test_data.xlsx through the real agents
    python evaluation/generate_test_data.py --force    # regenerate the default test cases

Results, confusion matrix and `confusion_matrix.png` are written into `evaluation/`.
