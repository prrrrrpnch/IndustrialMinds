# Industrial Mind

SCADA -> Middleware (Cyber Agent + Physical Agent + Orchestrator) -> PLC security demo.

## Setup

    python -m venv venv && source venv/bin/activate
    pip install -r requirements.txt

HMAC secret (shared by SCADA and middleware). Pick one:

    export IM_HMAC_SECRET="$(python -c 'import secrets;print(secrets.token_hex(32))')"   # in BOTH terminals
    # or leave unset: config/hmac_secret.key is generated on first run (mode 0600, git-ignored)

Optional settings:

    IM_TRUSTED_SOURCES="127.0.0.1,192.168.1.10"   # SCADA whitelist, IPs or CIDRs (this is the default)
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
    python dashboard/app.py                # http://127.0.0.1:5050
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
