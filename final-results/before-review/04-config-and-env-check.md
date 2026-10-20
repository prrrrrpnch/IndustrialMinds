# 04 - Configuration, secrets and dependencies

## Runtime

Python 3.13.16 | Linux-6.18.44-fc-v114-x86_64-with-glibc2.39 | 4 CPU |
numpy 2.5.4 | scikit-learn 1.9.1 | pandas 3.0.6

## Declared vs actually importable

| Package | Importable | Note |
|---|---|---|
| flask | OK | pinned in requirements.txt |
| requests | OK | pinned in requirements.txt |
| pymodbus | OK | pinned in requirements.txt |
| psutil | OK | pinned in requirements.txt |
| openpyxl | OK | pinned in requirements.txt |
| matplotlib | OK | pinned in requirements.txt |
| numpy | OK | pinned in requirements.txt |
| pandas | OK | pinned in requirements.txt |
| scikit-learn | OK | pinned in requirements.txt |
| joblib | OK | pinned in requirements.txt |
| anthropic | **MISSING** | optional, commented out; investigator degrades by design |

`pymodbus==3.6.9` and `scikit-learn==1.9.1` are exact pins. The scikit-learn pin is load-bearing: the weights are a pickle and
another version makes the load warn, which `tests/test_environment.py` turns into a failure. That is correct discipline but it
is also a fragility - the artefact is a pickle, not a portable format.

## Secrets

| Item | State | Note |
|---|---|---|
| config/hmac_secret.key | present, 0600, git-ignored | auto-generated if absent |
| config/lab.env | present, git-ignored | holds HMAC_SECRET and the four laptop addresses |
| IM_HMAC_SECRET | env var, read by SCADA + middleware | must match on both or every command is HMAC_INVALID |
| Committed secrets | **none** | `git ls-files` shows no key, pem, or lab.env |

No secret is committed and both secret files are correctly ignored. The weak point is distribution, not storage: the shared
secret is copied by hand into a file on each laptop, with no rotation path. See `05`.

## Model artefacts

| Artefact | Size | Role |
|---|---|---|
| models/weights/physical_model_v2.joblib | 0.29 MB | LIVE model |
| models/weights/physical_model.joblib | 1.49 MB | v1 fallback, still loadable |
| cyber weights | absent | deliberate: the cyber branch is rules-only |
| SWaT archive | absent | blocks re-measurement |

## Opt-in switches (all default OFF)

`IM_QUARANTINE`, `IM_POLICY_FILE`, `IM_DASHBOARD_TOKEN`, `IM_HMAC_KEYS`, `IM_INVESTIGATOR`, `IM_PHYSICAL_SENSITIVITY`,
`IM_PHYSICAL_THRESHOLD`, `IM_PHYSICAL_MODEL`, `IM_TWIN_NOISE`, `IM_TWIN_TIME_SCALE`, `IM_PENDING_TIMEOUT_S`.

Eleven switches, every one of them off by default. The demo therefore runs with authorization, per-device keys, dashboard auth
and quarantine all disabled. That is a defensible default for a demo and an indefensible one for a deployment; the gap between
"the code supports it" and "the running system uses it" is the subject of `05`.

## Test suite state at baseline

30 scripts passed, 0 failed, 2 skipped;
688 individual checks passed, 0 failed.
Recorded at commit `9793cb4`, 256.4 s wall clock.

A suite this green on a system with the defects listed in `05` is itself a finding: the tests assert that each component does
what it was written to do, and almost never that the system as a whole does what an operator needs. See `05-anomalies-found.md`
item A1.
