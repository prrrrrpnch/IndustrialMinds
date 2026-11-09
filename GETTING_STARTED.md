# Advanced setup: tuning, hardening and retraining

**First time?** Install and run the system from the [README](README.md): section 3 installs it, section 4 runs it on one
computer, and section 5 is the four-laptop demo step by step (network, `config/lab.env`, firewall, preflight, launchers,
attacks). Troubleshooting is in README section 14.

This page covers what comes after the demo works: making the physical model more or less sensitive, the opt-in hardening
settings that move the system toward a real deployment, and measuring the candidate model v3 on the SWaT archive.

---

## Tuning the model for the demo (optional)

The physical model is **advisory** (it raises ALERT, never blocks) and ships at a
0.5 false-alarm/hour operating point. To make it catch more (at the cost of more
alerts) for a live demo, lower its threshold at start time — set this on the
**middleware** laptop (Mac A) before launching, no retraining needed:
```
export IM_PHYSICAL_THRESHOLD=0.5     # macOS; lower = more sensitive (default ~0.788)
```
On the healthy twin the model raises **zero** false alarms over hours and flags
the clear physical attacks in 1–10 s; the harder, subtle SWaT attacks are what
keep its SWaT F1 modest. Real-data accuracy is retrained on the machine that
holds the SWaT archive — see `docs/reports/physical_training_report_v2_swat.md`
and `models/train_physical_v2.py`.

---

## Hardening beyond the demo (optional)

The defaults above are tuned for a clear single-key demo. Three opt-in settings
move it toward a more realistic deployment; each is off by default, so turning
none of them on leaves the demo exactly as described.

- **Per-device keys** (instead of one shared secret). On the **middleware**, set
  `IM_HMAC_KEYS="<scada-addr>=<scada-key>,<hmi-addr>=<hmi-key>"` (each key 32+
  chars). Each signer then holds only *its own* key as `IM_HMAC_SECRET`. The
  middleware verifies every command with the key bound to its source address, so
  a key stolen from one device cannot be used from another address, and a source
  with no registered key is rejected `UNKNOWN_DEVICE`. A JSON file works too:
  `IM_HMAC_KEYS_FILE=/path/to/keys.json`.
- **Dashboard token** (REQUIRED when the dashboard is on the network). If you set
  `IM_DASHBOARD_BIND_HOST=0.0.0.0` so another laptop can view the dashboard, you must
  also set the same `IM_DASHBOARD_TOKEN=<token>` on **both the dashboard and the
  middleware** — the dashboard refuses to start otherwise, and tells you so, because
  an unauthenticated `/api/reset` on a lab network lets anyone erase the operator's
  record of an attack. Loopback needs no token and is unchanged. The dashboard then rejects any POST to `/api/*` that doesn't carry
  the token, so only the middleware can push data to it. `GET /api/health` stays
  open as a liveness probe.
- **Authorization policy** (who may write which register). Copy
  `config/policy.example.json` to `config/policy.json`, put each laptop's address
  in `sources` with a role (`operator`, `engineer`, `observer`, or your own), and
  restart the middleware. A role lists the registers it may write and optional
  value limits; anything else is dropped `UNAUTHORIZED_*`. No file = no
  restriction. A broken file refuses all writes (`POLICY_ERROR`), so fix it
  before the demo. It reloads by itself within 2 s.
- **Auto-quarantine** (response to repeated attacks). A source that racks up
  violations (a forged command is worth 6 points, a flood request 1; the default
  limit is 12 within 30 s) is refused immediately for 60 s, doubling on repeat
  offences up to 10 min, then released automatically. Tune with
  `IM_QUARANTINE_LIMIT/WINDOW_S/HOLD_S/MAX_S`. **It sets itself automatically:**
  the launcher runs the middleware with `IM_QUARANTINE=auto`, which turns it ON
  when SCADA and the attacker have their own addresses (multi-laptop) and OFF by
  itself on a one-laptop demo, where both share the loopback address and a
  quarantine would lock SCADA out too. Nothing to configure. Force it off with
  `IM_QUARANTINE=0`, or on for testing with `IM_QUARANTINE=force`. Exempt one
  address with `IM_QUARANTINE_EXEMPT=<address>`.
- **Incidents** (always on): blocked and alerted commands from one source are
  grouped into a single incident with severity, timeline and whether the source
  was quarantined. They are served by `GET /api/incidents`; the dashboard page
  no longer has an incidents panel.
- **Model sensitivity** (how talkative the physical model is). `IM_PHYSICAL_SENSITIVITY=balanced` is the default shipped
  point: about 1.2 alerts per hour, 8 of 10 attack types caught on the held-out data. `sensitive` catches a little more and
  roughly doubles the alerts. Only operating points that were actually measured are offered, so there is nothing to guess.
- **Fail-closed decisions** are already the default: any internal error in a
  rule agent or the orchestrator drops the command (`AGENT_ERROR`), never passes
  it. Nothing to configure.

Note on accuracy: improving the physical model's real-data detection is retrained
on the machine that holds the SWaT archive (`models/train_physical_v2.py`); it
can't be done from the demo laptops alone.

## Appendix: train and evaluate physical model v3 (on the SWaT machine)

v3 is built and unit-tested, but its real-data accuracy is **not measured yet**
(only the synthetic fixture was available). It is opt-in and not promoted. To measure
it, on the machine that holds the SWaT archive (Windows example):

```
python -m research.train_physical_v3 --data-dir "G:\IM2\SWaT_dataset\archive" --candidate
```

Add `--quick` for a fast first pass. Nothing in `models/weights/` is touched. It writes
to `models/candidates/physical_v3/`:

- `physical_v3_report.md` / `.json` - held-out test metrics (precision, recall, F1,
  accuracy, confusion matrix, false-alarm episodes/h, per-segment detection, 95% CIs),
  compared against the v2 recipe refit on the same data, plus a promotion checklist
- `physical_v3_confusion.png`, `physical_v3_pr_curve.png`, `physical_v3_segments.png`

Send back the report and the three PNGs. If v3 beats v2 on the held-out block, we
decide on promotion together; only then is it packaged
(`python -m research.package_physical_v3 --budget <b> --report-json ...`, which needs
your explicit approval) and used with `IM_PHYSICAL_MODEL=v3`.
