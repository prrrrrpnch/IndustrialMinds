# Updates log — from the "run & demo it" work onward

This summarises everything changed since the project moved from "built" to
"run it on real laptops, demonstrate it, and harden it" — roughly **14 Oct
afternoon through 15 Oct**. Grouped by theme; the most significant work is
first. Commit hashes are in brackets so each item is traceable
(`git show <hash>`).

Branch: `claude/serene-feynman-or6ieo`.

---

## 1. The physical ML model: rebuilt, evaluated on real SWaT, promoted, and made tunable

- **Physical model v2 built and evaluated on real SWaT data** (15 Oct). A new
  detector: a 120-second window (vs 30 s before), 117 features (long-context
  trends + cross-sensor consistency residuals), and a gradient-boosted
  classifier. Held-out SWaT result: **precision 0.46, recall 0.51, F1 0.49, 8/10
  attack segments, ROC-AUC 0.84** — up from the previous F1 0.31, 6/10. [1664e5c,
  83d01d2, f31b114, 3b24ce6, 65eb1eb]
- **v2 promoted as the live advisory model** (15 Oct), with your approval. It
  ships as `models/weights/physical_model_v2.joblib`; the old v1 stays as an
  automatic fallback (`IM_PHYSICAL_MODEL=v1`). Inference was hand-optimised
  (~10x faster than scikit-learn, identical output), and a test confirms the
  live window reproduces the training scores exactly. [437356e]
- **Runtime recall/precision knob** (15 Oct): `IM_PHYSICAL_THRESHOLD` lets you
  trade "catch more" vs "fewer alerts" at start time without retraining. The
  training report now sweeps a wider range of operating points so you can pick
  one. [0796aad]
- **Honest finding:** on the live twin the model raises **zero false alarms**
  over hours and flags clear physical attacks in **1–10 s**; the modest SWaT F1
  reflects SWaT's subtle, long attacks. Real-data accuracy improvements must be
  retrained on the machine that holds the SWaT archive.

## 2. The dashboard and live monitoring

- **Attack controls removed from the dashboard** (15 Oct). Attacks now come only
  from the separate attacker system, which is the correct model for the demo.
  [5f2d59d]
- **New "Live Network Flow" panel** (15 Oct): every command is drawn from the
  host that really sent it, through the Cyber Agent → Physical Agent →
  Orchestrator → PLC, in real time. Green = forwarded, yellow = forwarded with an
  advisory alert, red = stopped at the layer that caught it; untrusted hosts are
  flagged. [5f2d59d]
- **Packet Tracer, blocked-source log, and the per-command journey** had been
  added just before this window (Phase 9) and remain the detailed view behind the
  flow panel. [5a81575]

## 3. Running it on four laptops (first-time setup made turnkey)

- **4-laptop topology + Wireshark/tshark docs + preflight tools** (14 Oct):
  per-laptop roles, env vars, firewall rules, a `check_topology` preflight, and a
  wire-correlation tool that matches captured frames to the dashboard by nonce.
  [c42e57c]
- **One-command launcher** (15 Oct): `scripts/run.sh` (macOS) and
  `scripts/run.ps1` (Windows) start any role with a single command, reading the
  addresses and shared secret from `config/lab.env` (copied from a committed
  template; the real file is git-ignored). A blank config falls back to loopback
  for a single-laptop rehearsal. [14e7bfe]
- **GETTING_STARTED.md** (15 Oct): a single first-time page — install per laptop,
  the launcher, cross-subnet notes, the demo, recovery, and common failures.
  Cross-subnet already works (addresses are all configurable; the whitelist
  accepts CIDR ranges). [0796aad]
- **docs/demo_workflow.md** (15 Oct): the end-to-end story — normal operation,
  the attack, what happens afterwards, and recovery. [f0031de]
- **Operator recovery command** (15 Oct): `python -m scada.scada --restore`
  walks every actuator back to its target through the middleware after an attack
  displaced the plant. [f0031de]

## 4. Robustness and security hardening

- **Dead-state fix** (15 Oct): a command the PLC never settles to no longer
  lingers forever (it would skew later cross-register checks); it expires after a
  timeout. [14e7bfe]
- **Log flood fix** (15 Oct): a down PLC laptop no longer floods the middleware
  log; one actionable line every few seconds instead. [14e7bfe]
- **Per-device HMAC keys** (15 Oct, opt-in): instead of one shared secret, each
  device can have its own key (`IM_HMAC_KEYS` on the middleware). A key stolen
  from one device is then useless from another address, and an unregistered
  source is rejected `UNKNOWN_DEVICE`. Default stays single-key. [889a293]
- **Dashboard token auth + health probe** (15 Oct, opt-in): when the dashboard is
  put on the network, `IM_DASHBOARD_TOKEN` makes it reject unauthenticated writes;
  a new `GET /api/health` gives a liveness check. [889a293]
- **Fail-closed decisions** confirmed and documented: any internal error in a
  rule agent or the orchestrator drops the command, never passes it. [889a293]

## 5. Verification, benchmarks, and the technical write-up

- **Reproducible benchmark pipeline** (14 Oct): one command regenerates the
  latency / rule-accuracy / held-out-SWaT / twin numbers, the report, and the
  README benchmark block, with a drift test so numbers can't silently diverge.
  [7314ca0, 44d2bcf, cb34fb1, faf4516]
- **Whole-middleware metrics**: accuracy / precision / recall / F1 / confusion
  matrices at command and session level, with figures. [059b0fd]
- **docs/PROJECT_DETAILS.md (+ .docx)** (14 Oct): a complete technical
  description of every component, algorithm, parameter and result — the source
  for your PPT / report / paper. [76b70da]
- **Full README rewrite** (14 Oct): architecture, dataset, twin, packet journey,
  per-role setup, training, attacker, tracer, Wireshark, demo runbook,
  limitations, future work. [9f1c204, be26309]
- **Test growth**: the suite went from ~19 scripts to **23 scripts / 344
  checks**, adding coverage for the v2 model, the dead-state fix, per-device keys,
  and the dashboard auth. All passing.

## 6. End-to-end verification performed (no code change)

- A full self-run of the stack: every attack fired against the live system and
  confirmed caught at the correct layer with the correct reason; malformed
  frames and garbage dashboard requests handled without crashing; concurrent
  sources isolated; a displaced plant recovered with `--restore`. The
  cryptographic core (server-set timestamp inside the signed frame) was reviewed
  and is sound.

---

## What is still outstanding (needs you / hardware)

- **Real-data model accuracy**: retrained only on the machine with the SWaT
  archive — `python -m models.train_physical_v2 --data-dir <archive> --candidate`,
  then pick an operating point from the report.
- **Multi-laptop run on real hardware**: rehearsed on loopback; the four-laptop
  run with real IPs is still pending the hardware (the launcher + guide are ready
  for it).
- **PPT/report numbers**: update them from `docs/reports/benchmark_report.md`,
  which is regenerated from the benchmarks.
- **Deeper deployment steps** (real/soft PLC in the loop, Modbus transport
  security) are architecture-level future work, documented as such.
