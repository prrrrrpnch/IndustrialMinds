# Getting started — first time, on four laptops

This is the one page to follow when none of the four laptops has ever run the
project. It covers install, the one-command launcher, cross-subnet notes, and
the demo. Deeper detail lives in `docs/topology.md` (roles, firewall, Wireshark)
and `docs/demo_workflow.md` (the attack-and-recovery story).

## Roles

| Laptop | Role | Runs | Needs Wireshark? |
|---|---|---|---|
| **Mac A** | Middleware + Dashboard | `./scripts/run.sh middleware`, `./scripts/run.sh dashboard` | yes (middleware leg) |
| **Windows A** | PLC digital twin | `.\scripts\run.ps1 plc` | yes (+ Npcap, PLC leg) |
| **Mac B** | SCADA operator | `./scripts/run.sh scada` | no |
| **Windows B** | Attacker | `.\scripts\run.ps1 attacker <attack>` | no |

Traffic: `SCADA / Attacker → Middleware :5021 → PLC :5020`. Dashboard is :5050
on Mac A.

---

## Step 1 — install (every laptop, once)

**Python 3.13**
- macOS: `brew install python@3.13` (use `python3` in every command).
- Windows: `winget install Python.Python.3.13`, then open a **new** terminal.
  If `python` opens the Microsoft Store, turn off the two "python" App
  execution aliases (Settings → Apps → Advanced app settings → App execution
  aliases).

**Get the code** (the working code is on a branch, not the default):
- ZIP (no Git): browser → `https://github.com/prrrrrpnch/IndustrialMinds/archive/refs/heads/claude/serene-feynman-or6ieo.zip`, unzip, `cd` into the folder.
- Git: `git clone -b claude/serene-feynman-or6ieo https://github.com/prrrrrpnch/IndustrialMinds` then `cd IndustrialMinds`. Sign in with a personal access token if prompted.

**Dependencies** (from the project folder):
```
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```
Check it: `python -m tests.test_environment` must print `ALL PASS` (this
confirms the `scikit-learn==1.9.1` and `pymodbus==3.6.9` pins and that the model
loads). On macOS use `python3`.

**Wireshark** (only Mac A and Windows A):
- Mac A: `brew install --cask wireshark`.
- Windows A: installer from wireshark.org; tick **Npcap** and **"Support
  loopback traffic capture"** on the Npcap step (a few screens in — not on the
  first "Choose Components" screen).

---

## Step 2 — one-time lab settings

1. **Same network.** A phone hotspot or a small Ethernet switch is most
   reliable; campus/guest Wi-Fi often blocks laptop-to-laptop traffic.
2. **Automatic time on all four** (a clock off by >30 s makes every command
   fail as `HMAC_EXPIRED`). macOS: System Settings → General → Date & Time.
   Windows: Settings → Time & language → Set time automatically → Sync now.
3. **Make one shared secret** (32+ chars), on any laptop:
   ```
   python3 -c "import secrets; print(secrets.token_hex(24))"
   ```
   Copy it; it goes in `config/lab.env` on Mac A, Mac B and Windows B.

4. **Find each laptop's IP:**
   - macOS: `ipconfig getifaddr en0` (try `en1` if blank).
   - Windows: `ipconfig` → "IPv4 Address" under your active adapter.

5. **Fill `config/lab.env`** on each laptop (copy the template once):
   ```
   # macOS/Linux
   cp config/lab.env.example config/lab.env
   # Windows
   Copy-Item config\lab.env.example config\lab.env
   ```
   Open `config/lab.env` and set the four addresses, the shared secret, and
   (only if a browser on another laptop must open the dashboard)
   `DASHBOARD_BIND_HOST=0.0.0.0`. This file is git-ignored; it never leaves the
   laptop. **Use the same `HMAC_SECRET` on Mac A, Mac B, Windows B.**

**Different subnets?** It already works. The source whitelist accepts plain IPs
*or* CIDR blocks, and every address is read from `config/lab.env`. If the four
laptops are on different subnets but can route to each other, just put each
laptop's real IP in `lab.env`. If you prefer, set `SCADA_IP`/`ATTACKER_IP` to a
CIDR covering that laptop's subnet instead of a single address. Nothing in the
code assumes one subnet — only the network between the laptops has to allow the
ports below.

**Windows firewall** (Windows A, PLC — Admin PowerShell), allow the middleware in:
```powershell
New-NetFirewallRule -DisplayName "IM PLC 5020" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5020 -RemoteAddress <Mac A IP> -Profile Any
```
On Mac A, when macOS asks "accept incoming network connections?" the first time,
click **Allow**.

---

## Step 3 — preflight (each laptop)

With `config/lab.env` filled, from the project folder:
```
# macOS                      # Windows
./scripts/run.sh check middleware    .\scripts\run.ps1 check plc
./scripts/run.sh check scada         .\scripts\run.ps1 check attacker
```
Every line should read `OK`. The `HMAC secret fingerprint` must be **identical**
on Mac A, Mac B and Windows B. If a peer is unreachable though it's running, the
network is blocking it (Wi-Fi client isolation or firewall) — use a hotspot or a
switch.

---

## Step 4 — start, in this order

```
# 1. Windows A — PLC
.\scripts\run.ps1 plc

# 2. Mac A — dashboard (terminal 1), middleware (terminal 2)
./scripts/run.sh dashboard
./scripts/run.sh middleware

# 3. Mac B — SCADA operator
./scripts/run.sh scada
```
Open `http://127.0.0.1:5050` on Mac A. **Wait ~2 minutes**: the physical model
reads `WARMING_UP` until it has a 120 s telemetry window, then `NORMAL`. Keep the
twin's sensor noise on (the default); a perfectly flat plant looks abnormal to
the model.

Healthy picture: green PASS rows, green dots flowing SCADA → middleware → PLC in
the **Live Network Flow** panel, telemetry near nominal, no red rows.

---

## Step 5 — run an attack (Windows B only)

```powershell
.\scripts\run.ps1 attacker hmac-tamper
.\scripts\run.ps1 attacker random --type ramp
```
Watch all at once: a red "untrusted" host appears in Live Network Flow with dots
stopping at the layer that caught them; the Packet Tracer shows the failing
check; the middleware prints `DROP ... reason=...`; and in Wireshark the frame is
on the middleware leg (Mac A) but absent from the PLC leg (Windows A).

Two attack modes (set `IM_TRUSTED_SOURCES` — the launcher sets it from
`SCADA_IP,ATTACKER_IP`; to make the attacker an outside stranger instead, remove
`ATTACKER_IP` from `lab.env` and restart the middleware):
- **Insider / stolen key** (attacker IP trusted): later layers stop it.
- **External stranger** (attacker IP not trusted): every frame dies at the
  whitelist with `UNTRUSTED_SOURCE`.

---

## Step 6 — recovery

If a stealthy attack (`ramp`/`freeze`) displaced the plant and ALERTs persist,
on **Mac B**:
```
./scripts/run.sh scada --restore
```
It walks every actuator back to its target through the middleware, then exits.
Resume normal operation with `./scripts/run.sh scada`. For a fully clean slate
after `false-injection` (which bypasses the middleware on purpose), restart the
PLC.

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

## Common failures

| Symptom | Fix |
|---|---|
| Every command `HMAC_EXPIRED` | Clocks differ >30 s. Turn on automatic time. |
| `HMAC_INVALID` on SCADA's own commands | `HMAC_SECRET` differs between laptops. Compare the preflight fingerprints. |
| `python` not recognized (Windows) | Open a new terminal, or use `py -3.13`. |
| `python` not recognized (macOS) | Use `python3`. |
| SCADA "Connection failed" | Wrong `MW_IP`, middleware not running, or the network blocks the port. |
| Middleware "cannot reach the PLC" | PLC not running, wrong `PLC_IP`, or the Windows A firewall rule is missing. |
| Constant yellow ALERT on a healthy plant | The PLC was started with `IM_TWIN_NOISE=0`; remove it. |
| Model stuck WARMING_UP | Normal for the first ~2 minutes; it needs a 120 s window. |
