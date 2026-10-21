# Four-laptop topology (2 MacBooks + 2 Windows laptops)

**Status: documented and rehearsed on ONE machine only** (loopback, real tshark capture, real tracer). The laptops were not
available, so none of the per-laptop steps below has been run on the actual hardware yet. Run `tools/check_topology.py` on each
laptop first; it tells you what is still wrong.

No IP address is written anywhere in the repository. Every address below is a placeholder you replace in the environment
variables (`core/netconfig.py` is the only place defaults live). Pick the placeholders once and write them down:

| Placeholder | Meaning |
|---|---|
| `<MW_IP>` | Mac A (middleware) |
| `<PLC_IP>` | Windows A (PLC twin) |
| `<SCADA_IP>` | Mac B (SCADA operator) |
| `<ATTACKER_IP>` | Windows B (attacker) |

## Roles

| Laptop | Role | Also runs | Why this laptop |
|---|---|---|---|
| **Mac A** | **Middleware** | **Dashboard**, **Wireshark** (middleware leg) | Every command passes through it, so one capture here shows every frame, including the ones that get dropped. The dashboard reads `logs/blocked_attacks.jsonl`, which the middleware writes locally, so the two must share a machine. Present from this screen. |
| **Windows A** | **PLC digital twin** | **tshark** (PLC leg) | A capture next to the PLC shows only what really arrived at the plant, the proof that dropped frames never reach it. |
| **Mac B** | **SCADA operator** | | The legitimate source. Its address is the one in the middleware's trusted list. |
| **Windows B** | **Attacker** (CLI) | | A separate machine, so the middleware sees a real foreign source address. |

Traffic: `SCADA/Attacker -> Middleware :5021 -> PLC :5020`. The middleware also polls the PLC, and posts events to the dashboard
(`http://127.0.0.1:5050`, same laptop, no network). The dashboard has no attack controls: every attack is launched by the CLI on the attacker laptop (Windows B), and shows up in the dashboard's Live Network Flow panel as traffic from that laptop's address.

## Ports

| Port | Served by | Who connects | Direction |
|---|---|---|---|
| 5020 | PLC (Windows A) | middleware (and attacker, only for the false-injection demo) | inbound on Windows A |
| 5021 | middleware (Mac A) | SCADA (Mac B), attacker (Windows B) | inbound on Mac A |
| 5050 | dashboard (Mac A) | browser on Mac A (loopback by default) | local; set `IM_DASHBOARD_BIND_HOST=0.0.0.0` only if another laptop must open it |

## Clocks (important)

Signed commands carry a timestamp and the middleware rejects frames more than **30 s** away from its own clock (`HMAC_EXPIRED`).
Enable automatic time on all four laptops (macOS: System Settings -> General -> Date & Time; Windows: Settings -> Time & language ->
"Set time automatically" -> Sync now). A skewed laptop looks exactly like a delayed-replay attack.

## The shared secret

SCADA, middleware and attacker must hold the **same** secret. Pick one string of 32+ characters and set it as `IM_HMAC_SECRET` on
those three laptops (the PLC and the dashboard do not need it). After setting it, run the preflight on each laptop and compare the
8-hex-digit fingerprint it prints: it must be identical (the secret itself is never printed). The attacker holds the key because
`attacker.py` models an insider or a man-in-the-middle who captured a valid frame; the key-less attacks (`hmac-missing`,
`hmac-forged`) do not use it.

## Per-laptop setup

Python 3.13 or 3.14 on every laptop. From the repository root: `pip install -r requirements.txt` (pymodbus stays at 3.6.9).

### Windows A: PLC twin (`<PLC_IP>`)

```powershell
# The PLC listens on all interfaces, port 5020. It accepts plant writes ONLY from the middleware (AUDIT S1), and it
# learns who that is from IM_MIDDLEWARE_HOST. Forget this and it refuses the middleware's own writes.
$env:IM_MIDDLEWARE_HOST = "<MW_IP>"
python -m plc.plc
# (the launcher does this for you:  .\scripts\run.ps1 plc   - it reads MW_IP from config\lab.env)
```
Firewall (PowerShell as Administrator): allow only the middleware (add `<ATTACKER_IP>` as well only for the false-injection demo).
```powershell
New-NetFirewallRule -DisplayName "IM PLC 5020" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5020 -RemoteAddress <MW_IP> -Profile Any
```
If the Wi-Fi is classed as *Public*, `-Profile Any` is what makes the rule apply. Remove it after the demo:
`Remove-NetFirewallRule -DisplayName "IM PLC 5020"`.

### Mac A: middleware + dashboard (`<MW_IP>`)

Terminal 1, dashboard (loopback only):
```bash
python dashboard/app.py
```
Terminal 2, middleware:
```bash
export IM_PLC_HOST=<PLC_IP>
export IM_TRUSTED_SOURCES="<SCADA_IP>,<ATTACKER_IP>"   # see "Two attack modes" below
export IM_HMAC_SECRET="<the shared 32+ character secret>"
python -m middleware.middleware_server
```
Firewall: macOS asks "Do you want python to accept incoming network connections?" the first time: choose **Allow**. Or in advance:
`sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add "$(which python3)" --unblockapp "$(which python3)"`.

### Mac B: SCADA (`<SCADA_IP>`)

```bash
export IM_MIDDLEWARE_HOST=<MW_IP>
export IM_HMAC_SECRET="<the shared secret>"
python -m scada.scada
```

### Windows B: attacker (`<ATTACKER_IP>`)

```powershell
$env:IM_MIDDLEWARE_HOST = "<MW_IP>"
$env:IM_PLC_HOST = "<PLC_IP>"                  # only the false-injection attack talks to the PLC directly
$env:IM_HMAC_SECRET = "<the shared secret>"
python attacker\attacker.py random --type ramp
python attacker\attacker.py hmac-tamper
```
Do **not** pass `--source-ip` across machines: the real address of Windows B is the source.

### Two attack modes (pick one before the demo)

The middleware's first check is the source whitelist, so which attacks you see depends on `IM_TRUSTED_SOURCES`:

| Mode | `IM_TRUSTED_SOURCES` | What the audience sees |
|---|---|---|
| **A. Insider / stolen key** (default for the HMAC, replay, flood, ramp, cross-register attacks) | `<SCADA_IP>,<ATTACKER_IP>` | the attacker passes the whitelist, so the *later* layers (rate limit, HMAC, replay, physical rules) are what stop it |
| **B. External stranger** | `<SCADA_IP>` only | every frame from Windows B dies at the first check, `UNTRUSTED_SOURCE` |

Restart the middleware to switch modes; it reads the variable at start-up.

## Preflight (run on each laptop, in this order: PLC, middleware, dashboard, SCADA, attacker)

```
python -m tools.check_topology --role plc --multi
python -m tools.check_topology --role middleware --multi
python -m tools.check_topology --role dashboard --multi
python -m tools.check_topology --role scada --multi
python -m tools.check_topology --role attacker --multi
```
`--multi` turns a leftover loopback setting into an error. It also checks reachability of the peers, whether the ports are free, and
prints the HMAC secret fingerprint. If a peer is unreachable from another laptop although it is running: client isolation on the
Wi-Fi access point (common on guest and campus networks) or a firewall. A phone hotspot or a small Ethernet switch avoids both.

## Single-laptop rehearsal (works today, no IP to set)

Run all five components on one machine with no variables set; everything is on loopback. This is exactly what was used to test the
packet tracer and the Wireshark filters. Capture interface: `lo0` (macOS), `Adapter for loopback traffic capture` (Windows, Npcap).
