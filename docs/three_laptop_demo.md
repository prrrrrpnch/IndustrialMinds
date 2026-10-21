# Three-laptop demo (and how it becomes four tomorrow)

Status: the layout below was exercised on loopback with real processes, real signed frames and the real attacker CLI, each
role on its own address (see "What was verified"). It has **not** yet been run on three physical laptops. No IP address is
written anywhere in the repository: you type the real ones into `config/lab.env` on each laptop (that file is git-ignored).

## The layout

One role has to double up. The best pairing is **PLC + SCADA on the same laptop**.

| Laptop | Runs | Why it goes here |
|---|---|---|
| **Laptop 1** (audience screen) | **Middleware + Dashboard + Wireshark** | The dashboard is the thing people watch. Every command passes through this machine, so a capture here shows every frame, including dropped ones. |
| **Laptop 2** | **PLC twin + SCADA operator** | SCADA still sends its commands *over the network* to Laptop 1, so the legitimate traffic is real packets, not loopback. The PLC is still a separate machine from the middleware, so the "bypass is refused" demo works. |
| **Laptop 3** | **Attacker** | A genuinely foreign source address, which is the point of the demo. |

Traffic: `SCADA (L2) -> Middleware :5021 (L1) -> PLC :5020 (L2)`, and `Attacker (L3) -> Middleware :5021 (L1)`.

Why not put SCADA on the middleware laptop instead? SCADA's traffic would then travel over loopback and never appear on the
network, so Wireshark could not show the legitimate half of the story, and the whitelist would mix `127.0.0.1` with a LAN address.

## Tomorrow, with the fourth laptop

Move **SCADA** onto it. Nothing else moves. Set `SCADA_IP` to the new laptop's address in `config/lab.env` on Laptop 1,
restart the middleware, and run `scada` on the new laptop. The attacker and the PLC keep their setup.

## 0. Before anything (all three laptops)

- Same Wi-Fi or switch, and **not** a guest/campus network. Client isolation blocks laptop-to-laptop traffic and looks exactly
  like a broken demo. A phone hotspot or a small Ethernet switch avoids it.
- Clocks automatic (macOS: Date & Time; Windows: Settings -> Time & language -> Sync now). The middleware rejects frames
  more than 30 s off its own clock (`HMAC_EXPIRED`), and a skewed laptop looks like a replay attack.
- Python 3.13, then from the repo root: `pip install -r requirements.txt` (pymodbus stays at 3.6.9).
- Find each laptop's address: macOS `ipconfig getifaddr en0`; Windows `ipconfig` -> IPv4 Address.

## 1. `config/lab.env` (identical on all three laptops)

```
cp config/lab.env.example config/lab.env          # Windows: Copy-Item config\lab.env.example config\lab.env
```
```
MW_IP=<LAPTOP1_IP>
PLC_IP=<LAPTOP2_IP>
SCADA_IP=<LAPTOP2_IP>          # the SAME as PLC_IP, because both run on Laptop 2
ATTACKER_IP=<LAPTOP3_IP>
HMAC_SECRET=<one random string, 32+ chars, IDENTICAL everywhere>
```
Generate the secret once: `python3 -c "import secrets; print(secrets.token_hex(24))"`, then paste it on all three.
`DASHBOARD_BIND_HOST` stays `127.0.0.1`: the dashboard is viewed on Laptop 1 itself, so no token is needed.

## 2. Firewalls

**Laptop 2 (PLC)** must let the middleware reach port 5020, and, for the bypass demo, the attacker too.
Without the attacker rule the bypass attempt just times out, which stops it but shows the audience nothing.
Windows, PowerShell as Administrator:
```powershell
New-NetFirewallRule -DisplayName "IM PLC 5020" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5020 -RemoteAddress <LAPTOP1_IP>,<LAPTOP3_IP> -Profile Any
```
Remove it afterwards: `Remove-NetFirewallRule -DisplayName "IM PLC 5020"`.
macOS: click **Allow** when asked "accept incoming network connections?" the first time Python runs.

**Laptop 1 (middleware)** must accept port 5021 from Laptops 2 and 3. macOS: click **Allow** on the prompt. Windows:
```powershell
New-NetFirewallRule -DisplayName "IM MW 5021" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5021 -RemoteAddress <LAPTOP2_IP>,<LAPTOP3_IP> -Profile Any
```

## 3. Preflight (run each, in this order; fix every FAIL before the demo)

```
./scripts/run.sh check plc            # Windows: .\scripts\run.ps1 check plc        (on Laptop 2)
./scripts/run.sh check middleware     #                                              (on Laptop 1)
./scripts/run.sh check scada          #                                              (on Laptop 2)
./scripts/run.sh check attacker       #                                              (on Laptop 3)
```
Each signing role prints an 8-hex-digit **secret fingerprint**. It must be identical on Laptops 1, 2 and 3.
The `plc` check fails if the PLC does not know who the middleware is (see Troubleshooting).

## 4. Start order (a terminal per item; replace `./scripts/run.sh` with `.\scripts\run.ps1` on Windows)

| Order | Laptop | Command |
|---|---|---|
| 1 | Laptop 2 | `./scripts/run.sh plc` |
| 2 | Laptop 1 | `./scripts/run.sh dashboard` then open `http://127.0.0.1:5050` |
| 3 | Laptop 1 | `./scripts/run.sh middleware` |
| 4 | Laptop 2 | `./scripts/run.sh scada` (a second terminal on Laptop 2) |
| 5 | Laptop 3 | nothing yet |

**Wait about 2 minutes after the middleware starts** (the physical model needs a 120 s window). Before that the dashboard
shows WARMING_UP, and you would have to explain it live.

## 5. The show (Laptop 3 runs these; always do a normal command first)

Watch the dashboard on Laptop 1 and the **Packet Tracer** panel at the bottom. Each attack shows which check stopped it.

| # | On Laptop 3 | What the audience sees |
|---|---|---|
| 0 | (SCADA is already sending normal commands from Laptop 2) | green PASS rows, the tanks moving |
| 1 | `./scripts/run.sh attacker impossible-command` | `OUT_OF_BOUNDS`, dropped, never reached the plant |
| 2 | `./scripts/run.sh attacker hmac-tamper` | `HMAC_INVALID`: a valid frame with the value altered |
| 3 | `./scripts/run.sh attacker replay` | first copy passes, the byte-identical copy is `REPLAY_DETECTED` |
| 4 | `./scripts/run.sh attacker flood` | `RATE_LIMIT_EXCEEDED` once the burst passes 5 requests/s |
| 5 | `./scripts/run.sh attacker cross-register` | each step is individually legal; the combination is stopped (`CROSS_REGISTER_VIOLATION`) |
| 6 | `./scripts/run.sh attacker false-injection` | **the bypass.** It skips the middleware and writes straight to the PLC. Look at the PLC terminal on Laptop 2: `REFUSED direct write from <LAPTOP3_IP>`, and the plant does not move |

Why this order: 1 to 5 go *through* the middleware and are stopped by it. Number 6 goes *around* it, which no inline device
can stop. The PLC refuses it (it only accepts writes from the middleware), and that is the honest ending: say that this is
defence in depth, that a spoofed source address would still get through, and that network segmentation is the real control.

Optional: `./scripts/run.sh attacker random --type ramp` runs a randomised slow-ramp attack with a printed seed.

## 6. Seeing it in Wireshark (this is the proof)

Use **one** port range, never the preference twice (the second value replaces the first): Edit -> Preferences -> Protocols ->
Modbus/TCP -> port `5020,5021`.

- **Laptop 1** (middleware): filter `tcp.port == 5021`. Every frame from SCADA and the attacker arrives here, including those that
  are dropped. Signed frames are `modbus.func_code == 16 && modbus.reference_num == 100`.
- **Laptop 2** (PLC): filter `tcp.port == 5020`. Only what *really reached the plant*: the middleware's forwarded writes, and the
  attacker's bypass attempt. Dropped frames from attacks 1 to 5 never appear here. That absence is the proof.

Capture interface: macOS `en0`; Windows the Wi-Fi/Ethernet adapter. Not loopback, since the traffic is now on the network.

## 7. After the demo

SCADA reset: `./scripts/run.sh scada --restore` (on Laptop 2). Remove the firewall rules from section 2.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Every normal command shows `UNDELIVERED`, and the PLC log says `REFUSED direct write from <LAPTOP1_IP>` | The PLC laptop does not know who the middleware is, so it refuses the middleware's own writes. Start it with `./scripts/run.sh plc` (the launcher sets `IM_MIDDLEWARE_HOST`), or set `IM_MIDDLEWARE_HOST=<LAPTOP1_IP>` yourself. The `check plc` preflight catches this. |
| `UNTRUSTED_SOURCE` for SCADA | Laptop 1's trusted list is missing Laptop 2. Use `./scripts/run.sh middleware` (it builds the list from `SCADA_IP,ATTACKER_IP`). |
| `HMAC_INVALID` for SCADA's normal commands | The secrets differ. Compare the fingerprints from the preflight. |
| `HMAC_EXPIRED` | Clock skew between laptops. Sync the time. |
| Nothing connects across laptops, but each works alone | Client isolation on the Wi-Fi, or a firewall. Use a hotspot or a switch. |
| The attacker's forged frames never get quarantined | By design (audit S4): only commands that passed HMAC count toward a quarantine, so a spoofed address cannot get the real operator locked out. Forged frames are still dropped, logged and raised as an incident. |

## What was verified

On one machine, with each role on a distinct loopback address (middleware, PLC+SCADA sharing one address, attacker on its own):
a signed command from the SCADA address passed and moved the plant; the attacker CLI's `impossible-command` was dropped as
`OUT_OF_BOUNDS`, `hmac-tamper` as `HMAC_INVALID`, and `replay` as `REPLAY_DETECTED`; and the attacker's direct write was
`REFUSED` by the PLC and did not move the plant. Running it also exposed a real bug, now fixed and tested: the PLC laptop was
never told who the middleware was, so on separate machines it would have refused the middleware's own writes.
What this does **not** prove: behaviour on real Wi-Fi, real firewalls, or macOS/Windows differences.
