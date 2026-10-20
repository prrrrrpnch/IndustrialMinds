# Wireshark / tshark: proof from the wire

Wireshark (GUI) and tshark (command line) are free, ship the Modbus/TCP dissector, and see the real packets regardless of
anything the dashboard says. That is the point: the dashboard is the system's own account of what happened; the capture is the
independent one.

**What was verified, and how.** The capture filters, the Modbus preference, every field name and the nonce correlation below were
run against real traffic from this stack (PLC + middleware + dashboard + attacker on loopback) with tshark 4.2.2 on Linux. The
Wireshark GUI menus, macOS/Windows interface names and Npcap/ChmodBPF permissions are written from the documentation and have
**not** been tried on the actual laptops.

## Install

* macOS: install Wireshark from wireshark.org and tick **Install ChmodBPF** (lets a normal user capture). tshark is included.
* Windows: install Wireshark and let it install **Npcap** (tick *Support loopback traffic* if you want to rehearse on one machine).
* List interfaces: `tshark -D`. Typical: macOS `en0` (Wi-Fi/Ethernet), `lo0` (loopback); Windows: the name shown for your Wi-Fi/Ethernet.

## The one thing that trips everybody: the Modbus port

Wireshark decodes Modbus/TCP only on port 502. This system uses **5021** (middleware) and **5020** (PLC), so by default the capture
shows plain TCP and **no Modbus at all** (verified: 0 Modbus packets). Do **not** use *Decode As* for this: it decodes the frames but
cannot tell requests from responses (it reports "Cannot classify packet type") and the register values stay empty. Set the Modbus/TCP
**port preference** instead, one port per capture:

| Where | Wireshark GUI | tshark option |
|---|---|---|
| Mac A (middleware leg) | Edit -> Preferences -> Protocols -> Modbus/TCP -> "Modbus/TCP port" = **5021** | `-o mbtcp.tcp.port:5021` |
| Windows A (PLC leg) | same, = **5020** | `-o mbtcp.tcp.port:5020` |
| one machine watching BOTH legs | same, = **5020,5021** (one range) | `-o mbtcp.tcp.port:5020,5021` |

**Both legs in one capture:** give the preference a single range, `5020,5021`. Setting it twice (`-o mbtcp.tcp.port:5021
-o mbtcp.tcp.port:5020`) does **not** work: the second value replaces the first, and frames on the other port are then shown as
*"Unable to classify as query or response"* with no `modbus.reference_num`. Verified with tshark 4.2.2.

(To look at the PLC leg from Mac A as well, open the same capture a second time with the port set to 5020.)

## Capture filters (BPF, applied while capturing; these are NOT display filters)

| Laptop | Capture filter |
|---|---|
| Mac A (middleware) | `tcp port 5021` (add `or tcp port 5020` to also record the middleware -> PLC leg) |
| Windows A (PLC) | `tcp port 5020` |

## Display filters (verified field names)

| Goal | Filter |
|---|---|
| Only Modbus | `mbtcp` |
| Signed command frames from SCADA/attacker (FC16 to register 100, 27 words) | `modbus.func_code == 16 && tcp.dstport == 5021` |
| Frames from one sender | `... && ip.src == <ATTACKER_IP>` |
| Writes the middleware forwarded to the plant | `modbus.func_code == 6 && tcp.dstport == 5020` |
| The middleware's 5 Hz polling (hide it) | `!(modbus.func_code == 3)` |
| Responses | `tcp.srcport == 5021` |

Useful columns (right-click a field -> Apply as Column): `modbus.reference_num`, `modbus.word_cnt`, `modbus.regval_uint16`.

### Reading a signed command frame

A command is one FC16 write to address **100** with 27 words, in this order (`docs/interfaces.py`, `docs/hmac_auth.py`):

| Words (`modbus.regval_uint16`) | Content |
|---|---|
| 0 | frame version (1) |
| 1 | target register (0 = MV101, 1 = P101, ...) |
| 2 | value x 10 (560 = 56.0 %) |
| 3-6 | **nonce** (64 bit, 4 words) |
| 7-10 | timestamp (ms, 4 words) |
| 11-26 | HMAC-SHA256 tag (32 bytes) |

The forwarded write on the PLC leg is a different, simple packet: **FC6, reference number = register, data = value x 10** (hex).
Example from a real capture: FC6, reference 0, data `0230` = 560 = 56.0.

## Matching a packet to a dashboard entry (the tx_id)

The tx_id is created inside the middleware, so it is not on the wire. The **nonce** is on the wire and the Packet Tracer shows it in
its Arrival hop (`nonce_words`). Same four numbers = same command. Verified on a real capture: the nonce words in tshark
(`37659,63920,1570,6983`) were exactly the Arrival-hop nonce words of the dashboard entry for that command.

Automate it with `tools/wire_correlate.py`. It matches every signed frame in the capture to its tracer entry, and (if you also
give it the PLC capture) checks the part that matters: **a DROPped command is on the middleware leg but not on the PLC leg; a
forwarded one is on both.** It prints `MISMATCH` and exits non-zero otherwise.

```
# Mac A: record the middleware leg (Ctrl-C to stop), in the layout the tool expects
tshark -i <interface> -f "tcp port 5021" -o mbtcp.tcp.port:5021 -Y mbtcp -T fields \
  -e frame.number -e frame.time_epoch -e ip.src -e tcp.dstport -e modbus.func_code \
  -e modbus.reference_num -e modbus.regval_uint16 -e modbus.data > mw.tsv

# Windows A (PowerShell): the PLC leg
tshark -i <interface> -f "tcp port 5020" -o mbtcp.tcp.port:5020 -Y mbtcp -T fields `
  -e frame.number -e frame.time_epoch -e ip.src -e tcp.dstport -e modbus.func_code `
  -e modbus.reference_num -e modbus.regval_uint16 -e modbus.data > plc.tsv

# copy plc.tsv to Mac A, then (the dashboard is on this laptop)
python -m tools.wire_correlate --mw mw.tsv --plc plc.tsv
```
Output, one line per signed frame on the wire: its tx id, verdict, reason and whether it reached the PLC. The clocks of the laptops
do not need to agree for this: matching uses the nonce and the (register, value) pair, not capture time.

## The side-by-side demo moment (about 90 seconds)

Screens: Mac A shows the dashboard Packet Tracer on one half and Wireshark (filter `modbus.func_code == 16 && tcp.dstport == 5021`)
on the other. Windows A shows Wireshark with `modbus.func_code == 6 && tcp.dstport == 5020`.

1. **One normal frame.** On Mac B the SCADA operator sends a setpoint. In Mac A's Wireshark a new FC16 frame appears (words 1 and 2
   are the register and value). In the Packet Tracer the newest entry is `PASS`: seven hops, all green. Windows A's Wireshark shows
   the matching **FC6 write** a few milliseconds later. Point at the nonce words in Wireshark and in the Arrival hop: the same four
   numbers.
2. **One tampered frame.** On Windows B run `python attacker\attacker.py hmac-tamper`. Mac A's Wireshark shows the frame **on the
   wire** (the attack is real traffic, not a dashboard animation); word 2 is 950 (95.0 %). The Packet Tracer entry is `DROP`: the
   Cyber Agent's `hmac` check is the red row, `replay` is `NOT_RUN`, the outcome says "dropped before the PLC" and names the log
   file. Windows A's Wireshark shows **nothing**: the frame never reached the plant.
3. **Close the loop.** `python -m tools.wire_correlate --mw mw.tsv --plc plc.tsv` prints both frames with their tx ids and
   `on PLC leg: yes` for the first and `NO` for the second.

For a one-laptop rehearsal use `-i lo0` (macOS) / `-i lo` (Linux) and run both legs on the same machine.

## Limits to say out loud

* A capture shows the frames, not whether the HMAC is valid; the validity verdict comes from the middleware and is shown in the tracer.
* The whole demo runs over plain TCP on a private network; there is no confidentiality, only integrity and authenticity.
* Wireshark's byte-level view of the tag cannot prove forgery either way; it proves only that the bytes were sent and that nothing
  forwarded followed them.
