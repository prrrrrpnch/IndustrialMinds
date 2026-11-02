"""
attacker/control_panel.py - a menu-driven attack panel: click a button, the attack runs, its output streams into the page.

    python -m attacker.control_panel                 # serves http://127.0.0.1:5070 and opens it in the browser
    python -m attacker.control_panel --no-browser
    IM_PANEL_PORT=5071 python -m attacker.control_panel

Runs on the ATTACKER machine. It does not attack by itself: every button starts the same launcher the command line uses
(scripts/run.ps1 on Windows, scripts/run.sh elsewhere -> attacker/attacker.py), so addresses, the secret and the attack
code are exactly what config/lab.env and attacker.py already say. The dashboard has no attack controls and still has none.

Safety of the panel itself:
  * it listens on 127.0.0.1 only (never the network), and refuses requests whose Host header is not the loopback name
    (DNS-rebinding), and POSTs without the X-Panel header (a web page on another site cannot set it);
  * a button can only start an attack from the fixed list below (the id is looked up, never passed to a shell);
  * one attack at a time: a second click while one runs is refused, so the middleware's rate limiter is not confused
    by two overlapping runs. Stop ends the running attack.
Standard library only.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = int(os.environ.get("IM_PANEL_PORT", "5070"))
PAUSE_BETWEEN_S = 5.0
MAX_LINES = 4000

# id -> what the button says, what it does, and what the middleware should answer (from attacker/attacker.py).
ATTACKS: List[Dict] = [
    {"id": "hmac-missing", "group": "Authentication", "label": "Unsigned command", "args": ["hmac-missing"],
     "what": "A plain write with no HMAC tag.", "expect": "DROP  HMAC_MISSING"},
    {"id": "hmac-tamper", "group": "Authentication", "label": "Tampered command", "args": ["hmac-tamper"],
     "what": "A validly signed frame whose value was altered in transit.", "expect": "DROP  HMAC_INVALID"},
    {"id": "hmac-forged", "group": "Authentication", "label": "Forged signature", "args": ["hmac-forged"],
     "what": "A frame signed with a guessed key.", "expect": "DROP  HMAC_INVALID"},
    {"id": "replay", "group": "Authentication", "label": "Replay", "args": ["replay"],
     "what": "A byte-identical re-send of a signed frame.", "expect": "DROP  REPLAY_DETECTED"},
    {"id": "flood", "group": "Commands", "label": "Flood", "args": ["flood"],
     "what": "A signed burst above the 5 requests/s limit.", "expect": "DROP  RATE_LIMIT_EXCEEDED"},
    {"id": "impossible-command", "group": "Commands", "label": "Impossible value", "args": ["impossible-command"],
     "what": "A signed, out-of-range actuator value.", "expect": "DROP  OUT_OF_BOUNDS"},
    {"id": "sensor-write", "group": "Commands", "label": "Write to a sensor", "args": ["sensor-write"],
     "what": "A signed, in-range write aimed at a read-only sensor.", "expect": "DROP  WRITE_TO_SENSOR_REGISTER"},
    {"id": "cross-register", "group": "Commands", "label": "Cross-register", "args": ["cross-register"],
     "what": "Low and slow: every step is legal, the combined plant state is unsafe.",
     "expect": "DROP  CROSS_REGISTER_VIOLATION"},
    {"id": "random-ramp", "group": "Commands", "label": "Random ramp", "args": ["random", "--type", "ramp"],
     "what": "A randomised ramp (new parameters each run; the seed is printed).", "expect": "varies"},
    {"id": "false-injection", "group": "Direct to PLC", "label": "False injection", "args": ["false-injection"],
     "what": "A legitimate command, then a write straight to the PLC, bypassing the middleware.",
     "expect": "PLC refuses the direct write"},
]
BY_ID = {a["id"]: a for a in ATTACKS}


def launcher_command(args: List[str]) -> List[str]:
    """The same launcher a person would type, so lab.env (addresses, secret) is honoured."""
    if sys.platform.startswith("win"):
        return ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                os.path.join(ROOT, "scripts", "run.ps1"), "attacker", *args]
    return ["bash", os.path.join(ROOT, "scripts", "run.sh"), "attacker", *args]


class Runner:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.proc: Optional[subprocess.Popen] = None
        self.label = ""
        self.lines: List[Dict] = []          # {"n", "text", "kind"}
        self.history: List[Dict] = []        # {"label", "started", "seconds", "code"}
        self.seq = 0
        self.all_thread: Optional[threading.Thread] = None
        self.stopping = False

    # ---- output ----------------------------------------------------------------------------------------------------
    def emit(self, text: str, kind: str = "out") -> None:
        with self.lock:
            self.seq += 1
            self.lines.append({"n": self.seq, "text": text.rstrip("\r\n"), "kind": kind})
            if len(self.lines) > MAX_LINES:
                del self.lines[: len(self.lines) - MAX_LINES]

    def snapshot(self, since: int) -> Dict:
        with self.lock:
            return {"lines": [l for l in self.lines if l["n"] > since], "last": self.seq,
                    "running": self.proc is not None and self.proc.poll() is None,
                    "label": self.label, "run_all": bool(self.all_thread and self.all_thread.is_alive()),
                    "history": self.history[-8:]}

    # ---- one attack --------------------------------------------------------------------------------------------------
    def busy(self) -> bool:
        with self.lock:
            return (self.proc is not None and self.proc.poll() is None) or bool(self.all_thread and self.all_thread.is_alive())

    def _run_blocking(self, attack: Dict) -> int:
        env = dict(os.environ, PYTHONUNBUFFERED="1", PYTHONIOENCODING="utf-8")
        kwargs = {} if sys.platform.startswith("win") else {"start_new_session": True}
        self.emit(f">>> {attack['label']}   ({' '.join(attack['args'])})   expect: {attack['expect']}", "head")
        started = time.time()
        try:
            proc = subprocess.Popen(launcher_command(attack["args"]), cwd=ROOT, env=env, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace", bufsize=1, **kwargs)
        except OSError as exc:
            self.emit(f"could not start the launcher: {exc}", "err")
            return 127
        with self.lock:
            self.proc, self.label = proc, attack["label"]
        for line in proc.stdout:                       # streams until the attack exits or is killed
            self.emit(line, "err" if "Traceback" in line or "Error" in line else "out")
        code = proc.wait()
        self.emit(f"<<< finished (exit code {code}, {time.time() - started:.1f} s)", "head" if code == 0 else "err")
        with self.lock:
            self.history.append({"label": attack["label"], "started": time.strftime("%H:%M:%S", time.localtime(started)),
                                 "seconds": round(time.time() - started, 1), "code": code})
        return code

    def start(self, attack_id: str) -> bool:
        attack = BY_ID.get(attack_id)
        if attack is None or self.busy():
            return False
        self.stopping = False
        threading.Thread(target=self._run_blocking, args=(attack,), daemon=True).start()
        for _ in range(50):                            # let the process register so the next poll sees "running"
            if self.busy():
                break
            time.sleep(0.02)
        return True

    # ---- all attacks ---------------------------------------------------------------------------------------------------
    def _all(self) -> None:
        for attack in ATTACKS:
            if self.stopping:
                break
            self._run_blocking(attack)
            end = time.time() + PAUSE_BETWEEN_S
            while time.time() < end and not self.stopping:
                time.sleep(0.2)
        self.emit("=== run-all finished" + (" (stopped)" if self.stopping else ""), "head")

    def start_all(self) -> bool:
        if self.busy():
            return False
        self.stopping = False
        self.all_thread = threading.Thread(target=self._all, daemon=True)
        self.all_thread.start()
        return True

    def stop(self) -> bool:
        self.stopping = True
        with self.lock:
            proc = self.proc
        if proc is None or proc.poll() is not None:
            return bool(self.all_thread and self.all_thread.is_alive())
        try:
            if sys.platform.startswith("win"):
                subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True)
            else:
                import signal
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (OSError, ProcessLookupError):
            proc.terminate()
        self.emit("--- stopped by the operator", "err")
        return True

    def clear(self) -> None:
        with self.lock:
            self.lines.clear()


RUNNER = Runner()


def target_summary() -> str:
    """Where the attacks go, read from the same lab.env the launcher uses (display only)."""
    path = os.environ.get("IM_LAB_ENV") or os.path.join(ROOT, "config", "lab.env")
    mw = "loopback (this computer)"
    try:
        for line in open(path, encoding="utf-8"):
            line = line.split("#", 1)[0].strip()
            if line.startswith("MW_IP=") and line[6:].strip():
                mw = line[6:].strip()
    except OSError:
        pass
    return f"middleware {mw}:5021"


PAGE = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Attack panel</title>
<style>
:root{--bg:#0f172a;--card:#1e293b;--border:#334155;--text:#f8fafc;--sub:#94a3b8;--muted:#64748b;--red:#f43f5e;--green:#10b981;--blue:#0ea5e9;--amber:#eab308;
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;--sans:system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font:14px/1.5 var(--sans);padding:20px}
.wrap{max-width:1180px;margin:0 auto;display:flex;flex-direction:column;gap:16px}
header{display:flex;align-items:center;gap:16px;background:var(--card);border:1px solid var(--border);border-radius:8px;padding:12px 18px}
header h1{font-size:16px;letter-spacing:.04em}header .t{color:var(--sub);font-family:var(--mono);font-size:12px}
.state{margin-left:auto;font-weight:700;font-size:12px;padding:3px 12px;border-radius:999px;border:1px solid var(--border);color:var(--sub)}
.state.run{color:var(--amber);border-color:rgba(234,179,8,.5);background:rgba(234,179,8,.12)}
.grid{display:grid;grid-template-columns:1fr 1.15fr;gap:16px;align-items:start}
@media(max-width:900px){.grid{grid-template-columns:1fr}}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:14px 16px}
.group{color:var(--muted);font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;margin:6px 0 8px}
.group:first-child{margin-top:0}
.atk{display:flex;gap:12px;align-items:center;padding:8px 0;border-top:1px solid #2b3a52}
.group+.atk{border-top:0}
button{font:inherit;cursor:pointer;border-radius:8px;border:1px solid var(--border);background:#0f172a;color:var(--text);padding:9px 14px;font-weight:600}
button:hover:not(:disabled){border-color:var(--red);color:var(--red)}
button:disabled{opacity:.4;cursor:not-allowed}
.atk button{min-width:170px;text-align:left}
.desc{color:var(--sub);font-size:12px}.exp{font-family:var(--mono);font-size:11px;color:var(--muted)}
.bar{display:flex;gap:10px;margin-top:12px;flex-wrap:wrap}
.bar .all{border-color:rgba(244,63,94,.6);color:var(--red)}
.bar .stop:hover:not(:disabled){border-color:var(--amber);color:var(--amber)}
pre{background:#0b1220;border:1px solid var(--border);border-radius:8px;padding:12px;height:520px;overflow:auto;font:12px/1.55 var(--mono);white-space:pre-wrap;word-break:break-word}
.head{color:var(--blue);font-weight:700}.err{color:var(--red)}.out{color:#cbd5e1}
.hist{font-family:var(--mono);font-size:11px;color:var(--muted);margin-top:8px}
.hist b{color:var(--sub)}.warn{color:var(--amber);font-size:12px;margin-top:10px}
</style></head><body><div class="wrap">
<header><h1>ATTACK PANEL</h1><span class="t" id="target"></span><span class="state" id="state">idle</span></header>
<div class="grid">
 <div class="card"><div id="buttons"></div>
  <div class="bar"><button class="all" id="all">Run all, one after another</button><button class="stop" id="stop" disabled>Stop</button><button id="clear">Clear output</button></div>
  <p class="warn">One attack at a time. Watch the dashboard on Laptop 1 and the two packet captures while these run.</p></div>
 <div class="card"><pre id="out"></pre><div class="hist" id="hist"></div></div>
</div></div>
<script>
const $=id=>document.getElementById(id);let last=0,attacks=[],busy=false;
async function post(path,body){const r=await fetch(path,{method:"POST",headers:{"X-Panel":"1","Content-Type":"application/json"},body:JSON.stringify(body||{})});return r.json().catch(()=>({}))}
async function init(){const d=await (await fetch("/api/attacks")).json();attacks=d.attacks;$("target").textContent="target: "+d.target;
 let html="",g="";for(const a of attacks){if(a.group!==g){g=a.group;html+=`<div class="group">${g}</div>`}
  html+=`<div class="atk"><button data-id="${a.id}">${a.label}</button><div><div class="desc">${a.what}</div><div class="exp">expect: ${a.expect}</div></div></div>`}
 $("buttons").innerHTML=html;
 $("buttons").querySelectorAll("button").forEach(b=>b.onclick=()=>post("/api/run",{id:b.dataset.id}).then(poll));
 $("all").onclick=()=>post("/api/run-all").then(poll);$("stop").onclick=()=>post("/api/stop").then(poll);
 $("clear").onclick=async()=>{await post("/api/clear");$("out").textContent="";poll()};}
function setBusy(b,label,all){busy=b;document.querySelectorAll("#buttons button,#all").forEach(x=>x.disabled=b);$("stop").disabled=!b;
 const s=$("state");s.className="state"+(b?" run":"");s.textContent=b?(all?"running all…":"running: "+label):"idle"}
async function poll(){try{const d=await (await fetch("/api/output?since="+last)).json();const out=$("out");
 const stick=out.scrollTop+out.clientHeight>=out.scrollHeight-30;
 for(const l of d.lines){const s=document.createElement("span");s.className=l.kind;s.textContent=l.text+"\n";out.appendChild(s)}
 last=d.last;if(d.lines.length&&stick)out.scrollTop=out.scrollHeight;
 setBusy(d.running||d.run_all,d.label,d.run_all);
 $("hist").innerHTML=d.history.length?"recent: "+d.history.map(h=>`<b>${h.label}</b> ${h.started} (${h.seconds}s${h.code?`, exit ${h.code}`:""})`).join(" &nbsp;·&nbsp; "):""}catch(e){}
 setTimeout(poll,600)}
init().then(poll);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "AttackPanel"

    def log_message(self, *args) -> None:        # quiet: the page polls every 600 ms
        pass

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]").lower()
        return host in ("127.0.0.1", "localhost")

    def _send(self, code: int, body: bytes, ctype: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj) -> None:
        self._send(code, json.dumps(obj).encode("utf-8"))

    def do_GET(self) -> None:
        if not self._host_ok():
            return self._json(403, {"error": "bad host"})
        url = urlparse(self.path)
        if url.path == "/":
            return self._send(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")
        if url.path == "/api/attacks":
            return self._json(200, {"attacks": ATTACKS, "target": target_summary()})
        if url.path == "/api/output":
            since = int((parse_qs(url.query).get("since") or ["0"])[0] or 0)
            return self._json(200, RUNNER.snapshot(since))
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        if not self._host_ok() or self.headers.get("X-Panel") != "1":
            return self._json(403, {"error": "forbidden"})
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            body = {}
        path = urlparse(self.path).path
        if path == "/api/run":
            ok = RUNNER.start(str(body.get("id", "")))
            return self._json(200 if ok else 409, {"started": ok})
        if path == "/api/run-all":
            ok = RUNNER.start_all()
            return self._json(200 if ok else 409, {"started": ok})
        if path == "/api/stop":
            return self._json(200, {"stopped": RUNNER.stop()})
        if path == "/api/clear":
            RUNNER.clear()
            return self._json(200, {"cleared": True})
        self._json(404, {"error": "not found"})


def main() -> int:
    ap = argparse.ArgumentParser(description="Menu-driven attack panel (runs on the attacker machine).")
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--port", type=int, default=PORT)
    args = ap.parse_args()
    try:
        httpd = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    except OSError as exc:
        print(f"Cannot listen on 127.0.0.1:{args.port}: {exc}\nIs another attack panel already open? (IM_PANEL_PORT changes the port.)")
        return 2
    url = f"http://127.0.0.1:{args.port}"
    print(f"Attack panel: {url}   ({target_summary()})\nCtrl+C stops the panel (and any attack running from it).")
    if not args.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print()
    finally:
        RUNNER.stop()
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
