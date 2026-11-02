#!/usr/bin/env python3
"""
PreToolUse guard for IndustrialMind (deterministic hard rules from prompt Step 0).

Rules enforced:
  R1  file deletion       -> blocked unless every target was confirmed this session
  R2  model weight files  -> existing models/weights/* blocked unless retraining of
                             that specific model was confirmed this session
  R3  IP addresses        -> any IPv4 in a command / written content must be loopback,
                             0.0.0.0, or a laptop IP confirmed in Phase 10
  R4  state file          -> confirmations may only be written via confirm.py

Confirmations live in .claude/state/confirmations.json (git-ignored), written only by
.claude/hooks/confirm.py, and are scoped to the current session id.
Exit code 2 = block (stderr is shown to the model).
"""
import ipaddress, json, os, re, shlex, sys

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", ".."))
STATE_DIR = os.path.join(ROOT, ".claude", "state")
CONF = os.path.join(STATE_DIR, "confirmations.json")
SESSION_FILE = os.path.join(STATE_DIR, "current_session")
WEIGHTS = os.path.join(ROOT, "models", "weights")
IP_RE = re.compile(r"(?<![\d.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\d.])")
SAFE_TMP = ("/tmp/claude-", "/root/.claude/")

def block(msg):
    sys.stderr.write("BLOCKED by .claude/hooks/guard.py: " + msg + "\n")
    sys.exit(2)

def load_conf(session):
    try:
        with open(CONF) as f:
            data = json.load(f)
    except Exception:
        data = {}
    return data.get(session, {"delete": [], "retrain": [], "ips": []})

def absp(p, cwd):
    p = os.path.expanduser(p)
    return os.path.realpath(p if os.path.isabs(p) else os.path.join(cwd, p))

def is_safe_tmp(p):
    return p.startswith(SAFE_TMP) or p.endswith("__pycache__") or "/__pycache__/" in p

def delete_confirmed(path, conf):
    for c in conf["delete"]:
        c = absp(c, ROOT)
        if path == c or path.startswith(c + os.sep):
            return True
    return False

def check_ips(text, conf, where):
    for ip in IP_RE.findall(text):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if a.is_loopback or ip == "0.0.0.0" or ip in conf["ips"]:
            continue
        block(f"IP {ip} in {where} is not loopback/0.0.0.0 and not a laptop IP confirmed in "
              f"Phase 10. Use an env var/CLI arg, or confirm IPs via confirm.py ips <ip...>.")

def model_of(path):
    base = os.path.basename(path)
    for m in ("cyber", "physical", "orchestrator"):
        if m in base:
            return m
    return "unknown"

def check_weight_write(path, conf):
    if not path.startswith(WEIGHTS + os.sep):
        return
    if os.path.exists(path):
        m = model_of(path)
        if m not in conf["retrain"] and "all" not in conf["retrain"]:
            block(f"{path} is an existing trained weight/report file; retraining of model "
                  f"'{m}' not confirmed this session. Write candidates to models/candidates/ instead.")

RM_LIKE = {"rm", "rmdir", "unlink", "shred", "trash", "trash-put"}

def split_commands(cmd):
    return [s for s in re.split(r"&&|\|\||;|\||\n", cmd) if s.strip()]

def check_bash(cmd, cwd, conf):
    # R4: state file
    if "confirmations.json" in cmd and "confirm.py" not in cmd:
        block("confirmations.json may only be modified through .claude/hooks/confirm.py")
    if "settings.json" in cmd and ".claude" in cmd and re.search(r">|sed -i|tee|mv |cp |rm ", cmd):
        block("do not modify .claude/settings.json from the shell; use Edit with user confirmation")
    # R3: IPs anywhere in the command (skip our own confirm helper)
    if "confirm.py" not in cmd:
        check_ips(cmd, conf, "shell command")
    # R1: deletions
    for seg in split_commands(cmd):
        try:
            toks = shlex.split(seg)
        except ValueError:
            toks = seg.split()
        if not toks:
            continue
        while toks and (toks[0] in ("sudo", "command", "env") or "=" in toks[0].split("/")[-1]):
            toks = toks[1:]
        if not toks:
            continue
        prog = os.path.basename(toks[0])
        targets = None
        if prog in RM_LIKE:
            targets = [t for t in toks[1:] if not t.startswith("-")]
        elif prog == "git" and len(toks) > 1 and toks[1] in ("rm", "clean"):
            if toks[1] == "clean":
                block("git clean deletes files; needs explicit confirmation (confirm.py delete <path>)")
            targets = [t for t in toks[2:] if not t.startswith("-")]
        elif prog == "find" and ("-delete" in toks or "-exec" in toks and any(t in ("rm", "rmdir") for t in toks)):
            targets = [t for t in toks[1:] if not t.startswith("-")][:1] or ["."]
        elif prog == "mv" and len(toks) >= 3:
            # mv onto an existing weights file is an overwrite
            dest = absp(toks[-1], cwd)
            check_weight_write(dest, conf)
        if targets is not None:
            if not targets:
                block("deletion command with no parsable target")
            for t in targets:
                if any(ch in t for ch in "*?[$`"):
                    block(f"deletion target '{t}' uses a glob/variable; list exact paths and confirm them")
                p = absp(t, cwd)
                if is_safe_tmp(p) or delete_confirmed(p, conf):
                    continue
                block(f"deleting {p} was not confirmed this session (confirm.py delete <path> after user approval)")
    # inline-python deletions
    if re.search(r"(os\.(remove|unlink|rmdir)|shutil\.rmtree|\.unlink\(|\.rmdir\(|rmtree)", cmd):
        block("inline deletion via python is blocked; use an explicit, confirmed rm")
    # R2: weights
    if "models/weights" in cmd or "models\\weights" in cmd:
        if re.search(r"(>|>>|\btee\b|\bcp\b|\bmv\b|\binstall\b|\bdd\b|joblib\.dump|\.dump\(|\bsed -i)", cmd):
            for m in re.findall(r"models/weights/[\w.\-]+", cmd):
                check_weight_write(absp(m, ROOT), conf)
    # only EXECUTION of a training entry point (python [-m] ...train...), not reads like sed/cat/grep
    if re.search(r"\bpython[\d.]*\s+(-\w+\s+)*(-m\s+)?[\w./\\]*train\w*(\.py)?\b", cmd):
        if "--candidate" not in cmd and "--out-dir" not in cmd and not conf["retrain"]:
            block("training commands that may write models/weights need --candidate/--out-dir "
                  "(writes to models/candidates/) or a confirmed retrain for that model")

def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        sys.exit(0)
    tool = data.get("tool_name", "")
    ti = data.get("tool_input", {}) or {}
    cwd = data.get("cwd") or ROOT
    session = data.get("session_id", "unknown")
    os.makedirs(STATE_DIR, exist_ok=True)
    try:
        with open(SESSION_FILE, "w") as f:
            f.write(session)
    except Exception:
        pass
    conf = load_conf(session)

    if tool == "Bash":
        check_bash(ti.get("command", ""), cwd, conf)
    elif tool in ("Write", "Edit", "NotebookEdit"):
        path = absp(ti.get("file_path", ""), cwd)
        if path == CONF:
            block("confirmations.json may only be modified through confirm.py")
        if path.endswith(os.path.join(".claude", "hooks", "guard.py")) or path.endswith(os.path.join(".claude", "settings.json")):
            if "guard-edit" not in conf["retrain"] and "guard-edit" not in conf["delete"]:
                pass  # editing the guard itself is allowed during Step 0; tracked in git
        check_weight_write(path, conf)
        text = ti.get("content") or ti.get("new_string") or ""
        if not path.endswith(".claude/hooks/guard.py") and not is_safe_tmp(path):
            check_ips(text, conf, path)
    elif tool == "mcp__github__delete_file":
        block("remote file deletion needs explicit confirmation")
    sys.exit(0)

if __name__ == "__main__":
    main()
