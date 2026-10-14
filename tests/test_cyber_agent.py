import time
from docs.interfaces import make_command
from docs import hmac_auth
from middleware import cyber_agent


def signed(tx_id, ts, src, fc, register, value, key=None, timestamp_ms=None):
    """Build a command exactly as the middleware would after parsing a signed frame."""
    parsed = hmac_auth.parse_frame(
        hmac_auth.build_frame(register, value, key=key,
                              timestamp_ms=timestamp_ms or int(ts * 1000))
    )
    return make_command(tx_id, ts, src, fc, register, value,
                        raw_value=parsed["raw_value"], auth=parsed["auth"])


cyber_agent.reset_state()
SRC = "192.168.1.10"

# 1. Normal command -> expect PASS
cmd = signed("tx1", time.time(), SRC, 16, 2, 45.0)
print("1. Normal command:", cyber_agent.check(cmd))
# EXPECTED: {'tx_id': 'tx1', 'pass': True, 'reason': 'OK', 'agent': 'cyber'}

# 2. Flood: send 7 requests fast from the same source -> later ones DROP
cyber_agent.reset_state()
for i in range(7):
    cmd = signed(f"tx-flood-{i}", time.time(), SRC, 16, 2, 45.0 + i)
    result = cyber_agent.check(cmd)
    print(f"2.{i} Flood request:", result)
# EXPECTED: first 5 -> pass: True, requests 6 and 7 -> pass: False, reason 'RATE_LIMIT_EXCEEDED'

# 3. Untrusted source -> expect DROP
cyber_agent.reset_state()
cmd = signed("tx2", time.time(), "10.0.0.99", 16, 2, 45.0)
print("3. Untrusted source:", cyber_agent.check(cmd))
# EXPECTED: {'tx_id': 'tx2', 'pass': False, 'reason': 'UNTRUSTED_SOURCE', 'agent': 'cyber'}

# 4. Invalid function code -> expect DROP
cmd = signed("tx3", time.time(), SRC, 99, 2, 45.0)
print("4. Bad function code:", cyber_agent.check(cmd))
# EXPECTED: {'tx_id': 'tx3', 'pass': False, 'reason': 'INVALID_FUNCTION_CODE', 'agent': 'cyber'}

# 5. Replay: same exact payload sent twice -> second one DROP
cyber_agent.reset_state()
cmd = signed("tx4", time.time(), SRC, 16, 2, 45.0)
r5a = cyber_agent.check(cmd)
print("5a. First send:", r5a)
cmd2 = dict(cmd, tx_id="tx5")   # byte-identical signed frame sent again
r5b = cyber_agent.check(cmd2)
print("5b. Replayed send:", r5b)
# EXPECTED: 5a pass: True, 5b pass: False, reason 'REPLAY_DETECTED...'
assert r5a["pass"] and not r5b["pass"] and r5b["reason"].startswith("REPLAY_DETECTED")


# ---- HMAC-SHA256 ----
cyber_agent.reset_state()
now = time.time()

r = cyber_agent.check(make_command("h1", now, SRC, 6, 2, 45.0))
print("6. Missing HMAC:", r)
assert not r["pass"] and r["reason"].startswith("HMAC_MISSING")

c = signed("h2", now, SRC, 16, 2, 46.0)
c["raw_value"] = 800     # value tampered after signing
c["value"] = 80.0
r = cyber_agent.check(c)
print("7. Tampered value:", r)
assert not r["pass"] and r["reason"].startswith("HMAC_INVALID")

r = cyber_agent.check(signed("h3", now, SRC, 16, 2, 47.0, key=b"x" * 64))
print("8. Wrong key:", r)
assert not r["pass"] and r["reason"].startswith("HMAC_INVALID")

r = cyber_agent.check(signed("h4", now, SRC, 16, 2, 48.0, timestamp_ms=int((now - 300) * 1000)))
print("9. Expired signature:", r)
assert not r["pass"] and r["reason"].startswith("HMAC_EXPIRED")

c = signed("h5", now, SRC, 16, 2, 49.0)
c["auth"] = dict(c["auth"], mac=c["auth"]["mac"][:10])
r = cyber_agent.check(c)
print("10. Truncated tag:", r)
assert not r["pass"] and r["reason"].startswith("HMAC_MALFORMED")

cyber_agent.reset_state()
r = cyber_agent.check(signed("h6", now, SRC, 16, 5, 50.0))
print("11. Valid HMAC on new machine register 5:", r)
assert r["pass"]

print("\nAll cyber agent checks passed")
