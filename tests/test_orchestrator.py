import time
from docs.interfaces import make_verdict
from middleware import orchestrator

orchestrator.reset_log()

# 1. Both agents pass -> expect PASS
cyber_ok = make_verdict("tx1", True, "OK", "cyber")
physical_ok = make_verdict("tx1", True, "OK", "physical")
print("1. Both pass:", orchestrator.decide(cyber_ok, physical_ok, time.time()))
# EXPECTED: verdict 'PASS', reason 'OK', direction 'downstream'

# 2. Cyber fails, physical passes -> expect DROP with cyber's reason
cyber_bad = make_verdict("tx2", False, "RATE_LIMIT_EXCEEDED", "cyber")
physical_ok2 = make_verdict("tx2", True, "OK", "physical")
print("2. Cyber fails:", orchestrator.decide(cyber_bad, physical_ok2, time.time()))
# EXPECTED: verdict 'DROP', reason 'RATE_LIMIT_EXCEEDED'

# 3. Cyber passes, physical fails -> expect DROP with physical's reason
cyber_ok3 = make_verdict("tx3", True, "OK", "cyber")
physical_bad = make_verdict("tx3", False, "PHYSICS_VIOLATION", "physical")
print("3. Physical fails:", orchestrator.decide(cyber_ok3, physical_bad, time.time()))
# EXPECTED: verdict 'DROP', reason 'PHYSICS_VIOLATION'

# 4. Both fail -> expect DROP, cyber's reason wins (checked first)
cyber_bad2 = make_verdict("tx4", False, "UNTRUSTED_SOURCE", "cyber")
physical_bad2 = make_verdict("tx4", False, "PHYSICS_VIOLATION", "physical")
print("4. Both fail:", orchestrator.decide(cyber_bad2, physical_bad2, time.time()))
# EXPECTED: verdict 'DROP', reason 'UNTRUSTED_SOURCE'

# 5. Upstream path: cyber_verdict is None, only physical checked -> expect PASS
physical_ok5 = make_verdict("tx5", True, "OK", "physical")
print("5. Upstream, physical passes:", orchestrator.decide(None, physical_ok5, time.time()))
# EXPECTED: verdict 'PASS', direction 'upstream'

# 6. Upstream path, physical fails -> expect DROP
physical_bad6 = make_verdict("tx6", False, "TELEMETRY_MISMATCH", "physical")
print("6. Upstream, physical fails:", orchestrator.decide(None, physical_bad6, time.time()))
# EXPECTED: verdict 'DROP', reason 'TELEMETRY_MISMATCH', direction 'upstream'

# 7. Check the log has all 6 entries
print("7. Log length:", len(orchestrator.get_log()))
# EXPECTED: 6