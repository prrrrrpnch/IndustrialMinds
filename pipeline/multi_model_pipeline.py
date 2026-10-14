"""
pipeline/multi_model_pipeline.py - MultiModelPipeline: one entry point for every
SCADA -> PLC command and every PLC telemetry sample.

Per command, two branches run concurrently on a small thread pool:

    cyber branch     Cyber Agent rules (HMAC, whitelist, rate, replay)   -> hard gate
                     + CyberModel anomaly score                         -> advisory*
    physical branch  Physical Agent rules (bounds, rate, cross-register) -> hard gate
                     + PhysicalModel machine health / RUL               -> advisory

The Orchestrator then fuses the two rule verdicts into PASS/DROP exactly as
before, and the pipeline returns one unified diagnostic report.

* Set IM_CYBER_MODEL_ENFORCE=1 to let a CyberModel threat flag DROP a command
  that the rules passed (reason ML_ANOMALY). Default is monitor-only, so the
  learned model can never block legitimate traffic on its own.

Failure policy
    Rule branch raises  -> fail CLOSED: verdict fails with AGENT_ERROR (DROP).
    Model raises        -> model abstains (status ERROR); rules still decide.
    Every failure is logged with its traceback.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any, Callable, Dict, Mapping, Optional, Tuple, Union

from docs.interfaces import make_verdict
from middleware import cyber_agent, orchestrator, physical_agent
from models.cyber_model import CyberModel
from models.physical_model import PhysicalModel

log = logging.getLogger("industrialmind.pipeline")

Report = Dict[str, Any]


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


class MultiModelPipeline:
    def __init__(self, cyber_model: Optional[CyberModel] = None,
                 physical_model: Optional[PhysicalModel] = None,
                 enforce_cyber_model: Optional[bool] = None,
                 max_workers: int = 2) -> None:
        self.cyber_model = cyber_model if cyber_model is not None else CyberModel.load()
        self.physical_model = physical_model if physical_model is not None else PhysicalModel.load()
        self.enforce_cyber_model = (_env_flag("IM_CYBER_MODEL_ENFORCE")
                                    if enforce_cyber_model is None else enforce_cyber_model)
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="im-pipeline")
        self._telemetry_lock = threading.Lock()
        log.info(
            "MultiModelPipeline ready: CyberModel=%s PhysicalModel=%s mode=%s",
            self.cyber_model.status, self.physical_model.status,
            "ENFORCE" if self.enforce_cyber_model else "MONITOR",
        )

    # ------------------------------------------------------------ branches
    @staticmethod
    def _guard_rule(fn: Callable[[], Dict[str, Any]], tx_id: str, agent: str) -> Dict[str, Any]:
        try:
            return fn()
        except Exception as exc:
            log.exception("%s agent failed on tx=%s - failing closed", agent, tx_id)
            return make_verdict(tx_id, False, f"AGENT_ERROR:{agent}:{type(exc).__name__}", agent)

    def _cyber_branch(self, command: Dict[str, Any], state: Dict[str, Any]) -> Tuple[Dict, Dict]:
        tx = command.get("tx_id", "")
        rule = self._guard_rule(lambda: cyber_agent.check(command), tx, "cyber")
        model = self.cyber_model.evaluate_payload(command, state)   # never raises
        return rule, model

    def _physical_branch(self, command: Dict[str, Any], state: Dict[str, Any]) -> Tuple[Dict, Dict]:
        tx = command.get("tx_id", "")
        rule = self._guard_rule(lambda: physical_agent.check_command(command, state), tx, "physical")
        model = self.physical_model.assess()                       # never raises
        return rule, model

    # ------------------------------------------------------------- command
    def process_command(self, command: Dict[str, Any], current_state: Dict[str, Any],
                        start_time: Optional[float] = None,
                        command_label: Optional[str] = None) -> Report:
        """Run both branches concurrently and fuse them. Returns the diagnostic report."""
        start_time = start_time or time.time()
        t0 = time.perf_counter()
        tx_id = command.get("tx_id", "")

        try:
            f_cyber: Future = self._executor.submit(self._cyber_branch, command, current_state)
            f_phys: Future = self._executor.submit(self._physical_branch, command, current_state)
            cyber_rule, cyber_ml = f_cyber.result()
            phys_rule, phys_ml = f_phys.result()
        except Exception:
            log.exception("pipeline branch dispatch failed on tx=%s - failing closed", tx_id)
            cyber_rule = make_verdict(tx_id, False, "AGENT_ERROR:pipeline", "cyber")
            phys_rule = make_verdict(tx_id, False, "AGENT_ERROR:pipeline", "physical")
            cyber_ml = {"model": "CyberModel", "status": "ERROR", "threat_flag": False, "anomaly_score": None}
            phys_ml = {"model": "PhysicalModel", "status": "ERROR", "machines": {}, "min_health_index": None}
        t_branches = time.perf_counter()

        gate_cyber = cyber_rule
        if self.enforce_cyber_model and cyber_rule.get("pass") and cyber_ml.get("threat_flag"):
            gate_cyber = dict(cyber_rule, **{
                "pass": False,
                "reason": (f"ML_ANOMALY:{'+'.join(cyber_ml.get('flagged_by') or ['model'])} "
                           f"score={cyber_ml.get('anomaly_score')} p={cyber_ml.get('attack_probability')}"),
            })

        if command_label is not None:
            phys_rule["command"] = command_label

        try:
            decision = orchestrator.decide(gate_cyber, phys_rule, start_time)
        except Exception:
            log.exception("orchestrator failed on tx=%s - failing closed", tx_id)
            decision = {"tx_id": tx_id, "verdict": "DROP", "reason": "AGENT_ERROR:orchestrator",
                        "latency_ms": round((time.time() - start_time) * 1000, 3), "direction": "downstream"}

        total_ms = (time.perf_counter() - t0) * 1000.0
        return {
            "tx_id": tx_id,
            "source_ip": command.get("source_ip"),
            "register": command.get("register"),
            "requested_value": command.get("value"),
            "decision": decision,
            "cyber": {
                "rule_verdict": cyber_rule,
                "gate_verdict": gate_cyber,
                "model": cyber_ml,
                "threat_flags": {
                    "rules": not cyber_rule.get("pass", False),
                    "ml_anomaly": bool(cyber_ml.get("threat_flag")),
                },
            },
            "physical": {
                "rule_verdict": phys_rule,
                "model": phys_ml,
                "health_state": _health_state(phys_ml.get("min_health_index")),
            },
            "mode": "ENFORCE" if self.enforce_cyber_model else "MONITOR",
            "timings_ms": {
                "branches": round((t_branches - t0) * 1000.0, 4),
                "cyber_model": cyber_ml.get("latency_ms"),
                "physical_model": phys_ml.get("latency_ms"),
                "total": round(total_ms, 4),
            },
        }

    # ----------------------------------------------------------- telemetry
    def ingest_telemetry(self, registers: Mapping[Union[int, str], float]) -> None:
        """Feed one PLC telemetry sample into the PhysicalModel window. Never raises."""
        try:
            with self._telemetry_lock:
                self.physical_model.update(registers)
        except Exception:
            log.exception("PhysicalModel.update failed - sample skipped")

    def health_report(self) -> Report:
        return self.physical_model.assess()

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False)


def _health_state(min_hi: Optional[float]) -> str:
    if min_hi is None:
        return "UNKNOWN"
    if min_hi >= 0.6:
        return "HEALTHY"
    if min_hi >= 0.3:
        return "DEGRADING"
    return "CRITICAL"


_default: Optional[MultiModelPipeline] = None
_default_lock = threading.Lock()


def get_pipeline() -> MultiModelPipeline:
    """Process-wide pipeline (lazy, thread-safe)."""
    global _default
    with _default_lock:
        if _default is None:
            _default = MultiModelPipeline()
        return _default
