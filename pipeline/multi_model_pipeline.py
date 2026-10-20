"""
pipeline/multi_model_pipeline.py - MultiModelPipeline: one entry point for every
SCADA -> PLC command and every PLC telemetry sample.

Per command, two branches run concurrently on a small thread pool:

    cyber branch     Cyber Agent rules (HMAC, whitelist, rate, replay)   -> hard gate
                     + CyberModel anomaly score                         -> advisory*
    physical branch  Physical Agent rules (bounds, rate, cross-register) -> hard gate
                     + PhysicalModel (SWaT window anomaly + attack prob.) -> advisory

The Orchestrator then fuses them with a rule-based four-branch table (DROP on a rule failure,
ALERT when only the advisory physical model flags, else PASS), and the pipeline returns one unified diagnostic report.

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
from collections import OrderedDict
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any, Callable, Dict, Mapping, Optional, Tuple, Union

from docs.interfaces import make_verdict
from middleware import cyber_agent, incidents, investigator, orchestrator, physical_agent, quarantine, trace as tracer
from models.cyber_model import CyberModel
from models.physical_model import PhysicalModel
from models.physical_model_v2 import load_physical_model

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
        self.physical_model = physical_model if physical_model is not None else load_physical_model()
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
            phys_ml = {"model": "PhysicalModel", "status": "ERROR", "plant_state": "ERROR", "anomaly_score": None,
                       "attack_probability": None, "threat_flag": False, "flagged_by": [], "bounds_violations": []}
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
            decision = orchestrator.decide(gate_cyber, phys_rule, start_time, physical_advisory=phys_ml)
        except Exception:
            log.exception("orchestrator failed on tx=%s - failing closed", tx_id)
            decision = {"tx_id": tx_id, "verdict": "DROP", "reason": "AGENT_ERROR:orchestrator",
                        "latency_ms": round((time.time() - start_time) * 1000, 3), "direction": "downstream"}

        total_ms = (time.perf_counter() - t0) * 1000.0
        timings = {"branches": round((t_branches - t0) * 1000.0, 4), "cyber_model": cyber_ml.get("latency_ms"),
                   "physical_model": phys_ml.get("latency_ms"), "total": round(total_ms, 4)}
        mode = "ENFORCE" if self.enforce_cyber_model else "MONITOR"
        try:
            hop_trace = tracer.build_trace(command, current_state, cyber_rule, gate_cyber, cyber_ml, phys_rule, phys_ml,
                                           decision, timings, mode)
        except Exception:
            log.exception("trace build failed on tx=%s (decision unaffected)", tx_id)
            hop_trace = None

        self._remember(command, current_state, hop_trace)
        incident = self._respond(command, decision)

        return {
            "trace": hop_trace,
            "tx_id": tx_id,
            "source_ip": command.get("source_ip"),
            "register": command.get("register"),
            "requested_value": command.get("value"),
            "decision": decision,
            "incident": incident,
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
                "plant_state": phys_ml.get("plant_state", phys_ml.get("status", "UNKNOWN")),
            },
            "mode": "ENFORCE" if self.enforce_cyber_model else "MONITOR",
            "timings_ms": {
                "branches": round((t_branches - t0) * 1000.0, 4),
                "cyber_model": cyber_ml.get("latency_ms"),
                "physical_model": phys_ml.get("latency_ms"),
                "total": round(total_ms, 4),
            },
        }

    # ------------------------------------------------------------ response
    _incident_sent: Dict[str, Tuple[float, str, bool]] = {}
    _recent_traces: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
    _last_registers: Dict[Any, Any] = {}
    MAX_KEPT_TRACES = 60

    def _remember(self, command: Dict[str, Any], state: Dict[str, Any], hop_trace: Optional[Dict[str, Any]]) -> None:
        """Keep a small, bounded ring of recent traces and the last plant snapshot, so an investigation has something to read.
        In memory, read-only to everything else, and never consulted by a decision."""
        try:
            self._last_registers = dict(state.get("registers") or {})
            if hop_trace:
                self._recent_traces[str(command.get("tx_id"))] = hop_trace
                while len(self._recent_traces) > self.MAX_KEPT_TRACES:
                    self._recent_traces.popitem(last=False)
        except Exception:
            pass

    def _investigation_context(self) -> Dict[str, Any]:
        """Evidence an investigation may read. Gathered in the worker thread, after the decision has already been returned."""
        model = self.physical_model.assess()
        suspect = [s for s in ([model.get("suspect_stage")] + [d.get("stage") for d in (model.get("top_deviations") or [])]) if s]
        return {"traces": dict(self._recent_traces),
                "plant_state": {"registers": dict(self._last_registers), "physical_model": model,
                                "suspect_stages": sorted(set(suspect))}}

    def _respond(self, command: Dict[str, Any], decision: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Strikes for the quarantine, incident correlation, dashboard notification. Never raises, never changes the decision."""
        try:
            verdict = decision.get("verdict")
            if verdict not in ("DROP", "ALERT"):
                return None
            started = None
            if verdict == "DROP":
                started = quarantine.record(str(command.get("source_ip")), decision.get("reason", ""), command.get("timestamp"))
                if started:
                    log.warning("QUARANTINE source=%s for %.0fs (offence %s, trigger %s)", started["source"], started["hold_s"],
                                started["offence"], started["trigger"])
            inc = incidents.record(command, decision, started)
            if inc is not None:
                # OPT-IN (IM_INVESTIGATOR=1), strictly off the decision path: a worker thread investigates the incident and
                # publishes an analysis. The decision below has already been made and cannot be changed by it.
                investigator.investigate_async(inc, self._investigation_context, orchestrator.forward_investigation_to_dashboard)
                last = self._incident_sent.get(inc["id"])
                now = time.time()
                if last is None or now - last[0] >= 0.5 or last[1] != inc["severity"] or last[2] != inc["quarantined"]:
                    self._incident_sent[inc["id"]] = (now, inc["severity"], inc["quarantined"])
                    orchestrator.forward_incident_to_dashboard(inc)
                return {"id": inc["id"], "severity": inc["severity"], "quarantined": inc["quarantined"], "summary": inc["summary"]}
        except Exception:
            log.exception("incident/quarantine bookkeeping failed on tx=%s (decision unaffected)", command.get("tx_id"))
        return None

    # ----------------------------------------------------------- telemetry
    def ingest_telemetry(self, registers: Mapping[Union[int, str], float],
                         timestamp: Optional[float] = None) -> None:
        """Feed one PLC telemetry sample into the PhysicalModel window (decimated to 1 Hz). Never raises."""
        try:
            with self._telemetry_lock:
                self.physical_model.update(registers, timestamp)
        except Exception:
            log.exception("PhysicalModel.update failed - sample skipped")

    def health_report(self) -> Report:
        """Current PhysicalModel assessment (plant_state, scores, bounds violations)."""
        return self.physical_model.assess()

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False)


_default: Optional[MultiModelPipeline] = None
_default_lock = threading.Lock()


def get_pipeline() -> MultiModelPipeline:
    """Process-wide pipeline (lazy, thread-safe)."""
    global _default
    with _default_lock:
        if _default is None:
            _default = MultiModelPipeline()
        return _default
