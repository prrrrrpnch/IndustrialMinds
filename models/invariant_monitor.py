"""
models/invariant_monitor.py - the LIVE side of the physical-invariant rules (swat/invariants.py).

It keeps the last `lookback` seconds of the same 18 signals the physical model reads (1 Hz, decimated from the 5 Hz poll, restarted after a
telemetry gap exactly as the model's window is) and, once per telemetry sample, scores them with the SAME `InvariantSet.score` that the SWaT
evaluation uses - so what is measured offline is what runs live. The result is cached: a command arriving between samples costs a dict copy.

ADVISORY, never a gate. A violation means "these readings cannot all be true at once" and is reported like the physical model's flag
(ALERT, the command is still forwarded). It is OFF unless IM_INVARIANTS=1 and the invariant file loads: invariants are FITTED to a plant,
so the file must come from the plant being protected (`python -m tools.fit_invariants`). SWaT-fitted invariants do not describe the twin
(its tank dynamics are compressed in time), so the demo uses its own twin-fitted file; see docs/INVARIANTS.md.

Fail-safe: no file, a bad file, too little history, or any exception -> status NO_MODEL / WARMING_UP / ERROR and no flag; the rules keep enforcing.
"""

from __future__ import annotations

import logging
import os
import threading
from collections import deque
from typing import Any, Deque, Dict, List, Mapping, Optional, Tuple, Union

import numpy as np

from core.interfaces import MACHINE_BY_NAME
from models.physical_model import MAX_GAP_S, SAMPLE_PERIOD_S
from swat.invariants import InvariantSet
from swat.physical_features import ACTUATORS, ON_THRESHOLD, SENSORS

log = logging.getLogger("industrialmind.models.invariants")

Registers = Mapping[Union[int, str], float]
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEFAULT_FILE = os.path.join(ROOT, "config", "invariants_twin.json")
MAX_NAMED = 3                                   # invariants named in a flag reason (the report lists all)


def _value(registers: Registers, tag: str) -> Optional[float]:
    m = MACHINE_BY_NAME[tag]
    v = registers.get(m["register"], registers.get(tag))
    return None if v is None else float(v)


class InvariantMonitor:
    def __init__(self, invariants: Optional[InvariantSet] = None, theta: float = 1.0, source: str = "") -> None:
        self.inv = invariants if invariants is not None and len(invariants) else None
        self.theta = float(theta)
        self.source = source
        self.status = "NO_MODEL" if self.inv is None else "WARMING_UP"
        self.lookback = self.inv.lookback if self.inv is not None else 0
        self._buf: Deque[Tuple[np.ndarray, np.ndarray]] = deque(maxlen=max(self.lookback, 1))
        self._last_t: Optional[float] = None
        self._lock = threading.Lock()
        self._report: Dict[str, Any] = self._empty()

    # ---------------------------------------------------------------------------------------- report
    def _empty(self) -> Dict[str, Any]:
        return {"model": "InvariantMonitor", "status": self.status, "threat_flag": False, "flagged_by": [], "violated": [], "score": None,
                "theta": self.theta, "suspect_stage": None, "explanation": None, "source": self.source,
                "invariants": 0 if self.inv is None else len(self.inv), "warmup_remaining_s": max(0, self.lookback - len(self._buf))}

    def reset_window(self) -> None:
        with self._lock:
            self._buf.clear()
            self._last_t = None
            self.status = "NO_MODEL" if self.inv is None else "WARMING_UP"
            self._report = self._empty()

    # ---------------------------------------------------------------------------------------- telemetry
    def update(self, registers: Registers, timestamp: Optional[float] = None) -> None:
        """Push one telemetry sample (decimated to 1 Hz) and rescore. Never raises."""
        if self.inv is None:
            return
        try:
            import time as _t
            t = float(timestamp) if timestamp is not None else _t.time()
            s = [_value(registers, tag) for tag in SENSORS]
            a = [_value(registers, tag) for tag in ACTUATORS]
            if any(v is None for v in s + a):
                return
            with self._lock:
                if self._last_t is not None:
                    if t - self._last_t < SAMPLE_PERIOD_S - 1e-6:
                        return
                    if t - self._last_t > MAX_GAP_S:
                        self._buf.clear()
                self._buf.append((np.array(s, dtype=np.float64), (np.array(a) >= ON_THRESHOLD).astype(np.float64)))
                self._last_t = t
                if len(self._buf) < self.lookback:
                    self.status = "WARMING_UP"
                    self._report = self._empty()
                    return
                S = np.stack([b[0] for b in self._buf])
                A = np.stack([b[1] for b in self._buf])
            violated = self.inv.violated_at_end(S, A, np.zeros(len(S), dtype=int), self.theta)
            V = violated[0]["excess"] if violated else 0.0
            rep = self._empty()
            rep.update(status="OK", score=round(float(V), 3), violated=violated, threat_flag=bool(violated),
                       flagged_by=[f"invariant:{v['id']}" for v in violated[:MAX_NAMED]],
                       suspect_stage=violated[0]["stage"] if violated else None,
                       explanation=("physical invariant violated: " + violated[0]["text"]) if violated else None, warmup_remaining_s=0)
            with self._lock:
                self.status, self._report = "OK", rep
        except Exception:
            log.exception("InvariantMonitor.update failed - abstaining (rules still enforce)")
            with self._lock:
                self.status = "ERROR"
                self._report = {**self._empty(), "status": "ERROR"}

    def assess(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._report)

    # ---------------------------------------------------------------------------------------- merging into the physical advisory
    def merge_into(self, phys_ml: Dict[str, Any]) -> Dict[str, Any]:
        """Add this monitor's verdict to the physical model's advisory dict (flag, flagged_by, suspect_stage); returns the merged dict. Never raises."""
        try:
            rep = self.assess()
            out = dict(phys_ml)
            out["invariants"] = rep
            if rep["threat_flag"]:
                out["threat_flag"] = True
                out["flagged_by"] = list(out.get("flagged_by") or []) + rep["flagged_by"]
                out["suspect_stage"] = out.get("suspect_stage") or rep["suspect_stage"]
                out["explanation"] = out.get("explanation") or rep["explanation"]
                if out.get("plant_state") in (None, "NORMAL"):
                    out["plant_state"] = "ALERT"
            return out
        except Exception:
            log.exception("merging the invariant report failed - physical advisory used unchanged")
            return phys_ml


def enabled() -> bool:
    return os.environ.get("IM_INVARIANTS", "0").strip().lower() in ("1", "true", "yes", "on")


def load_monitor() -> Optional[InvariantMonitor]:
    """The monitor if IM_INVARIANTS=1 and IM_INVARIANTS_FILE (default config/invariants_twin.json) loads; None otherwise (the default)."""
    if not enabled():
        return None
    path = os.environ.get("IM_INVARIANTS_FILE", "").strip() or DEFAULT_FILE
    try:
        inv = InvariantSet.load(path)
    except FileNotFoundError:
        log.warning("IM_INVARIANTS=1 but %s does not exist - invariants disabled (fit one with `python -m tools.fit_invariants`)", path)
        return None
    except Exception as exc:
        log.warning("IM_INVARIANTS=1 but %s is unusable (%s) - invariants disabled", path, exc)
        return None
    theta = inv.theta                                   # calibrated when the set was fitted; IM_INVARIANT_THETA overrides
    try:
        theta = float(os.environ.get("IM_INVARIANT_THETA", theta))
    except ValueError:
        pass
    log.info("physical invariants ON: %d invariants from %s (fitted on: %s), theta=%.2f", len(inv), path, inv.meta.get("label"), theta)
    return InvariantMonitor(inv, theta, source=f"{os.path.basename(path)} ({inv.meta.get('label')})")
