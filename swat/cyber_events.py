"""
swat/cyber_events.py - turn SWaT actuator columns into "commands" and compute the cyber-model
features from them. THIS MODULE IS THE SINGLE FEATURE IMPLEMENTATION: training (SWaT events) and
the live middleware (models/cyber_model.py) both call EventFeatureStream.push(), so the schema
cannot drift between the two.

Definition agreed at the Phase 4 gate:
  * a "command" = a STABLE-STATE CHANGE of one of the twin's SWaT-backed actuators
    (SWaT pumps/UV: 1 = off, 2 = on; motorised valves: 0 = transit, 1 = closed, 2 = open);
  * states map to the twin's continuous actuators as 1 -> 0 %, 2 -> 100 % (derived, not measured);
  * a valve's transitional state 0 is a transition, not a state (forward-filled);
  * state is never carried across a data gap (chunk boundary).
Live commands are quantised the same way (>= ON_THRESHOLD percent = on). A live command that does
not flip the quantised state has no SWaT counterpart: the model ABSTAINS on it (rules still gate).

Timing resolution: SWaT is sampled at 1 Hz, so training timestamps are whole seconds; live
timestamps have millisecond resolution.
"""

from __future__ import annotations

import math
from collections import defaultdict, deque
from typing import Deque, Dict, List, Optional

import numpy as np
import pandas as pd

from core.interfaces import MACHINES, MACHINE_BY_REGISTER

ON_THRESHOLD = 50.0     # percent; >= this counts as "on/open" for live commands

# SWaT tag -> twin register for the actuators that exist in SWaT (MV503 is twin-only synthetic)
ACTUATOR_COLUMNS: Dict[str, int] = {m["name"]: m["register"] for m in MACHINES
                                    if m["kind"] == "actuator" and m["swat_backed"]}

FEATURE_NAMES: List[str] = [
    "turns_on",          # 1 = off->on / closed->open, 0 = on->off
    "stage",             # SWaT process stage of the actuator (1..5)
    "is_valve",          # 1 = motorised valve, 0 = pump / UV lamp
    "log_dt_same_ms",    # log1p(ms since the previous change of the SAME actuator; 60 s if none)
    "log_dt_any_ms",     # log1p(ms since the previous change of ANY actuator)
    "events_1s",         # changes of any actuator in the last 1 s
    "events_10s",        # changes of any actuator in the last 10 s
    "same_reg_60s",      # changes of the same actuator in the last 60 s
]

# (feature, SWaT source, status) - rendered into the training report
PROVENANCE = [
    ("turns_on", "actuator state column: 1->2 (on/open) vs 2->1 (off/closed)", "derived"),
    ("stage", "tag digit of the actuator column (P1..P5)", "derived"),
    ("is_valve", "tag prefix MV", "derived"),
    ("log_dt_same_ms", "Timestamp deltas between changes of the same actuator column (1 s resolution)", "derived"),
    ("log_dt_any_ms", "Timestamp deltas between changes of any twin actuator column", "derived"),
    ("events_1s", "count of actuator changes in the preceding 1 s", "derived"),
    ("events_10s", "count of actuator changes in the preceding 10 s", "derived"),
    ("same_reg_60s", "count of changes of the same actuator in the preceding 60 s", "derived"),
]
DROPPED = [
    ("fc_write_single / fc_write_multiple / fc_other", "no Modbus function codes in SWaT (no network data)", "dropped"),
    ("register_known", "constant 1 by construction (only known actuators are events)", "dropped (no variance)"),
    ("value_norm", "replaced by turns_on: SWaT actuators are binary", "dropped (redundant)"),
    ("out_of_range", "constant 0: SWaT states are always in range", "dropped (no variance)"),
    ("delta_norm", "constant 1 after quantising to on/off", "dropped (no variance)"),
    ("signature_present / signature_age", "SWaT has no HMAC signatures - rule-based check only, NOT validated on SWaT", "dropped"),
    ("requests_last_1s / 10s (per source)", "SWaT has no source addresses; replaced by global event counts", "replaced"),
    ("same_payload_recent", "a repeated write with no state change is not an event in SWaT", "dropped (no variance)"),
]


def state_class(value: float) -> int:
    return 1 if float(value) >= ON_THRESHOLD else 0


class EventFeatureStream:
    """Streaming feature computation over a time-ordered sequence of actuator state-change events."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self._any: Deque[float] = deque()
        self._same: Dict[int, Deque[float]] = defaultdict(deque)
        self._last_same: Dict[int, float] = {}
        self._last_any: Optional[float] = None

    def push(self, t: float, register: int, turns_on: int, update: bool = True) -> np.ndarray:
        any_q = self._any
        while any_q and t - any_q[0] > 10.0:
            any_q.popleft()
        same_q = self._same[register]
        while same_q and t - same_q[0] > 60.0:
            same_q.popleft()
        last_same = self._last_same.get(register)
        dt_same_ms = (t - last_same) * 1000.0 if last_same is not None else 60_000.0
        dt_any_ms = (t - self._last_any) * 1000.0 if self._last_any is not None else 60_000.0
        m = MACHINE_BY_REGISTER[register]
        vec = np.array([
            float(turns_on),
            float(m["stage"]),
            1.0 if m["name"].startswith("MV") else 0.0,
            math.log1p(max(0.0, min(dt_same_ms, 600_000.0))),
            math.log1p(max(0.0, min(dt_any_ms, 600_000.0))),
            float(sum(1 for x in any_q if t - x <= 1.0)),
            float(len(any_q)),
            float(len(same_q)),
        ], dtype=np.float64)
        if update:
            any_q.append(t)
            same_q.append(t)
            self._last_same[register] = t
            self._last_any = t
        return vec


def extract_events(stream: pd.DataFrame) -> pd.DataFrame:
    """Actuator state-change events from the loader's chronological stream."""
    chunk = stream["chunk"].to_numpy()
    same_chunk = np.concatenate(([False], chunk[1:] == chunk[:-1]))
    out: List[pd.DataFrame] = []
    for tag, reg in ACTUATOR_COLUMNS.items():
        if tag not in stream.columns:
            continue
        v = stream[tag].to_numpy(dtype=np.float64)
        is_valve = tag.startswith("MV")
        mapped = np.where(v == 2, 1.0, np.where(v == 1, 0.0, np.nan))      # 1->off(0), 2->on(1); 0/NaN -> NaN
        if is_valve:
            trans = v == 0                                                    # transit: not a state, carry the last one
            s = pd.Series(mapped)
            ff = s.groupby(chunk).ffill().to_numpy()
            mapped = np.where(trans, ff, mapped)
        prev = np.concatenate(([np.nan], mapped[:-1]))
        ev = same_chunk & ~np.isnan(mapped) & ~np.isnan(prev) & (mapped != prev)
        idx = np.flatnonzero(ev)
        if idx.size:
            out.append(pd.DataFrame({
                "epoch": stream["epoch"].to_numpy()[idx], "register": reg, "tag": tag,
                "turns_on": mapped[idx].astype(int), "label": stream["label"].to_numpy()[idx],
                "seg": stream["seg"].to_numpy()[idx], "block": stream["block"].to_numpy()[idx],
                "chunk": chunk[idx], "row": idx}))
    if not out:
        return pd.DataFrame(columns=["epoch", "register", "tag", "turns_on", "label", "seg", "block", "chunk", "row"])
    ev = pd.concat(out, ignore_index=True)
    return ev.sort_values(["epoch", "register"], kind="mergesort").reset_index(drop=True)


def event_features(events: pd.DataFrame) -> np.ndarray:
    """[n_events, len(FEATURE_NAMES)] using the SAME stream class as the live path."""
    fs = EventFeatureStream()
    X = np.empty((len(events), len(FEATURE_NAMES)), dtype=np.float64)
    last_chunk = None
    for i, (t, reg, on, ch) in enumerate(zip(events["epoch"].to_numpy(), events["register"].to_numpy(),
                                             events["turns_on"].to_numpy(), events["chunk"].to_numpy())):
        if last_chunk is not None and ch != last_chunk:
            fs.reset()                      # never carry history across a data gap
        last_chunk = ch
        X[i] = fs.push(float(t), int(reg), int(on))
    return X
