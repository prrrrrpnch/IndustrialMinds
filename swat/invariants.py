"""
swat/invariants.py - PHYSICAL INVARIANT rules: deterministic consistency checks between the plant's own signals.

An invariant is a relationship that holds in normal operation because of physics or of the control logic, learned from NORMAL data only
(no attack labels, no classifier). A violation means "these readings cannot all be true at once": a spoofed or frozen sensor, a pump that
does not do what its state says, a tank that gains water nobody pumped. Four families, all over the 18 signals the live twin provides:

  rate      a sensor cannot move faster than it ever did in normal operation (10 s and 60 s horizons)            |x(t) - x(t-h)| <= cap
  state     while an actuator has held one state for >= DWELL s, a sensor stays inside the band it always had   x in [lo, hi] | actuator = s
            in that state (a pump that is on => its flow is up; control-logic and process couplings)
  balance   a tank's level change over 60 s is explained by the flows and pump states around it (mass balance)  |dL - f(drivers)| <= tol
  flat      a sensor that always carries measurement noise cannot go perfectly flat: its range over the last         range(20 s) >= floor
            20 s never fell below a floor in normal operation (a flat reading is a stuck, frozen or replayed sensor)

Every invariant yields an EXCESS e(t) with e <= 1 inside the range seen in normal data and e > 1 outside (the same scale for all
families), made PERSISTENT by taking the minimum over the last `persist` seconds so one noisy second is not a violation. The detector's
score is V(t) = max over invariants; the rule fires when V(t) > theta (theta = 1: beyond everything normal training ever showed).

HOW THEY ARE KEPT HONEST
  * proposals are fitted on the first 75 % of the normal rows and VALIDATED on the last 25 % (held out in time): an invariant that
    already misfires on unseen normal days is dropped, with the reason recorded; survivors are then refitted on all normal rows;
  * a state band is kept only if it is materially TIGHTER than the sensor's marginal range (otherwise it is just the envelope);
  * a balance is kept only if it explains the level change and is tighter than the plain rate cap;
  * tolerances are the WORST per-block quantile (blocks = contiguous slices of the normal data), so one quiet day cannot set them.

ONE implementation: training/evaluation (SWaT stream) and the live monitor (models/invariant_monitor.py) call the same `InvariantSet.score`
on the same arrays, so the rule cannot drift between them. Pure NumPy; no scikit-learn.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Iterator, List, Optional, Tuple

import numpy as np

from core.interfaces import MACHINE_BY_NAME
from swat.physical_features import ACTUATORS, SENSORS

SCHEMA = "im-invariants-1"
RATE_HORIZONS = (10, 60)
BAL_H = 60                       # seconds over which a level change is balanced
DWELL = 30                       # an actuator state counts only after it has been steady this long (flows lag the pump)
FLAT_W = 20                      # seconds over which "perfectly flat" is judged
FLAT_LO_Q = 0.0005               # lower quantile of the rolling range that sets the floor
FLAT_FLOOR_FRACTION = 0.5        # the floor is half of the worst block's lower quantile: flat means well below anything normal
PERSIST = {"rate": 2, "state": 10, "balance": 20, "flat": 5}
QUANTILE = 0.9999
STATE_LO_Q, STATE_HI_Q = 0.0005, 0.9995
MIN_STATE_SAMPLES = 2000
MIN_BLOCK_SAMPLES = 200
MIN_HOLDOUT_VALID = 200
MAX_STATE_TIGHTNESS = 0.5        # band width / marginal width: above this the band says little more than the envelope
MIN_BALANCE_R2 = 0.25
MAX_BALANCE_VS_RATE = 0.8        # balance tolerance / 60 s rate cap: above this the balance is no tighter than the rate rule
MIN_HALF_FRACTION = 0.02         # a band is never narrower than 2 % of the sensor's marginal range (quantisation noise)

# Which signals a tank's level change is balanced against (inflow, outflow and the pumps/valves that set them, from the plant's piping).
# The fit decides how much each matters; the validation decides whether the relation holds at all.
LEVEL_DRIVERS: Dict[str, List[str]] = {
    "LIT101": ["mean:FIT101", "mean:FIT201", "frac:P101", "frac:MV302"],
    "LIT301": ["mean:FIT201", "mean:DPIT301", "frac:MV302", "frac:P302"],
    "LIT401": ["mean:DPIT301", "mean:FIT501", "mean:PIT501", "frac:P402"],
}
_SI = {n: i for i, n in enumerate(SENSORS)}
_AI = {n: i for i, n in enumerate(ACTUATORS)}


# ----------------------------------------------------------------------------------------------- causal array helpers
def since_start(chunk: np.ndarray) -> np.ndarray:
    """Samples since the start of the row's chunk (0 on the first row of a chunk). Chunks are runs with no time gap."""
    n = len(chunk)
    new = np.ones(n, bool)
    if n > 1:
        new[1:] = chunk[1:] != chunk[:-1]
    idx = np.arange(n)
    return idx - np.maximum.accumulate(np.where(new, idx, 0))


def lag(x: np.ndarray, h: int, since: np.ndarray) -> np.ndarray:
    """x[t-h]; NaN where t-h falls before the chunk's start."""
    out = np.full(x.shape, np.nan)
    if 0 < h < len(x):
        out[h:] = x[:-h]
    elif h == 0:
        out = x.astype(float).copy()
    out[since < h] = np.nan
    return out


def trailing_mean(x: np.ndarray, w: int, since: np.ndarray) -> np.ndarray:
    """Mean of the last w samples (current included); NaN until w valid samples exist inside the chunk."""
    valid = ~np.isnan(x)
    pad = (1,) + x.shape[1:]
    c = np.concatenate([np.zeros(pad), np.cumsum(np.where(valid, x, 0.0), axis=0)])
    k = np.concatenate([np.zeros(pad), np.cumsum(valid, axis=0)])
    n = len(x)
    out = np.full(x.shape, np.nan)
    if n >= w:
        hi = np.arange(w - 1, n)
        full = (k[hi + 1] - k[hi + 1 - w]) == w
        m = (c[hi + 1] - c[hi + 1 - w]) / w
        m[~full] = np.nan
        out[hi] = m
    out[since < w - 1] = np.nan
    return out


def state_age(a: np.ndarray, since: np.ndarray) -> np.ndarray:
    """Seconds the actuator has held its current state (0 right after a change, a NaN reading or a chunk start)."""
    n = len(a)
    change = np.ones(n, bool)
    if n > 1:
        change[1:] = (a[1:] != a[:-1]) | np.isnan(a[1:]) | np.isnan(a[:-1])
    change |= (since == 0) | np.isnan(a)
    idx = np.arange(n)
    return idx - np.maximum.accumulate(np.where(change, idx, 0))


def persist_min(e: np.ndarray, p: int, since: np.ndarray) -> np.ndarray:
    """Minimum of the excess over the last p seconds. Missing evidence counts as 0 (no violation)."""
    v = np.nan_to_num(e, nan=0.0)
    out = v.copy()
    for k in range(1, p):
        out = np.minimum(out, np.nan_to_num(lag(v, k, since), nan=0.0))
    return out


class _Ctx:
    """Per-call caches so invariants that share a lag, a trailing mean or an actuator age compute it once."""

    def __init__(self, S: np.ndarray, A: np.ndarray, chunk: np.ndarray) -> None:
        self.S, self.A = np.asarray(S, float), np.asarray(A, float)
        self.since = since_start(np.asarray(chunk))
        self._lag: Dict[Tuple[int, int], np.ndarray] = {}
        self._mean: Dict[Tuple[str, int], np.ndarray] = {}
        self._age: Dict[int, np.ndarray] = {}
        self._range: Dict[Tuple[int, int], np.ndarray] = {}

    def flat_range(self, i: int, w: int) -> np.ndarray:
        """max - min of the last w samples of sensor i (NaN until w valid samples exist inside the chunk)."""
        if (i, w) not in self._range:
            hi = lo = self.S[:, i]
            for k in range(1, w):
                prev = self.lag(i, k)
                hi, lo = np.maximum(hi, prev), np.minimum(lo, prev)       # NaN propagates: an incomplete window is unknown, never flat
            self._range[(i, w)] = hi - lo
        return self._range[(i, w)]

    def lag(self, i: int, h: int) -> np.ndarray:
        if (i, h) not in self._lag:
            self._lag[(i, h)] = lag(self.S[:, i], h, self.since)
        return self._lag[(i, h)]

    def driver(self, spec: str, w: int) -> np.ndarray:
        if (spec, w) not in self._mean:
            kind, name = spec.split(":")
            col = self.S[:, _SI[name]] if kind == "mean" else self.A[:, _AI[name]]
            self._mean[(spec, w)] = trailing_mean(col, w, self.since)
        return self._mean[(spec, w)]

    def age(self, j: int) -> np.ndarray:
        if j not in self._age:
            self._age[j] = state_age(self.A[:, j], self.since)
        return self._age[j]


# ----------------------------------------------------------------------------------------------- one invariant's excess
def raw_excess(inv: Dict[str, Any], ctx: _Ctx) -> np.ndarray:
    """e(t) for one invariant (NaN where it cannot be evaluated): <= 1 inside the normal range, > 1 outside."""
    fam = inv["family"]
    if fam == "rate":
        i = _SI[inv["sensor"]]
        return np.abs(ctx.S[:, i] - ctx.lag(i, inv["horizon"])) / inv["cap"]
    if fam == "state":
        j, i = _AI[inv["actuator"]], _SI[inv["sensor"]]
        sel = (ctx.age(j) >= inv["dwell"] - 1) & (ctx.A[:, j] == inv["state"])
        e = np.abs(ctx.S[:, i] - inv["mid"]) / inv["half"]
        return np.where(sel, e, np.nan)
    if fam == "balance":
        i = _SI[inv["level"]]
        H = inv["horizon"]
        pred = np.full(len(ctx.S), inv["intercept"], dtype=float)
        for spec, coef, mu, sd in zip(inv["drivers"], inv["coef"], inv["mu"], inv["sd"]):
            pred = pred + coef * (ctx.driver(spec, H) - mu) / sd
        return np.abs((ctx.S[:, i] - ctx.lag(i, H)) - pred) / inv["tol"]
    if fam == "flat":
        r = ctx.flat_range(_SI[inv["sensor"]], inv["window"])
        return inv["floor"] / np.maximum(r, inv["floor"] / 1000.0)         # 1 at the floor, rising as the sensor flattens
    raise ValueError(f"unknown invariant family {fam!r}")


def describe(inv: Dict[str, Any]) -> str:
    u = lambda name: MACHINE_BY_NAME[name]["unit"] if name in MACHINE_BY_NAME else ""
    f = lambda v: f"{v:.3g}"
    if inv["family"] == "rate":
        return f"{inv['sensor']} never changed by more than {f(inv['cap'])} {u(inv['sensor'])} in {inv['horizon']} s in normal operation"
    if inv["family"] == "state":
        word = "ON" if inv["state"] == 1 else "OFF"
        return (f"while {inv['actuator']} is steadily {word} (>= {inv['dwell']} s), {inv['sensor']} stays within "
                f"{f(inv['mid'] - inv['half'])} to {f(inv['mid'] + inv['half'])} {u(inv['sensor'])}")
    if inv["family"] == "flat":
        return (f"{inv['sensor']} always varied by at least {f(inv['floor'])} {u(inv['sensor'])} within any {inv['window']} s in normal operation; "
                f"a perfectly flat reading means a stuck, frozen or replayed sensor")
    names = ", ".join(s.split(":")[1] for s in inv["drivers"])
    return (f"the change of {inv['level']} over {inv['horizon']} s is explained by {names} "
            f"(within +-{f(inv['tol'])} {u(inv['level'])}; explains {100 * inv['fit']['r2']:.0f} % of the variance)")


def stage_of(inv: Dict[str, Any]) -> Optional[str]:
    tag = inv.get("sensor") or inv.get("level") or inv.get("actuator")
    m = MACHINE_BY_NAME.get(tag)
    return None if m is None else f"S{m['stage']}"


def lookback_of(inv: Dict[str, Any]) -> int:
    fam = inv["family"]
    need = inv["horizon"] + 1 if fam in ("rate", "balance") else inv["window"] if fam == "flat" else inv["dwell"]
    return need + PERSIST[fam]


# ----------------------------------------------------------------------------------------------- the set
class InvariantSet:
    def __init__(self, invariants: List[Dict[str, Any]], meta: Optional[Dict[str, Any]] = None) -> None:
        self.invariants = list(invariants)
        self.meta = dict(meta or {})
        for k in self.invariants:
            k.setdefault("text", describe(k))
            k.setdefault("stage", stage_of(k))

    def __len__(self) -> int:
        return len(self.invariants)

    @property
    def theta(self) -> float:
        """The violation threshold this set was calibrated for (1.0 = beyond everything normal training showed)."""
        return float(self.meta.get("theta", 1.0))

    @property
    def lookback(self) -> int:
        return max((lookback_of(k) for k in self.invariants), default=1) + 5

    def series(self, S: np.ndarray, A: np.ndarray, chunk: np.ndarray) -> Iterator[Tuple[int, np.ndarray, np.ndarray]]:
        """For each invariant: (index, v, valid) where v is the persistent excess (0 where unknown) and valid marks rows it could be evaluated on."""
        ctx = _Ctx(S, A, chunk)
        for n, inv in enumerate(self.invariants):
            e = raw_excess(inv, ctx)
            yield n, persist_min(e, PERSIST[inv["family"]], ctx.since), ~np.isnan(e)

    def score(self, S: np.ndarray, A: np.ndarray, chunk: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """(V, arg): V[t] = max over invariants of the persistent excess, arg[t] = which invariant (-1 when none is evaluable)."""
        n = len(S)
        V = np.zeros(n)
        arg = np.full(n, -1, dtype=np.int32)
        for k, v, _ in self.series(S, A, chunk):
            better = v > V
            V = np.where(better, v, V)
            arg = np.where(better, k, arg)
        return V, arg

    def assess_end(self, S: np.ndarray, A: np.ndarray, chunk: np.ndarray, theta: float = 1.0) -> Dict[str, Any]:
        """What the invariants say about the LAST row: the largest persistent excess over ALL of them (a continuous score that
        exists whether or not anything is violated, so it can be tracked for drift and scored with ROC-AUC), and the violations."""
        worst, violated = 0.0, []
        for k, v, _ in self.series(S, A, chunk):
            if not len(v):
                continue
            e = float(v[-1])
            worst = max(worst, e)
            if e > theta:
                inv = self.invariants[k]
                violated.append({"id": inv["id"], "excess": round(e, 3), "text": inv["text"], "stage": inv.get("stage"), "family": inv["family"]})
        return {"max_excess": round(worst, 3), "violated": sorted(violated, key=lambda r: -r["excess"])}

    def violated_at_end(self, S: np.ndarray, A: np.ndarray, chunk: np.ndarray, theta: float = 1.0) -> List[Dict[str, Any]]:
        """Invariants violated at the LAST row, worst first: [{id, excess, text, stage}]."""
        return self.assess_end(S, A, chunk, theta)["violated"]

    # ---------------------------------------------------------------------------- fitting
    @classmethod
    def fit(cls, S: np.ndarray, A: np.ndarray, chunk: np.ndarray, *, label: str = "unspecified", quantile: float = QUANTILE, n_blocks: int = 6,
            holdout_frac: float = 0.25, max_holdout_rate: float = 2e-4, max_state: int = 16) -> "InvariantSet":
        """Learn invariants from NORMAL rows (chronological, with chunk ids), validate on the last holdout_frac, refit the survivors on everything."""
        S, A, chunk = np.asarray(S, float), np.asarray(A, float), np.asarray(chunk)
        n = len(S)
        if n < 5000:
            raise ValueError(f"need at least 5,000 normal rows to fit invariants, got {n}")
        nf = int(n * (1.0 - holdout_frac))
        proposals = _propose(S[:nf], A[:nf], chunk[:nf], quantile, n_blocks)
        report: Dict[str, Any] = {"label": label, "rows": n, "rows_fit": nf, "rows_holdout": n - nf, "quantile": quantile, "blocks": n_blocks,
                                  "proposed": _count(proposals), "dropped": [], "holdout": {}}
        trial = cls(proposals)
        kept: List[Dict[str, Any]] = []
        for k, v, valid in trial.series(S[nf:], A[nf:], chunk[nf:]):
            inv = proposals[k]
            nv = int(valid.sum())
            rate = float((v[valid] > 1.0).mean()) if nv else None
            report["holdout"][inv["id"]] = {"valid_rows": nv, "violation_rate": None if rate is None else round(rate, 6)}
            if nv < MIN_HOLDOUT_VALID:
                report["dropped"].append({"id": inv["id"], "reason": f"exercised on only {nv} held-out rows - cannot be validated"})
            elif rate > max_holdout_rate:
                report["dropped"].append({"id": inv["id"], "reason": f"misfires on unseen normal rows: violation rate {rate:.2e} > {max_holdout_rate:.0e}"})
            else:
                kept.append(inv)
        states = sorted([k for k in kept if k["family"] == "state"], key=lambda k: k["fit"]["tightness"])
        for k in states[max_state:]:
            report["dropped"].append({"id": k["id"], "reason": f"only the {max_state} tightest state bands are kept"})
        kept = [k for k in kept if k["family"] != "state"] + states[:max_state]
        final = _propose(S, A, chunk, quantile, n_blocks, only={k["id"] for k in kept})        # refit survivors on all normal rows
        report["kept"] = _count(final)
        meta = {"schema": SCHEMA, "label": label, "signals": {"sensors": list(SENSORS), "actuators": list(ACTUATORS)}, "report": report}
        return cls(final, meta)

    # ---------------------------------------------------------------------------- persistence
    def to_json(self) -> Dict[str, Any]:
        return {"schema": SCHEMA, "label": self.meta.get("label"), "theta": self.theta, "signals": {"sensors": list(SENSORS), "actuators": list(ACTUATORS)},
                "report": self.meta.get("report", {}), "invariants": self.invariants}

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w") as fh:
            json.dump(self.to_json(), fh, indent=1, default=float)

    @classmethod
    def from_json(cls, blob: Dict[str, Any]) -> "InvariantSet":
        if blob.get("schema") != SCHEMA:
            raise ValueError(f"not an {SCHEMA} file")
        sig = blob.get("signals", {})
        if sig.get("sensors") != list(SENSORS) or sig.get("actuators") != list(ACTUATORS):
            raise ValueError("invariants were fitted on a different signal set than this build reads")
        return cls(blob["invariants"], {"schema": SCHEMA, "label": blob.get("label"), "theta": blob.get("theta", 1.0), "signals": sig,
                                        "report": blob.get("report", {})})

    @classmethod
    def load(cls, path: str) -> "InvariantSet":
        with open(path) as fh:
            return cls.from_json(json.load(fh))


def stream_signals(stream) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """(S [n,10], A [n,8] 0/1 with NaN where unknown, chunk [n]) from the SWaT loader's stream - the arrays every invariant call takes."""
    from swat.physical_features import actuator_class_series
    chunk = stream["chunk"].to_numpy()
    S = stream[SENSORS].to_numpy(dtype=np.float64)
    A = np.column_stack([actuator_class_series(stream[a].to_numpy(dtype=np.float64), a.startswith("MV"), chunk) for a in ACTUATORS])
    return S, A, chunk


def _count(invs: List[Dict[str, Any]]) -> Dict[str, int]:
    out = {"rate": 0, "state": 0, "balance": 0, "flat": 0}
    for k in invs:
        out[k["family"]] += 1
    return out


# ----------------------------------------------------------------------------------------------- proposing invariants from normal data
def _blocks(n: int, k: int) -> List[np.ndarray]:
    return [b for b in np.array_split(np.arange(n), k) if len(b)]


def _worst_block_quantile(values: np.ndarray, blocks: List[np.ndarray], q: float, minimum: int = MIN_BLOCK_SAMPLES) -> Optional[float]:
    qs = []
    for b in blocks:
        x = values[b]
        x = x[~np.isnan(x)]
        if x.size >= minimum:
            qs.append(float(np.quantile(x, q)))
    return max(qs) if qs else None


def _propose(S: np.ndarray, A: np.ndarray, chunk: np.ndarray, q: float, n_blocks: int, only: Optional[set] = None) -> List[Dict[str, Any]]:
    ctx = _Ctx(S, A, chunk)
    blocks = _blocks(len(S), n_blocks)
    out: List[Dict[str, Any]] = []
    want = lambda inv_id: only is None or inv_id in only

    # ---- rate: the fastest a sensor ever moved, worst block
    caps: Dict[Tuple[str, int], float] = {}
    for name, i in _SI.items():
        for h in RATE_HORIZONS:
            d = np.abs(S[:, i] - ctx.lag(i, h))
            cap = _worst_block_quantile(d, blocks, q)
            if cap is None or cap <= 0:
                continue
            caps[(name, h)] = cap
            inv_id = f"rate:{name}:{h}s"
            if want(inv_id):
                out.append({"id": inv_id, "family": "rate", "sensor": name, "horizon": h, "cap": cap})

    # ---- flat: a sensor that always carries noise never goes perfectly flat. The floor is half of the worst block's lower quantile of the 20 s range;
    # a sensor whose range was ever (near) zero in normal data - quantised coarser than its noise, or legitimately constant - gets no flat rule.
    for name, i in _SI.items():
        inv_id = f"flat:{name}:{FLAT_W}s"
        if not want(inv_id):
            continue
        r = ctx.flat_range(i, FLAT_W)
        lows = []
        for b in blocks:
            x = r[b]
            x = x[~np.isnan(x)]
            if x.size >= MIN_BLOCK_SAMPLES:
                lows.append(float(np.quantile(x, FLAT_LO_Q)))
        if len(lows) < 3 or min(lows) <= 1e-9:
            continue
        out.append({"id": inv_id, "family": "flat", "sensor": name, "window": FLAT_W, "floor": FLAT_FLOOR_FRACTION * min(lows)})

    # ---- state: the band of a sensor while an actuator holds a steady state
    marg: Dict[str, Tuple[float, float]] = {}
    for name, i in _SI.items():
        x = S[:, i][~np.isnan(S[:, i])]
        if x.size:
            lo_hi = np.quantile(x, [STATE_LO_Q, STATE_HI_Q])
            marg[name] = (float(lo_hi[0]), float(lo_hi[1]))
    for aname, j in _AI.items():
        steady = ctx.age(j) >= DWELL - 1
        for state in (0, 1):
            sel = steady & (A[:, j] == state)
            if int(sel.sum()) < MIN_STATE_SAMPLES:
                continue
            for sname, i in _SI.items():
                inv_id = f"state:{aname}={'on' if state else 'off'}:{sname}"
                if sname not in marg or not want(inv_id):
                    continue
                col = np.where(sel, S[:, i], np.nan)
                los, his = [], []
                for b in blocks:
                    x = col[b]
                    x = x[~np.isnan(x)]
                    if x.size >= MIN_BLOCK_SAMPLES:
                        los.append(float(np.quantile(x, STATE_LO_Q)))
                        his.append(float(np.quantile(x, STATE_HI_Q)))
                if len(los) < 3:                                    # the band must be seen in at least three separate blocks
                    continue
                lo, hi = min(los), max(his)
                mrange = marg[sname][1] - marg[sname][0]
                if mrange <= 0:
                    continue
                tight = (hi - lo) / mrange
                if tight > MAX_STATE_TIGHTNESS and only is None:
                    continue
                half = max((hi - lo) / 2.0, MIN_HALF_FRACTION * mrange, 1e-9)
                out.append({"id": inv_id, "family": "state", "actuator": aname, "state": state, "sensor": sname, "dwell": DWELL,
                            "mid": (lo + hi) / 2.0, "half": half, "fit": {"tightness": round(tight, 4), "samples": int(np.isfinite(col).sum()), "blocks": len(los)}})

    # ---- balance: a tank's level change over BAL_H seconds against its drivers
    for level, drivers in LEVEL_DRIVERS.items():
        inv_id = f"balance:{level}"
        if not want(inv_id):
            continue
        i = _SI[level]
        dL = S[:, i] - ctx.lag(i, BAL_H)
        X = np.column_stack([ctx.driver(s, BAL_H) for s in drivers])
        ok = ~np.isnan(dL) & ~np.isnan(X).any(axis=1)
        idx = np.flatnonzero(ok)[::10]                              # a window every 10 s: neighbours overlap by 50 s anyway
        if idx.size < 500:
            continue
        live = X[idx].std(axis=0) > 1e-9                            # a driver that never varied in normal data says nothing: leave it out
        if not live.any():
            continue
        drivers_used = [d for d, keep in zip(drivers, live) if keep]
        X = X[:, live]
        mu, sd = X[idx].mean(axis=0), X[idx].std(axis=0)
        Z = (X[idx] - mu) / sd
        y = dL[idx]
        b0 = float(y.mean())
        w = np.linalg.solve(Z.T @ Z + 1.0 * np.eye(Z.shape[1]), Z.T @ (y - b0))
        pred_all = b0 + ((X - mu) / sd) @ w
        resid = np.abs(dL - pred_all)
        tol = _worst_block_quantile(resid, blocks, q)
        cap60 = caps.get((level, BAL_H))
        r2 = 1.0 - float(np.var(y - (b0 + Z @ w)) / max(np.var(y), 1e-12))
        if tol is None or tol <= 0 or cap60 is None:
            continue
        if only is None and (r2 < MIN_BALANCE_R2 or tol > MAX_BALANCE_VS_RATE * cap60):
            continue
        out.append({"id": inv_id, "family": "balance", "level": level, "horizon": BAL_H, "drivers": drivers_used, "coef": [float(c) for c in w],
                    "mu": [float(m) for m in mu], "sd": [float(s) for s in sd], "intercept": b0, "tol": tol,
                    "fit": {"r2": round(r2, 4), "tol_vs_rate_cap": round(tol / cap60, 4), "windows": int(idx.size)}})
    return out
