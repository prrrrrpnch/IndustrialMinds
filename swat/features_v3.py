"""
swat/features_v3.py - physical model v3 features: multi-scale dynamics, per-stage views, and NORMAL-ONLY consistency models.

THE single feature implementation for v3: training (models/train_physical_v3.py) and the live middleware
(models/physical_model_v3.py) both call base_features() / NormalModels, so live == training by construction.

Inputs are the same live-available points as v1/v2 (10 sensors, 8 actuators) over a LONG = 120 s window at 1 Hz, so the live warm-up
does not grow. What is new compared with swat/features_v2.py:

  * MULTI-SCALE dynamics (30 / 60 / 120 s slopes, 30 / 120 s std, range and net change, largest one-second jump, curvature) and
    actuator "seconds since the last toggle": slow drifts and fast spikes both leave a trace.
  * NO absolute sensor levels in the classifier inputs (they carry SWaT's day-to-day drift); levels appear only as distance outside
    the MEASURED envelope.
  * NORMAL-ONLY models, fitted on benign windows only and used as features:
      - a ridge CONSISTENCY model: each sensor's 30 s and 120 s trend is predicted from the OTHER sensors and the actuators; the
        standardised error is the residual (a relationship that breaks makes it grow);
      - a PCA process monitor (MSPC): Hotelling T2 and the squared prediction error SPE, in total and per stage (the per-stage SPE
        says WHICH stage looks abnormal: it is also the explanation shown with an alert).
    Both are trained cross-fitted (see crossfit_normal_features) so the classifier never sees optimistic in-sample residuals.

Pure NumPy at inference: no scikit-learn needed for the features.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

import numpy as np

from docs.interfaces import MACHINE_BY_NAME
from swat.features_v2 import LONG
from swat.physical_features import ACTUATORS, SENSORS, Norm

FEATURE_VERSION = "physical_v3/1"
SCALES = (30, 60, 120)
STAGE_IDS = (1, 2, 3, 4, 5)
STAGE_OF_SENSOR = np.array([MACHINE_BY_NAME[s]["stage"] for s in SENSORS])
STAGE_OF_ACT = np.array([MACHINE_BY_NAME[a]["stage"] for a in ACTUATORS])
_I101, _I201 = SENSORS.index("FIT101"), SENSORS.index("FIT201")
NS, NA = len(SENSORS), len(ACTUATORS)

SENSOR_STATS = ["slope30", "slope60", "slope120", "std30", "std120", "range30", "range120", "delta30", "delta120", "maxabsdiff120", "curv"]
ACT_STATS = ["state", "toggles120", "frac30", "frac120", "since_toggle"]
CROSS_NAMES = ["x.flow_balance30", "x.flow_balance120", "x.sensors_outside_envelope", "x.max_envelope_excess", "x.env_frac120"]
BASE_NAMES: List[str] = ([f"{s}.{k}" for s in SENSORS for k in SENSOR_STATS]
                         + [f"{a}.{k}" for a in ACTUATORS for k in ACT_STATS] + CROSS_NAMES)

# AUX matrix: statistics used ONLY by the normal-only models (they are not classifier inputs, because some carry levels / drift).
_AUX_BLOCKS: List[Tuple[str, int]] = [("M120", NS), ("M30", NS), ("SL30", NS), ("SL120", NS), ("SD30", NS), ("SD120", NS), ("FON30", NA), ("FON120", NA)]
AUX_SLICES: Dict[str, slice] = {}
_o = 0
for _name, _w in _AUX_BLOCKS:
    AUX_SLICES[_name] = slice(_o, _o + _w)
    _o += _w
AUX_DIM = _o
_SENSOR_BLOCKS = {"M120", "M30", "SL30", "SL120", "SD30", "SD120"}


def _slope(z: np.ndarray) -> np.ndarray:
    """Least-squares slope per second of z [n, W, d] over its W samples -> [n, d]."""
    W = z.shape[1]
    t = np.arange(W, dtype=np.float64) - (W - 1) / 2.0
    return (z * t[None, :, None]).sum(axis=1) / float((t ** 2).sum())


def base_features(Sl: np.ndarray, Al: np.ndarray, norm: Norm) -> Tuple[np.ndarray, np.ndarray]:
    """
    Sl [n, LONG, 10] raw sensor windows, Al [n, LONG, 8] actuator 0/1 windows (no NaN)
    -> (X [n, len(BASE_NAMES)] classifier inputs, AUX [n, AUX_DIM] inputs of the normal-only models).
    """
    n, W, _ = Sl.shape
    if W != LONG:
        raise ValueError(f"expected {LONG} s windows, got {W}")
    z = (Sl - norm.mu) / norm.sd
    zs = {s: z[:, -s:, :] for s in SCALES}
    sl = {s: _slope(zs[s]) for s in SCALES}
    sd = {s: zs[s].std(axis=1) for s in (30, 120)}
    rg = {s: zs[s].max(axis=1) - zs[s].min(axis=1) for s in (30, 120)}
    dl = {s: zs[s][:, -1, :] - zs[s][:, 0, :] for s in (30, 120)}
    maxjump = np.abs(np.diff(z, axis=1)).max(axis=1)
    per_sensor = np.stack([sl[30], sl[60], sl[120], sd[30], sd[120], rg[30], rg[120], dl[30], dl[120], maxjump, sl[30] - sl[120]], axis=2)

    chg = (np.abs(np.diff(Al, axis=1)) > 0)[:, ::-1, :]
    first = chg.argmax(axis=1)
    since = np.where(chg.any(axis=1), first + 1, W).astype(np.float64)
    fon30, fon120 = Al[:, -30:, :].mean(axis=1), Al.mean(axis=1)
    per_act = np.stack([Al[:, -1, :], np.abs(np.diff(Al, axis=1)).sum(axis=1), fon30, fon120, since], axis=2)

    m120, m30 = z.mean(axis=1), zs[30].mean(axis=1)
    x_last = Sl[:, -1, :]
    excess = np.maximum(np.maximum(norm.lo - x_last, x_last - norm.hi), 0.0) / norm.sd
    outside = (Sl < norm.lo) | (Sl > norm.hi)
    cross = np.stack([m30[:, _I101] - m30[:, _I201], m120[:, _I101] - m120[:, _I201], (excess > 0).sum(axis=1).astype(np.float64),
                      excess.max(axis=1), outside.any(axis=2).mean(axis=1)], axis=1)
    X = np.concatenate([per_sensor.reshape(n, -1), per_act.reshape(n, -1), cross], axis=1)
    aux = np.concatenate([m120, m30, sl[30], sl[120], sd[30], sd[120], fon30, fon120], axis=1)
    return X.astype(np.float32), aux.astype(np.float32)


# --------------------------------------------------------------------------- normal-only models
RESID_TARGETS: List[Tuple[str, int]] = [("SL30", i) for i in range(NS)] + [("SL120", i) for i in range(NS)]
RESID_NAMES: List[str] = [f"{SENSORS[i]}.res{30 if b == 'SL30' else 120}" for b, i in RESID_TARGETS]
NM_NAMES: List[str] = RESID_NAMES + ["nm.res_absmax", "nm.res_absmean", "nm.spe", "nm.t2"] + [f"nm.spe_s{s}" for s in STAGE_IDS]
FEATURE_NAMES: List[str] = BASE_NAMES + NM_NAMES


def _regressor_cols(use_levels: bool, i: int) -> np.ndarray:
    blocks = ["SL30", "SL120", "SD30", "SD120", "FON30", "FON120"] + (["M120", "M30"] if use_levels else [])
    cols: List[int] = []
    for b in blocks:
        sl = AUX_SLICES[b]
        for c in range(sl.start, sl.stop):
            if b in _SENSOR_BLOCKS and c - sl.start == i:
                continue                                  # a sensor is never used to predict itself
            cols.append(c)
    return np.array(cols)


def _pca_cols(use_levels: bool) -> Tuple[np.ndarray, np.ndarray]:
    blocks = ["SL30", "SL120", "SD30", "SD120", "FON120"] + (["M120"] if use_levels else [])
    cols: List[int] = []
    stage: List[int] = []
    for b in blocks:
        sl = AUX_SLICES[b]
        for j, c in enumerate(range(sl.start, sl.stop)):
            cols.append(c)
            stage.append(int(STAGE_OF_ACT[j] if b.startswith("FON") else STAGE_OF_SENSOR[j]))
    return np.array(cols), np.array(stage)


class NormalModels:
    """Ridge consistency model + PCA process monitor, fitted on NORMAL windows only. transform() -> len(NM_NAMES) features."""

    def __init__(self, use_levels: bool = True, alpha: float = 10.0, var_target: float = 0.95) -> None:
        self.use_levels, self.alpha, self.var_target = use_levels, alpha, var_target
        self.res: List[Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, float, float]] = []
        self.pca_cols = np.array([], int)
        self.pca_stage = np.array([], int)
        self.pca_mu = self.pca_sd = self.P = self.lam = None
        self.spe_mean = self.t2_mean = 1.0
        self.spe_stage_mean = np.ones(len(STAGE_IDS))

    def fit(self, aux: np.ndarray) -> "NormalModels":
        A = np.asarray(aux, dtype=np.float64)
        self.res = []
        for blk, i in RESID_TARGETS:
            cols = _regressor_cols(self.use_levels, i)
            X = A[:, cols]
            mu, sd = X.mean(axis=0), np.maximum(X.std(axis=0), 1e-6)
            Xs = (X - mu) / sd
            y = A[:, AUX_SLICES[blk].start + i]
            ym = float(y.mean())
            w = np.linalg.solve(Xs.T @ Xs + self.alpha * np.eye(Xs.shape[1]), Xs.T @ (y - ym))
            rsd = float(max((y - (Xs @ w + ym)).std(), 1e-6))
            self.res.append((cols, mu, sd, w, ym, rsd))
        self.pca_cols, self.pca_stage = _pca_cols(self.use_levels)
        V = A[:, self.pca_cols]
        self.pca_mu, self.pca_sd = V.mean(axis=0), np.maximum(V.std(axis=0), 1e-6)
        Z = (V - self.pca_mu) / self.pca_sd
        vals, vecs = np.linalg.eigh(np.cov(Z, rowvar=False))
        order = np.argsort(vals)[::-1]
        vals, vecs = np.maximum(vals[order], 1e-9), vecs[:, order]
        k = int(np.searchsorted(np.cumsum(vals) / vals.sum(), self.var_target) + 1)
        k = max(3, min(k, 20, len(vals) - 1))
        self.P, self.lam = vecs[:, :k], vals[:k]
        spe, t2, spe_s = self._monitor(Z)
        self.spe_mean, self.t2_mean = float(max(spe.mean(), 1e-9)), float(max(t2.mean(), 1e-9))
        self.spe_stage_mean = np.maximum(spe_s.mean(axis=0), 1e-9)
        return self

    def _monitor(self, Z: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        T = Z @ self.P
        E = Z - T @ self.P.T
        sq = E ** 2
        spe_s = np.stack([sq[:, self.pca_stage == s].sum(axis=1) for s in STAGE_IDS], axis=1)
        return sq.sum(axis=1), ((T ** 2) / self.lam).sum(axis=1), spe_s

    def transform(self, aux: np.ndarray) -> np.ndarray:
        A = np.asarray(aux, dtype=np.float64)
        r = np.empty((A.shape[0], len(RESID_TARGETS)))
        for j, ((blk, i), (cols, mu, sd, w, ym, rsd)) in enumerate(zip(RESID_TARGETS, self.res)):
            r[:, j] = (A[:, AUX_SLICES[blk].start + i] - (((A[:, cols] - mu) / sd) @ w + ym)) / rsd
        a = np.abs(r)
        spe, t2, spe_s = self._monitor((A[:, self.pca_cols] - self.pca_mu) / self.pca_sd)
        out = np.concatenate([r, a.max(axis=1, keepdims=True), a.mean(axis=1, keepdims=True), (spe / self.spe_mean)[:, None],
                              (t2 / self.t2_mean)[:, None], spe_s / self.spe_stage_mean], axis=1)
        return out.astype(np.float32)


def crossfit_normal_features(aux: np.ndarray, y: np.ndarray, epoch: np.ndarray, k: int = 4, **kw) -> Tuple[np.ndarray, NormalModels]:
    """
    Normal-model features for the rows of a TRAINING set, without in-sample optimism.
    A benign row in hour-fold g gets features from a model fitted on the benign rows of the OTHER folds; an attack row gets them from
    the model fitted on all benign rows (it was never fitted on attacks either way). Returns (features, the all-benign model), the
    latter being what scores new data (validation folds, the test block, the live middleware).
    """
    y = np.asarray(y).astype(int)
    ben = np.flatnonzero(y == 0)
    full = NormalModels(**kw).fit(aux[ben])
    F = full.transform(aux)
    group = (np.asarray(epoch) // 3600).astype(np.int64) % k
    for g in range(k):
        rows = np.flatnonzero((y == 0) & (group == g))
        train = ben[group[ben] != g]
        if rows.size == 0 or train.size < 500:
            continue
        F[rows] = NormalModels(**kw).fit(aux[train]).transform(aux[rows])
    return F, full


def assemble(X: np.ndarray, nm_features: np.ndarray) -> np.ndarray:
    return np.concatenate([X, nm_features], axis=1)


# --------------------------------------------------------------------------- stacking math (shared by training and live)
def stack_inputs(scores: np.ndarray) -> np.ndarray:
    """Head probabilities [n, h] -> stacker inputs [n, h + 1]: each head's logit, plus the largest logit (any stage speaking up)."""
    p = np.clip(np.asarray(scores, dtype=np.float64), 1e-6, 1.0 - 1e-6)
    L = np.log(p / (1.0 - p))
    return np.concatenate([L, L.max(axis=1, keepdims=True)], axis=1)


def stack_predict(inputs: np.ndarray, w: np.ndarray, b: float) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-(inputs @ np.asarray(w, dtype=np.float64) + float(b))))


# --------------------------------------------------------------------------- per-stage views
def stage_view(stage: int, names: Optional[List[str]] = None) -> np.ndarray:
    """Column indices of FEATURE_NAMES for one stage: its own sensors/actuators (incl. their residuals), its SPE, and the global features."""
    names = names or FEATURE_NAMES
    tags = {t for t, s in zip(SENSORS, STAGE_OF_SENSOR) if s == stage} | {t for t, s in zip(ACTUATORS, STAGE_OF_ACT) if s == stage}
    cols = []
    for j, name in enumerate(names):
        head = name.split(".", 1)[0]
        if head in tags or head == "x" or name in ("nm.res_absmax", "nm.res_absmean", "nm.spe", "nm.t2") or name == f"nm.spe_s{stage}":
            cols.append(j)
    return np.array(cols)


def stage_summary(nm_features: np.ndarray) -> Dict[str, float]:
    """Per-stage normalised SPE for ONE window (the explanation shown next to an alert): which stage looks abnormal."""
    base = len(NM_NAMES) - len(STAGE_IDS)
    return {f"S{s}": float(nm_features[0, base + k]) for k, s in enumerate(STAGE_IDS)}


# --------------------------------------------------------------------------- training windows
def build_windows_v3(stream, norm: Norm, stride: int = 5, batch: int = 4000):
    """
    One pass over the stream: the SAME windows as swat.features_v2.build_windows_v2 (120 s of history, 5 s stride, NaN-free), with
    every feature family computed from the same batch:  (X87, XL, X3, AUX, meta).  X87/XL are the v2 features (kept so the v2 recipe
    can be refit on identical windows as the baseline); X3 / AUX are the v3 ones.
    """
    from swat.features_v2 import long_features
    from swat.physical_features import WINDOW, actuator_class_series, window_features

    chunk = stream["chunk"].to_numpy()
    S = stream[SENSORS].to_numpy(dtype=np.float64)
    A = np.column_stack([actuator_class_series(stream[a].to_numpy(dtype=np.float64), a.startswith("MV"), chunk) for a in ACTUATORS])
    bounds_idx = np.flatnonzero(np.concatenate(([True], chunk[1:] != chunk[:-1], [True])))
    ends = [np.arange(a + LONG - 1, b, stride) for a, b in zip(bounds_idx[:-1], bounds_idx[1:]) if b - a >= LONG]
    cols = ["epoch", "label", "seg", "block", "chunk"]
    if not ends:
        e0 = np.empty((0, 0))
        return e0, e0, np.empty((0, len(BASE_NAMES)), np.float32), np.empty((0, AUX_DIM), np.float32), stream.iloc[:0][cols]
    e = np.concatenate(ends)
    offs = np.arange(-LONG + 1, 1)
    keep, x87, xl, x3, aux = [], [], [], [], []
    for i in range(0, len(e), batch):
        eb = e[i:i + batch]
        idx = eb[:, None] + offs[None, :]
        Sl, Al = S[idx], A[idx]
        ok = ~(np.isnan(Sl).any(axis=(1, 2)) | np.isnan(Al).any(axis=(1, 2)))
        if not ok.any():
            continue
        Sl, Al = Sl[ok], Al[ok]
        x87.append(window_features(Sl[:, -WINDOW:], Al[:, -WINDOW:], norm).astype(np.float32))
        xl.append(long_features(Sl, Al, norm).astype(np.float32))
        b3, ax = base_features(Sl, Al, norm)
        x3.append(b3)
        aux.append(ax)
        keep.append(eb[ok])
    k = np.concatenate(keep)
    meta = stream.iloc[k][cols].reset_index(drop=True)
    return np.vstack(x87), np.vstack(xl), np.vstack(x3), np.vstack(aux), meta
