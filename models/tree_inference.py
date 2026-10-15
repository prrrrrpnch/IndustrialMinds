"""
models/tree_inference.py - low-latency inference for fitted scikit-learn tree ensembles.

scikit-learn's predict()/score_samples() carry ~1-10 ms of fixed Python and
input-validation overhead per call, which dominates when scoring ONE Modbus
command at a time. This module copies the fitted trees into padded NumPy
arrays and walks all trees at once, giving bit-for-bit the same leaves as
sklearn (inputs are cast to float32 exactly like sklearn's Tree.apply) in
tens of microseconds.

Equality with sklearn is asserted in tests/test_models.py.
"""

from __future__ import annotations

from typing import Any, List, Optional, Sequence

import numpy as np

_LEAF = -1


def average_path_length(n: np.ndarray) -> np.ndarray:
    """c(n): expected path length of an unsuccessful BST search (Isolation Forest)."""
    n = np.asarray(n, dtype=np.float64)
    out = np.zeros_like(n)
    two = n == 2
    big = n > 2
    out[two] = 1.0
    out[big] = 2.0 * (np.log(n[big] - 1.0) + np.euler_gamma) - 2.0 * (n[big] - 1.0) / n[big]
    return out


class PackedTreeEnsemble:
    """All trees of an ensemble packed into [n_trees, max_nodes] arrays."""

    def __init__(self, trees: Sequence, leaf_values: Sequence[np.ndarray],
                 feature_subsets: Optional[Sequence[np.ndarray]] = None) -> None:
        n_trees = len(trees)
        max_nodes = max(t.node_count for t in trees)

        self.left = np.full((n_trees, max_nodes), _LEAF, dtype=np.int64)
        self.right = np.full((n_trees, max_nodes), _LEAF, dtype=np.int64)
        self.feature = np.zeros((n_trees, max_nodes), dtype=np.int64)
        self.threshold = np.zeros((n_trees, max_nodes), dtype=np.float64)
        self.leaf_value = np.zeros((n_trees, max_nodes), dtype=np.float64)

        self.max_depth = 0
        for i, t in enumerate(trees):
            n = t.node_count
            self.left[i, :n] = t.children_left
            self.right[i, :n] = t.children_right
            feat = np.where(t.feature >= 0, t.feature, 0)
            if feature_subsets is not None:
                # Map tree-local feature index -> column in the full matrix.
                feat = np.asarray(feature_subsets[i])[feat]
            self.feature[i, :n] = feat
            self.threshold[i, :n] = t.threshold
            self.leaf_value[i, :n] = leaf_values[i]
            self.max_depth = max(self.max_depth, int(t.max_depth))

        self.n_trees = n_trees
        self._tree_idx = np.arange(n_trees)

    def leaf_values(self, X: np.ndarray) -> np.ndarray:
        """Returns [n_samples, n_trees] leaf values."""
        X = np.asarray(X, dtype=np.float32).astype(np.float64)
        if X.ndim == 1:
            X = X[None, :]
        n = X.shape[0]

        nodes = np.zeros((n, self.n_trees), dtype=np.int64)
        rows = np.arange(n)[:, None]
        trees = self._tree_idx[None, :]

        for _ in range(self.max_depth + 1):
            left = self.left[trees, nodes]
            is_leaf = left == _LEAF
            if is_leaf.all():
                break
            feat = self.feature[trees, nodes]
            go_left = X[rows, feat] <= self.threshold[trees, nodes]
            nxt = np.where(go_left, left, self.right[trees, nodes])
            nodes = np.where(is_leaf, nodes, nxt)

        return self.leaf_value[trees, nodes]


def pack_isolation_forest(model: Any) -> "PackedIsolationForest":
    return PackedIsolationForest(model)


class PackedIsolationForest:
    """Exact re-implementation of IsolationForest.score_samples()."""

    def __init__(self, model: Any) -> None:
        trees = [e.tree_ for e in model.estimators_]
        leaf_terms: List[np.ndarray] = []
        for t in trees:
            depth = np.zeros(t.node_count, dtype=np.float64)
            for node in range(t.node_count):          # parents precede children
                for child in (t.children_left[node], t.children_right[node]):
                    if child != _LEAF:
                        depth[child] = depth[node] + 1.0
            # sklearn: decision_path_length (= depth + 1) + c(n_leaf) - 1
            leaf_terms.append(depth + average_path_length(t.n_node_samples))

        subsets = None
        if getattr(model, "_max_features", None) != model.n_features_in_:
            subsets = model.estimators_features_
        self.packed = PackedTreeEnsemble(trees, leaf_terms, subsets)
        self.denominator = len(trees) * float(average_path_length(np.array([model._max_samples]))[0])

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """Same sign convention as sklearn: lower = more anomalous (range [-1, 0])."""
        depths = self.packed.leaf_values(X).sum(axis=1)
        if self.denominator == 0:
            return -np.ones(depths.shape[0])
        return -(2.0 ** (-depths / self.denominator))


class PackedForestRegressor:
    """Exact re-implementation of RandomForestRegressor.predict() (single output)."""

    def __init__(self, model: Any) -> None:
        trees = [e.tree_ for e in model.estimators_]
        values = [t.value[:, 0, 0].astype(np.float64) for t in trees]
        self.packed = PackedTreeEnsemble(trees, values)

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self.packed.leaf_values(X).mean(axis=1)


class PackedHistGB:
    """Single-row (or small batch) inference for a fitted sklearn HistGradientBoostingClassifier (binary, numerical features).

    sklearn's predict_proba has milliseconds of fixed overhead per call; this walks all trees at once with numpy and returns the same
    probabilities (checked against sklearn in tests/test_physical_v2_live.py). Falls back to the caller (raises ValueError) for models it does not support."""

    def __init__(self, gb) -> None:
        preds = gb._predictors
        if len(gb.classes_) != 2 or any(len(p) != 1 for p in preds):
            raise ValueError("PackedHistGB supports binary classifiers only")
        nodes = [p[0].nodes for p in preds]
        if any(n["is_categorical"].any() for n in nodes):
            raise ValueError("categorical splits are not supported")
        T, M = len(nodes), max(len(n) for n in nodes)
        self.feat = np.zeros((T, M), dtype=np.int64)
        self.thr = np.zeros((T, M))
        self.left = np.zeros((T, M), dtype=np.int64)
        self.right = np.zeros((T, M), dtype=np.int64)
        self.leaf = np.ones((T, M), dtype=bool)
        self.val = np.zeros((T, M))
        self.nan_left = np.zeros((T, M), dtype=bool)
        for t, n in enumerate(nodes):
            k = len(n)
            self.feat[t, :k], self.thr[t, :k] = n["feature_idx"], n["num_threshold"]
            self.left[t, :k], self.right[t, :k] = n["left"], n["right"]
            self.leaf[t, :k], self.val[t, :k] = n["is_leaf"].astype(bool), n["value"]
            self.nan_left[t, :k] = n["missing_go_to_left"].astype(bool)
        self.depth = int(max(n["depth"].max() for n in nodes))
        self.baseline = float(np.ravel(gb._baseline_prediction)[0])
        self.T = T
        self._rows = np.arange(T)

    def predict_proba1(self, X: np.ndarray) -> np.ndarray:
        """X [n, f] -> P(class 1) [n]."""
        X = np.atleast_2d(X)
        out = np.empty(X.shape[0])
        for r, x in enumerate(X):
            idx = np.zeros(self.T, dtype=np.int64)
            t = self._rows
            for _ in range(self.depth):
                f = self.feat[t, idx]
                v = x[f]
                go_left = np.where(np.isnan(v), self.nan_left[t, idx], v <= self.thr[t, idx])
                nxt = np.where(go_left, self.left[t, idx], self.right[t, idx])
                idx = np.where(self.leaf[t, idx], idx, nxt)
            raw = self.baseline + self.val[t, idx].sum()
            out[r] = 1.0 / (1.0 + np.exp(-raw))
        return out
