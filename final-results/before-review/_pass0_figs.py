"""PASS 0 figures: confusion matrix and a metrics summary, drawn from the recorded held-out numbers."""
from __future__ import annotations

import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

ROOT = "/home/user/IndustrialMinds"
SHOTS = os.path.join(ROOT, "final-results", "before-review", "screenshots")
M = json.load(open(os.path.join(ROOT, "final-results", "before-review", "_raw", "model.json")))
h = M["heldout_swat"]
cm = h["confusion_matrix"]

fig, ax = plt.subplots(figsize=(6.4, 5.4))
m = np.array([[cm["TN"], cm["FP"]], [cm["FN"], cm["TP"]]], dtype=float)
pct = m / m.sum(axis=1, keepdims=True)
ax.imshow(pct, cmap="Blues", vmin=0, vmax=1)
for i in range(2):
    for j in range(2):
        ax.text(j, i, f"{int(m[i, j]):,}\n{100 * pct[i, j]:.1f}% of row", ha="center", va="center",
                color="white" if pct[i, j] > 0.55 else "black", fontsize=11)
ax.set_xticks([0, 1], ["predicted benign", "predicted attack"])
ax.set_yticks([0, 1], ["true benign", "true attack"])
ax.set_title("Live physical model (PhysicalModelV2)\nheld-out SWaT test block, RECORDED (not re-measured here)\n"
             f"n={h['samples']:,}  accuracy {h['accuracy']:.3f}  macro-F1 {h['macro_f1']:.3f}  AUC {h['auc_roc']}", fontsize=9)
fig.tight_layout()
fig.savefig(os.path.join(SHOTS, "confusion-matrix.png"), dpi=140)
plt.close(fig)

fig, axes = plt.subplots(1, 2, figsize=(12.5, 4.6))
cls = ["attack", "benign"]
metrics = ["precision", "recall", "f1"]
x = np.arange(len(metrics))
for k, c in enumerate(cls):
    vals = [h["per_class"][c][mm] for mm in metrics]
    axes[0].bar(x + k * 0.36, vals, 0.36, label=f"{c} (n={h['per_class'][c]['support']:,})")
    for i, v in enumerate(vals):
        axes[0].text(i + k * 0.36, v + 0.01, f"{v:.3f}", ha="center", fontsize=8)
axes[0].axhline(0.70, ls="--", c="crimson", lw=1)
axes[0].text(2.3, 0.715, "F1 0.70 red line", color="crimson", fontsize=8, ha="right")
axes[0].set_xticks(x + 0.18, metrics)
axes[0].set_ylim(0, 1.08)
axes[0].legend(fontsize=8)
axes[0].set_title("Per class - the attack class is the one that matters", fontsize=10)

names = ["accuracy", "majority-class\nbaseline", "balanced\naccuracy", "macro F1", "weighted F1", "AUC-ROC"]
vals = [h["accuracy"], h["majority_class_baseline_accuracy"], h["balanced_accuracy"], h["macro_f1"],
        h["weighted_f1"], h["auc_roc"]]
cols = ["#999999", "#d62d2d", "#1f77b4", "#1f77b4", "#999999", "#1f77b4"]
axes[1].bar(names, vals, color=cols)
for i, v in enumerate(vals):
    axes[1].text(i, v + 0.012, f"{v:.3f}", ha="center", fontsize=9)
axes[1].set_ylim(0, 1.08)
axes[1].set_title("Headline numbers - accuracy is BELOW the do-nothing baseline (red)", fontsize=10)
axes[1].tick_params(axis="x", labelsize=8)
fig.tight_layout()
fig.savefig(os.path.join(SHOTS, "metrics-summary.png"), dpi=140)
plt.close(fig)

seg = h["segments"]["per_segment"]
fig, ax = plt.subplots(figsize=(9, 4.2))
ids = [str(s["segment"]) for s in seg]
frac = [s["flagged_windows"] / max(s["attack_windows"], 1) for s in seg]
ax.bar(ids, frac, color=["#1f77b4" if s["detected"] else "#d62d2d" for s in seg])
for i, s in enumerate(seg):
    ax.text(i, frac[i] + 0.015, f"{s['flagged_windows']}/{s['attack_windows']}", ha="center", fontsize=7)
ax.set_xlabel("held-out attack segment")
ax.set_ylabel("fraction of attack windows flagged")
ax.set_title(f"Per-segment recall: {h['segments']['detected']}/{h['segments']['total']} segments detected "
             f"(red = missed entirely). Only 10 segments exist - every interval is wide.", fontsize=10)
fig.tight_layout()
fig.savefig(os.path.join(SHOTS, "per-segment-recall.png"), dpi=140)
plt.close(fig)

# honest placeholder: the curve genuinely cannot be drawn
fig, ax = plt.subplots(figsize=(5.6, 5.2))
ax.plot([0, 1], [0, 1], "k--", lw=1)
ax.text(0.5, 0.55, "ROC CURVE NOT AVAILABLE", ha="center", fontsize=13, weight="bold", color="crimson")
ax.text(0.5, 0.45, f"Only the scalar AUC was recorded ({h['auc_roc']}).\nPer-window scores were never saved, so the curve\n"
                   "cannot be reconstructed. Re-running the held-out\nevaluation needs the SWaT archive, which is not\n"
                   "in this environment.", ha="center", fontsize=8.5)
ax.set_xlabel("false positive rate")
ax.set_ylabel("true positive rate")
ax.set_title("ROC - UNAVAILABLE (documented as a finding)", fontsize=10)
fig.tight_layout()
fig.savefig(os.path.join(SHOTS, "roc-curve.png"), dpi=140)
plt.close(fig)
print("figures written to", SHOTS)
