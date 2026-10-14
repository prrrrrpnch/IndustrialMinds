# Orchestrator fusion model - candidate report

Protocol: out-of-fold physical outputs on train; dominant segment capped; classifier + ALERT threshold chosen on val; test touched once.
Real-data evidence concerns the PHYSICAL side (PASS vs ALERT). DROP rows are constructed from deterministic cyber rules (scenario, not data).

Chosen params: `{'max_depth': 3, 'max_iter': 100, 'l2_regularization': 10.0, 'min_samples_leaf': 200, 'learning_rate': 0.05}`; ALERT threshold 0.9226 (val budget 0.5/h); dominant val segment 22

Rows: {'train': 146981, 'val': 55665, 'test': 34020}

## VAL block

```
{
  "confusion_overall": {
    "labels": [
      "PASS",
      "ALERT",
      "DROP"
    ],
    "rows_truth_cols_pred": [
      [
        26377,
        35,
        0
      ],
      [
        1364,
        6762,
        0
      ],
      [
        0,
        0,
        21127
      ]
    ]
  },
  "confusion_swat_real": {
    "labels": [
      "PASS",
      "ALERT",
      "DROP"
    ],
    "rows_truth_cols_pred": [
      [
        26377,
        35,
        0
      ],
      [
        1364,
        6762,
        0
      ],
      [
        0,
        0,
        0
      ]
    ]
  },
  "confusion_constructed": {
    "labels": [
      "PASS",
      "ALERT",
      "DROP"
    ],
    "rows_truth_cols_pred": [
      [
        0,
        0,
        0
      ],
      [
        0,
        0,
        0
      ],
      [
        0,
        0,
        21127
      ]
    ]
  },
  "roc_auc_fusion_p_alert_real": 0.9310524239256248,
  "roc_auc_physical_p_attack_real": 0.9006492202975034,
  "fusion": {
    "alarm_episodes_per_h": 0.10904134484325308,
    "segments": 8,
    "segments_detected": 4,
    "attack_window_recall": 0.83214373615555
  },
  "physical_alone_at_promoted_operating_point": {
    "alarm_episodes_per_h": 1.3630168105406635,
    "segments": 8,
    "segments_detected": 4,
    "attack_window_recall": 0.8595865124292394
  },
  "naive_lookup_accuracy": 0.9762148567322375,
  "and_gate_accuracy_real": 0.7594244021078232,
  "fusion_accuracy": 0.9748675110033235
}
```

## TEST block

```
{
  "confusion_overall": {
    "labels": [
      "PASS",
      "ALERT",
      "DROP"
    ],
    "rows_truth_cols_pred": [
      [
        26704,
        315,
        0
      ],
      [
        829,
        232,
        0
      ],
      [
        0,
        0,
        5940
      ]
    ]
  },
  "confusion_swat_real": {
    "labels": [
      "PASS",
      "ALERT",
      "DROP"
    ],
    "rows_truth_cols_pred": [
      [
        26704,
        315,
        0
      ],
      [
        829,
        232,
        0
      ],
      [
        0,
        0,
        0
      ]
    ]
  },
  "confusion_constructed": {
    "labels": [
      "PASS",
      "ALERT",
      "DROP"
    ],
    "rows_truth_cols_pred": [
      [
        0,
        0,
        0
      ],
      [
        0,
        0,
        0
      ],
      [
        0,
        0,
        5940
      ]
    ]
  },
  "roc_auc_fusion_p_alert_real": 0.6792926881941805,
  "roc_auc_physical_p_attack_real": 0.8255595540527751,
  "fusion": {
    "alarm_episodes_per_h": 0.5862541174728895,
    "segments": 10,
    "segments_detected": 4,
    "attack_window_recall": 0.21866163996229973
  },
  "physical_alone_at_promoted_operating_point": {
    "alarm_episodes_per_h": 2.051889411155113,
    "segments": 10,
    "segments_detected": 6,
    "attack_window_recall": 0.2714420358152686
  },
  "naive_lookup_accuracy": 0.9552028218694886,
  "and_gate_accuracy_real": 0.9354700854700855,
  "fusion_accuracy": 0.9663727219282775
}
```

## Grid trials

```
[
 {
  "max_depth": 2,
  "max_iter": 100,
  "l2_regularization": 1.0,
  "min_samples_leaf": 50,
  "learning_rate": 0.05,
  "val_auc_excluding_dominant_segment": 0.8349694657979476
 },
 {
  "max_depth": 2,
  "max_iter": 100,
  "l2_regularization": 1.0,
  "min_samples_leaf": 200,
  "learning_rate": 0.05,
  "val_auc_excluding_dominant_segment": 0.8332554489454629
 },
 {
  "max_depth": 2,
  "max_iter": 100,
  "l2_regularization": 10.0,
  "min_samples_leaf": 50,
  "learning_rate": 0.05,
  "val_auc_excluding_dominant_segment": 0.8346942689577643
 },
 {
  "max_depth": 2,
  "max_iter": 100,
  "l2_regularization": 10.0,
  "min_samples_leaf": 200,
  "learning_rate": 0.05,
  "val_auc_excluding_dominant_segment": 0.8351722013409882
 },
 {
  "max_depth": 2,
  "max_iter": 300,
  "l2_regularization": 1.0,
  "min_samples_leaf": 50,
  "learning_rate": 0.05,
  "val_auc_excluding_dominant_segment": 0.8339676948686594
 },
 {
  "max_depth": 2,
  "max_iter": 300,
  "l2_regularization": 1.0,
  "min_samples_leaf": 200,
  "learning_rate": 0.05,
  "val_auc_excluding_dominant_segment": 0.8322370485387032
 },
 {
  "max_depth": 2,
  "max_iter": 300,
  "l2_regularization": 10.0,
  "min_samples_leaf": 50,
  "learning_rate": 0.05,
  "val_auc_excluding_dominant_segment": 0.830328080579684
 },
 {
  "max_depth": 2,
  "max_iter": 300,
  "l2_regularization": 10.0,
  "min_samples_leaf": 200,
  "learning_rate": 0.05,
  "val_auc_excluding_dominant_segment": 0.832000433687167
 },
 {
  "max_depth": 3,
  "max_iter": 100,
  "l2_regularization": 1.0,
  "min_samples_leaf": 50,
  "learning_rate": 0.05,
  "val_auc_excluding_dominant_segment": 0.8335618435658851
 },
 {
  "max_depth": 3,
  "max_iter": 100,
  "l2_regularization": 1.0,
  "min_samples_leaf": 200,
  "learning_rate": 0.05,
  "val_auc_excluding_dominant_segment": 0.8313849028838516
 },
 {
  "max_depth": 3,
  "max_iter": 100,
  "l2_regularization": 10.0,
  "min_samples_leaf": 50,
  "learning_rate": 0.05,
  "val_auc_excluding_dominant_segment": 0.8349191371146244
 },
 {
  "max_depth": 3,
  "max_iter": 100,
  "l2_regularization": 10.0,
  "min_samples_leaf": 200,
  "learning_rate": 0.05,
  "val_auc_excluding_dominant_segment": 0.8361739122360615
 },
 {
  "max_depth": 3,
  "max_iter": 300,
  "l2_regularization": 1.0,
  "min_samples_leaf": 50,
  "learning_rate": 0.05,
  "val_auc_excluding_dominant_segment": 0.8285914708510673
 },
 {
  "max_depth": 3,
  "max_iter": 300,
  "l2_regularization": 1.0,
  "min_samples_leaf": 200,
  "learning_rate": 0.05,
  "val_auc_excluding_dominant_segment": 0.799659802114421
 },
 {
  "max_depth": 3,
  "max_iter": 300,
  "l2_regularization": 10.0,
  "min_samples_leaf": 50,
  "learning_rate": 0.05,
  "val_auc_excluding_dominant_segment": 0.8349191371146244
 },
 {
  "max_depth": 3,
  "max_iter": 300,
  "l2_regularization": 10.0,
  "min_samples_leaf": 200,
  "learning_rate": 0.05,
  "val_auc_excluding_dominant_segment": 0.8083046289741449
 }
]
```