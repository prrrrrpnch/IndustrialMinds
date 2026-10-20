"""
research/ - experiments that were run on real SWaT, measured, and NOT promoted.

They are kept because a documented negative result is evidence, and because the trainers are the reproducible proof behind
the numbers in docs/reports/. They are NOT kept on the import path of the live control system, which is the distinction the
audit (final-results/AUDIT.md, A-list and PASS 3) drew: roughly 29% of the product's lines were rejected experiments sitting
next to the shipped model, where a wrong import is a silent downgrade.

  physical_model_v3 / features_v3 / train_physical_v3 / package_physical_v3
        v3 physical stack. Measured WORSE than the live v2 on the held-out SWaT block (F1 0.352 vs 0.432,
        6/10 vs 8/10 segments). Reachable only via IM_PHYSICAL_MODEL=v3, imported lazily.
  train_fusion_swat / fusion_scenarios
        learned orchestrator fusion. Test AUC 0.68 vs 0.83 for the physical model alone -> rule-based fusion shipped instead.
  train_cyber_swat
        the cyber ML candidate. Test ROC-AUC 0.63, F1 0.137 -> the cyber branch is rules-only.

Deliberately NOT moved: swat/cyber_events.py. The audit listed it here, but models/cyber_model.py imports it live, and the
same audit credits the shared train/serve feature code as the single best defence against train/serve skew. Moving it would
put live feature extraction in research/ to satisfy a label.
"""
