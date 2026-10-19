# Reproduced synthetic results

Generated on 2026-10-19 with deterministic simulator IDs/timestamps and:

```bash
python model/research_experiment.py --runs 30 --seed-start 20261019 --output-dir artifacts/paper_reproduction_20261019
```

The run directory contains 30 independently seeded synthetic datasets (400 normal and 80 attack sessions each), per-run model metrics, per-seed manifests with Python/library versions and SHA-256 hashes, a representative fitted Isolation Forest, and aggregate JSON. Each dataset was split by session into 70% training and 30% test data with stratification. Isolation Forest was fit only on the normal portion of the training split. The run-level 95% intervals below are normal approximations over the 30 seed-level metrics, not intervals over independent real deployments.

| Method | Precision | Recall | F1 | ROC-AUC | Average precision | Specificity (1 − FPR) |
|---|---:|---:|---:|---:|---:|---:|
| Allow all | 0.000 | 0.000 | 0.000 | 0.500 | 0.167 | 1.000 |
| Explicit rules | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| Isolation Forest | 0.552 [0.528, 0.576] | 0.910 [0.887, 0.933] | 0.685 [0.663, 0.706] | 0.960 [0.951, 0.970] | 0.901 [0.881, 0.920] | 0.848 [0.834, 0.863] |
| Supervised logistic regression | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |

For Isolation Forest, attack-family recall was 1.000 for bulk exfiltration, 0.648 for mismatched recipients, 1.000 for rapid-fire, and 1.000 for reconnaissance. Its mean false-positive rate was 0.152 (95% normal-approximation interval 0.137–0.167). The per-run CSV contains each confusion matrix; the mean counts were TN 101.77, FP 18.23, FN 2.17, and TP 21.83 per 144-session test split.

## Interpretation

These results **do not show that the Isolation Forest improves on the baselines**. The explicit rules and supervised model perfectly separate this simulator's four attack patterns because the generated behaviors have distinctive signatures in the engineered features. Isolation Forest misses some recipient-redirection cases and has a substantial benign false-positive rate. This is evidence that the current synthetic benchmark is too easy and that the proposed ML component has no demonstrated advantage here.

The independent label manifest fixes direct feature-to-label derivation, but the data still has simulator shortcut structure: fixed tool names, simple benign behavior, and attacks constructed to trigger the same features used by the rule baseline. The 30 seeds quantify random variation inside this one simulator; they do not provide external validation, robustness to unseen attack families, or evidence about live MCP clients. Do not present these numbers as deployment performance or as proof of security efficacy.

The simulator now uses seeded pseudorandom session/request identifiers and seed-derived virtual timestamps. A test confirms byte-identical logs and labels for repeated runs with the same seed. The earlier committed `results/` metrics and plots predate independent labels and are withdrawn. Use `artifacts/paper_reproduction_20261019/summary.json` and `per_run_metrics.csv` only for this synthetic experiment, alongside the limitations above.
