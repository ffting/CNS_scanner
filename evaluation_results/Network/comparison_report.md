# Tool Comparison Report

## Overall Summary

| Tool | Cases | Expected | Raw Findings | Scoped Findings | TP | FP | FN | Precision | Recall | F1 | High-Conf Precision | High-Priority Precision |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| mobsf | 5 | 16 | 42 | 37 | 0 | 37 | 16 | 0.0000 | 0.0000 | N/A | 0.0000 | 0.0000 |
| our_scanner | 5 | 16 | 9 | 8 | 7 | 1 | 9 | 0.8750 | 0.4375 | 0.5833 | 0.8750 | 0.8750 |

## Per-case Comparison

### Network/MASTG-TEST0019

| Tool | Expected | Findings | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| mobsf | 5 | 6 | 0 | 6 | 5 | 0.0000 | 0.0000 | N/A |
| our_scanner | 5 | 2 | 2 | 0 | 3 | 1.0000 | 0.4000 | 0.5714 |

### Network/MASTG-TEST0020

| Tool | Expected | Findings | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| mobsf | 2 | 5 | 0 | 5 | 2 | 0.0000 | 0.0000 | N/A |
| our_scanner | 2 | 3 | 2 | 1 | 0 | 0.6667 | 1.0000 | 0.8000 |

### Network/MASTG-TEST0021

| Tool | Expected | Findings | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| mobsf | 5 | 8 | 0 | 8 | 5 | 0.0000 | 0.0000 | N/A |
| our_scanner | 5 | 2 | 2 | 0 | 3 | 1.0000 | 0.4000 | 0.5714 |

### Network/MASTG-TEST0022

| Tool | Expected | Findings | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| mobsf | 2 | 11 | 0 | 11 | 2 | 0.0000 | 0.0000 | N/A |
| our_scanner | 2 | 1 | 1 | 0 | 1 | 1.0000 | 0.5000 | 0.6667 |

### Network/MASTG-TEST0023

| Tool | Expected | Findings | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| mobsf | 2 | 7 | 0 | 7 | 2 | 0.0000 | 0.0000 | N/A |
| our_scanner | 2 | 0 | 0 | 0 | 2 | N/A | 0.0000 | N/A |

## Best Tool Per Case

| Case | Best Tool | Reason |
|---|---|---|
| Network/MASTG-TEST0019 | our_scanner | TP=2, FP=0, FN=3, F1=0.5714 |
| Network/MASTG-TEST0020 | our_scanner | TP=2, FP=1, FN=0, F1=0.8000 |
| Network/MASTG-TEST0021 | our_scanner | TP=2, FP=0, FN=3, F1=0.5714 |
| Network/MASTG-TEST0022 | our_scanner | TP=1, FP=0, FN=1, F1=0.6667 |
| Network/MASTG-TEST0023 | our_scanner | TP=0, FP=0, FN=2, F1=N/A |

## Notes

- Raw Findings means all findings loaded from each normalized report.
- Scoped Findings means findings after category, third-party, and optional score filters.
- TP/FP/FN are computed using the same matching logic as the detailed evaluation report.