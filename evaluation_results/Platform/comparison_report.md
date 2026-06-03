# Tool Comparison Report

## Overall Summary

| Tool | Cases | Expected | Raw Findings | Scoped Findings | TP | FP | FN | Precision | Recall | F1 | High-Conf Precision | High-Priority Precision |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| mobsf | 10 | 25 | 85 | 73 | 3 | 70 | 22 | 0.0411 | 0.1200 | 0.0612 | 0.0625 | 0.0429 |
| our_scanner | 10 | 25 | 7 | 6 | 5 | 1 | 20 | 0.8333 | 0.2000 | 0.3226 | 1.0000 | 0.8333 |

## Per-case Comparison

### Platform/MASTG-TEST0007

| Tool | Expected | Findings | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| mobsf | 2 | 7 | 2 | 5 | 0 | 0.2857 | 1.0000 | 0.4444 |
| our_scanner | 2 | 1 | 1 | 0 | 1 | 1.0000 | 0.5000 | 0.6667 |

### Platform/MASTG-TEST0008

| Tool | Expected | Findings | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| mobsf | 2 | 4 | 0 | 4 | 2 | 0.0000 | 0.0000 | N/A |
| our_scanner | 2 | 0 | 0 | 0 | 2 | N/A | 0.0000 | N/A |

### Platform/MASTG-TEST0024

| Tool | Expected | Findings | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| mobsf | 2 | 6 | 0 | 6 | 2 | 0.0000 | 0.0000 | N/A |
| our_scanner | 2 | 2 | 2 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |

### Platform/MASTG-TEST0028

| Tool | Expected | Findings | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| mobsf | 3 | 9 | 0 | 9 | 3 | 0.0000 | 0.0000 | N/A |
| our_scanner | 3 | 2 | 2 | 0 | 1 | 1.0000 | 0.6667 | 0.8000 |

### Platform/MASTG-TEST0030

| Tool | Expected | Findings | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| mobsf | 2 | 7 | 0 | 7 | 2 | 0.0000 | 0.0000 | N/A |
| our_scanner | 2 | 1 | 0 | 1 | 2 | 0.0000 | 0.0000 | N/A |

### Platform/MASTG-TEST0031

| Tool | Expected | Findings | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| mobsf | 2 | 4 | 0 | 4 | 2 | 0.0000 | 0.0000 | N/A |
| our_scanner | 2 | 0 | 0 | 0 | 2 | N/A | 0.0000 | N/A |

### Platform/MASTG-TEST0032

| Tool | Expected | Findings | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| mobsf | 3 | 10 | 0 | 10 | 3 | 0.0000 | 0.0000 | N/A |
| our_scanner | 3 | 0 | 0 | 0 | 3 | N/A | 0.0000 | N/A |

### Platform/MASTG-TEST0033

| Tool | Expected | Findings | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| mobsf | 3 | 13 | 1 | 12 | 2 | 0.0769 | 0.3333 | 0.1250 |
| our_scanner | 3 | 0 | 0 | 0 | 3 | N/A | 0.0000 | N/A |

### Platform/MASTG-TEST0035

| Tool | Expected | Findings | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| mobsf | 2 | 8 | 0 | 8 | 2 | 0.0000 | 0.0000 | N/A |
| our_scanner | 2 | 0 | 0 | 0 | 2 | N/A | 0.0000 | N/A |

### Platform/MASTG-TEST0037

| Tool | Expected | Findings | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| mobsf | 4 | 5 | 0 | 5 | 4 | 0.0000 | 0.0000 | N/A |
| our_scanner | 4 | 0 | 0 | 0 | 4 | N/A | 0.0000 | N/A |

## Best Tool Per Case

| Case | Best Tool | Reason |
|---|---|---|
| Platform/MASTG-TEST0007 | our_scanner | TP=1, FP=0, FN=1, F1=0.6667 |
| Platform/MASTG-TEST0008 | our_scanner | TP=0, FP=0, FN=2, F1=N/A |
| Platform/MASTG-TEST0024 | our_scanner | TP=2, FP=0, FN=0, F1=1.0000 |
| Platform/MASTG-TEST0028 | our_scanner | TP=2, FP=0, FN=1, F1=0.8000 |
| Platform/MASTG-TEST0030 | our_scanner | TP=0, FP=1, FN=2, F1=N/A |
| Platform/MASTG-TEST0031 | our_scanner | TP=0, FP=0, FN=2, F1=N/A |
| Platform/MASTG-TEST0032 | our_scanner | TP=0, FP=0, FN=3, F1=N/A |
| Platform/MASTG-TEST0033 | mobsf | TP=1, FP=12, FN=2, F1=0.1250 |
| Platform/MASTG-TEST0035 | our_scanner | TP=0, FP=0, FN=2, F1=N/A |
| Platform/MASTG-TEST0037 | our_scanner | TP=0, FP=0, FN=4, F1=N/A |

## Notes

- Raw Findings means all findings loaded from each normalized report.
- Scoped Findings means findings after category, third-party, and optional score filters.
- TP/FP/FN are computed using the same matching logic as the detailed evaluation report.