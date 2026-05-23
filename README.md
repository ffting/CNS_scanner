# our_scanner — Android Attack Surface Scanner

Python 3 scanner focused on **bug-bounty-style attack surface**: exported components, ContentProviders, implicit services, deep links / app links, plus **adb test command drafts**.

Complements [AndroBugs](../AndroBugs_Framework/) (broad rule-based scan); this tool produces a **short, prioritized map** for manual testing.

## Install

```bash
cd our_scanner
pip install -r requirements.txt
```

## Usage

```bash
# Summary on terminal
python our_scanner.py -f path/to/app.apk

# Full report (JSON + Markdown + poc.sh)
python our_scanner.py -f path/to/app.apk -o ./reports/
```

## Output

| File | Content |
|------|---------|
| `{package}.json` | Machine-readable full result |
| `{package}.md` | Human-readable report |
| `{package}_poc.sh` | Suggested `adb` commands (review before run) |

## Priority levels

| Level | Meaning |
|-------|---------|
| **P0** | Test first (e.g. exported OAuth callback, exposed provider) |
| **P1** | High-value exported surface |
| **P2** | Review when time allows |
| **P3** | Informational (e.g. launcher entry) |

## Vulnerability patterns & attack chains

After surface analysis, the scanner matches **named vulnerability patterns** (e.g. exported provider leak, OAuth deep link open) and composes **attack chains** when multiple patterns/signals align (A + B => plausible exploit path).

See `vulnerability_patterns.py` for the full rule list.

## Modules

- `manifest_parser.py` — APK / Manifest via androguard
- `deep_link.py` — intent-filter URL patterns
- `risk_rules.py` — heuristics and P0–P3 scoring
- `vulnerability_patterns.py` — pattern + chain detection
- `poc_generator.py` — adb command drafts
- `report.py` — JSON / Markdown export

## Limitations

- Static analysis only; does not confirm exploitability
- Does not replace dynamic tools (e.g. drozer) or full SAST (MobSF, AndroBugs)
- Code-level taint analysis is not included in v1

## Ground truth

`ground_truth.json` stores the expected finding for each benchmark test.

## Run benchmark scan

Scan all APKs under one benchmark category:

```bash
./run_scanner.sh Platform
```

## Run evaluation

Evaluate one APK report:

```bash
python evaluation.py \
  --scanner our_scanner \
  --result ./reports/our_scanner/Platform/MASTG-TEST0007/com.example.mastg_test0007.json \
  --ground-truth ./ground_truth.json \
  --app-id MASTG-TEST0007 \
  --out ./evaluation_results
```

Evaluate a whole category:

```bash
python evaluation.py \
  --scanner our_scanner \
  --result-dir ./reports/our_scanner/Platform \
  --ground-truth ./ground_truth.json \
  --out ./evaluation_results
```

Evaluation outputs:

| File | Content |
|------|---------|
| `evaluation_results/our_scanner/{app_id}_evaluation.json` | Per-test matching details |
| `evaluation_results/our_scanner_summary.csv` | Per-test summary |
| `evaluation_results/our_scanner_overall.json` | Overall benchmark result |

## Current workflow

```text
1. Put OWApp APKs under benchmarks/
2. Run ./run_scanner.sh <Category>
3. Read each test README
4. Add expected findings to ground_truth.json
5. Run evaluation.py
6. Use summary CSV / overall JSON for reporting
```