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

## API key / token leak scan

The scanner also performs a lightweight **static secret scan** to detect likely hardcoded API keys/tokens
in APK strings/assets/code (values are **redacted** in reports).

Optional online verification is available for a small provider set and is **disabled by default**.
Only enable it for keys you own or have explicit authorization to test:

```bash
python our_scanner.py -f path/to/app.apk -o ./reports/ --verify-api-keys --i-own-these-keys
python our_scanner.py -f path/to/app.apk -o ./reports/ --verify-api-keys --verify-api-keys-allow github,stripe
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