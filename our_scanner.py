#!/usr/bin/env python3
"""
Attack Surface Scanner for Android APK.

CLI entry point only.

Responsibilities:
- Parse command-line arguments
- Call scan pipeline
- Print concise summary
- Optionally write JSON / Markdown / PoC reports

Usage:
    python our_scanner.py -f path/to/app.apk
    python our_scanner.py -f app.apk -o ./reports/
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow running as script from repo:
#   python our_scanner.py
#   python our_scanner/our_scanner.py
_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from scanner import scan_apk, scan_apk_to_dir  # noqa: E402


def _score_text(vuln) -> str:
    """Return compact severity/confidence score text if available."""
    severity_score = getattr(vuln, "severity_score", None)
    confidence_score = getattr(vuln, "confidence_score", None)

    if severity_score is None and confidence_score is None:
        return ""

    sev = "-" if severity_score is None else str(severity_score)
    conf = "-" if confidence_score is None else str(confidence_score)
    return f" severity={sev}/10 confidence={conf}/10"


def _print_scan_summary(result) -> None:
    """Print human-readable CLI summary."""
    print(f"Package: {result.meta.package_name}")
    print(f"APK: {result.meta.apk_path}")
    print(f"minSdk / targetSdk: {result.meta.min_sdk} / {result.meta.target_sdk}")
    print(f"debuggable: {result.meta.debuggable}")
    print(f"allowBackup: {result.meta.allow_backup}")
    print()

    print("Summary:")
    print(f"  Total components: {result.summary.get('total_components', 0)}")
    print(f"  Exported/implicit components: {result.summary.get('exported_or_implicit', 0)}")
    print(f"  Deep links: {result.summary.get('deep_link_count', 0)}")
    print(f"  P0 components: {result.summary.get('p0_components', 0)}")
    print(f"  P0 deep links: {result.summary.get('p0_deep_links', 0)}")
    print(
        f"  API keys/tokens (confirmed): {result.summary.get('api_key_confirmed_count', 0)} "
        f"(warnings: {result.summary.get('api_key_warning_count', 0)})"
    )
    print(
        f"  Vulnerabilities: {result.summary.get('vulnerability_count', 0)} "
        f"(Critical: {result.summary.get('critical_vulns', 0)})"
    )
    print(
        f"  Attack chains: {result.summary.get('attack_chain_count', 0)} "
        f"(Critical: {result.summary.get('critical_chains', 0)})"
    )
    print()

    if result.vulnerabilities:
        print("Vulnerability patterns:")
        for vuln in result.vulnerabilities:
            score = _score_text(vuln)
            print(f"  [{vuln.severity}] {vuln.pattern_id}: {vuln.title}{score}")
    else:
        print("Vulnerability patterns: none")

    if result.attack_chains:
        print()
        print("Attack chains:")
        for chain in result.attack_chains:
            score = _score_text(chain)
            parts = " + ".join(chain.composed_of[:5])
            print(f"  [{chain.severity}] {chain.chain_id}: {chain.title}{score}")
            if parts:
                print(f"      {parts}")

    print()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Android APK Attack Surface Scanner",
    )

    parser.add_argument(
        "-f",
        "--apk_file",
        required=True,
        help="Path to APK file",
    )

    parser.add_argument(
        "-o",
        "--output_dir",
        default=None,
        help="Write JSON, Markdown, and poc.sh reports to this directory",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()
    apk = Path(args.apk_file)

    try:
        if args.output_dir:
            result = scan_apk_to_dir(str(apk), args.output_dir)

            pkg = result.meta.package_name or "unknown"
            out = Path(args.output_dir)

            print(f"Reports written to {out.resolve()}")
            print(f"  - {pkg}.json")
            print(f"  - {pkg}.md")
            print(f"  - {pkg}_poc.sh")
            print()

            _print_scan_summary(result)
        else:
            result = scan_apk(str(apk))
            _print_scan_summary(result)

    except ImportError as err:
        print("Error: missing dependency.", file=sys.stderr)
        print("Install dependencies with:", file=sys.stderr)
        print("  pip install -r requirements.txt", file=sys.stderr)
        print(err, file=sys.stderr)
        return 1

    except FileNotFoundError as err:
        print(f"Error: {err}", file=sys.stderr)
        return 1

    except KeyboardInterrupt:
        print("Scan interrupted.", file=sys.stderr)
        return 130

    except Exception as err:
        print(f"Scan failed: {err}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())