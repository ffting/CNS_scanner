#!/usr/bin/env python3
"""
Attack Surface Scanner for Android APK.

Focus: exported components, ContentProvider exposure, implicit services,
       deep links / app links, and adb PoC drafts for manual testing.

Usage:
    python our_scanner.py -f path/to/app.apk
    python our_scanner.py -f app.apk -o ./reports/
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow running as script from repo: python our_scanner/our_scanner.py
_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from scanner import scan_apk, scan_apk_to_dir  # noqa: E402


def _print_scan_summary(result) -> None:
    print(f"Package: {result.meta.package_name}")
    print(f"Exported/implicit components: {result.summary.get('exported_or_implicit', 0)}")
    print(f"Deep links: {result.summary.get('deep_link_count', 0)}")
    print(f"Vulnerabilities: {result.summary.get('vulnerability_count', 0)} "
          f"(Critical: {result.summary.get('critical_vulns', 0)})")
    print(f"Attack chains: {result.summary.get('attack_chain_count', 0)}")
    print()
    if result.vulnerabilities:
        print("Vulnerability patterns:")
        for vuln in result.vulnerabilities:
            print(f"  [{vuln.severity}] {vuln.pattern_id}: {vuln.title}")
    if result.attack_chains:
        print()
        print("Attack chains (A + B):")
        for chain in result.attack_chains:
            parts = " + ".join(chain.composed_of[:5])
            print(f"  [{chain.severity}] {chain.chain_id}")
            print(f"      {parts}")
    print()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Android APK Attack Surface Scanner (Manifest + Deep Links)",
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
        help="Write JSON, Markdown, and poc.sh to this directory",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    apk = Path(args.apk_file)

    try:
        if args.output_dir:
            result = scan_apk_to_dir(str(apk), args.output_dir)
            pkg = result.meta.package_name
            out = Path(args.output_dir)
            print(f"Reports written to {out.resolve()}")
            print(f"  - {pkg}.json")
            print(f"  - {pkg}.md")
            print(f"  - {pkg}_poc.sh")
            _print_scan_summary(result)
        else:
            result = scan_apk(str(apk))
            _print_scan_summary(result)
    except ImportError as err:
        print("Error: androguard is required. Install with:", file=sys.stderr)
        print("  pip install -r requirements.txt", file=sys.stderr)
        print(err, file=sys.stderr)
        return 1
    except FileNotFoundError as err:
        print(err, file=sys.stderr)
        return 1
    except Exception as err:
        print(f"Scan failed: {err}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
