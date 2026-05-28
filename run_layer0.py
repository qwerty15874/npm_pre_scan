#!/usr/bin/env python3
"""
CLI for Layer 0 metadata checks.

Usage:
    python run_layer0.py <package-name> [package-name ...]
    python run_layer0.py --json <package-name>
"""
import argparse
import json
import sys

from layer0 import run_layer0

VERDICT_COLOR = {
    "PASS": "\033[32m",    # green
    "SUSPECT": "\033[33m", # yellow
    "BLOCK": "\033[31m",   # red
    "ERROR": "\033[35m",   # magenta
}
RESET = "\033[0m"


def print_result(result: dict, use_color: bool = True) -> None:
    verdict = result["verdict"]
    color = VERDICT_COLOR.get(verdict, "") if use_color else ""
    reset = RESET if use_color else ""

    print(f"\n{'='*60}")
    print(f"Package : {result['package']}")
    print(f"Verdict : {color}{verdict}{reset}")

    note = result.get("note")
    if note:
        print(f"Note    : {note}")

    findings = result.get("findings", [])
    if not findings:
        print("Findings: none")
    else:
        print(f"Findings: {len(findings)}")
        for f in findings:
            sev = f.get("severity", "?")
            sev_color = {
                "BLOCK": "\033[31m", "SUSPECT": "\033[33m", "INFO": "\033[36m"
            }.get(sev, "") if use_color else ""
            print(f"  [{sev_color}{sev}{reset}] ({f['check']}) {f.get('message', '')}")


def main() -> None:
    parser = argparse.ArgumentParser(description="npm pre-scan Layer 0 checker")
    parser.add_argument("packages", nargs="+", help="npm package name(s) to check")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    parser.add_argument("--no-color", action="store_true", help="Disable color output")
    args = parser.parse_args()

    results = []
    for pkg in args.packages:
        sys.stderr.write(f"Checking {pkg}...\n")
        result = run_layer0(pkg)
        results.append(result)

    if args.json:
        print(json.dumps(results if len(results) > 1 else results[0], indent=2))
    else:
        for r in results:
            print_result(r, use_color=not args.no_color)
        print()

    # Exit code: 0=PASS, 1=SUSPECT, 2=BLOCK
    worst = "PASS"
    for r in results:
        v = r["verdict"]
        if v == "BLOCK":
            worst = "BLOCK"
            break
        if v == "SUSPECT":
            worst = "SUSPECT"

    sys.exit({"PASS": 0, "SUSPECT": 1, "BLOCK": 2}.get(worst, 3))


if __name__ == "__main__":
    main()
