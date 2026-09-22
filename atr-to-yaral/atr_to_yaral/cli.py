"""Command-line entry point for atr-to-yaral."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from atr_to_yaral.converter import DEFAULT_UDM_FIELD, convert_rules
from atr_to_yaral.parser import load_rule, load_rules_from_directory


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="atr-to-yaral",
        description="Convert Agent Threat Rules (ATR) YAML rules into YARA-L 2.0 rules for Google SecOps (Chronicle).",
    )
    p.add_argument("path", help="Path to a single ATR rule YAML file, or a directory of rules")
    p.add_argument(
        "--udm-field",
        default=DEFAULT_UDM_FIELD,
        help=f"UDM field the regex conditions match against (default: {DEFAULT_UDM_FIELD}). "
        "Change this to match wherever your pipeline puts agent/LLM content.",
    )
    p.add_argument("-o", "--output", help="Write output to this file instead of stdout")
    p.add_argument(
        "--canary",
        action="store_true",
        help="Run each rule's own test_cases (true_positives/true_negatives) against the "
        "converted matching logic before emitting output, and report pass/fail. Exits "
        "non-zero if any true_positive fails to match, since that means the rule wouldn't "
        "fire even with a correctly populated field.",
    )
    return p


def run(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    path = Path(args.path)

    if path.is_dir():
        rules, skipped = load_rules_from_directory(path)
        for skip_path, reason in skipped:
            print(f"skipped {skip_path}: {reason}", file=sys.stderr)
        if not rules:
            print("error: no convertible rules found", file=sys.stderr)
            return 2
        output = convert_rules(rules, udm_field=args.udm_field)
    else:
        from atr_to_yaral.converter import convert_rule
        from atr_to_yaral.parser import UnsupportedRuleError

        try:
            rule = load_rule(path)
        except UnsupportedRuleError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        rules = [rule]
        output = convert_rule(rule, udm_field=args.udm_field) + "\n"

    canary_failed = False
    if args.canary:
        from atr_to_yaral.canary import format_report, run_canary

        print("", file=sys.stderr)
        print("--- canary test results ---", file=sys.stderr)
        for r in rules:
            report = run_canary(r)
            print(format_report(report), file=sys.stderr)
            # A failed true_positive means the converted logic wouldn't fire
            # even with a correctly populated field — that's a real defect,
            # not just missing context, so it fails the run.
            if any(f.case_type == "true_positive" for f in report.failures):
                canary_failed = True
        print("", file=sys.stderr)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        print(output)

    return 1 if canary_failed else 0


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
