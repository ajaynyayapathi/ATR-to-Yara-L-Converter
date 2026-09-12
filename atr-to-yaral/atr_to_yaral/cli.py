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

        rule = load_rule(path)
        output = convert_rule(rule, udm_field=args.udm_field) + "\n"

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        print(output)

    return 0


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
