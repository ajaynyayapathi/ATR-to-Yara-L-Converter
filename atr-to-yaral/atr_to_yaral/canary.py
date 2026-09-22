"""Canary testing: proves a converted rule's matching logic actually works against the ATR rule author's own test cases, rather than just compiling.

This does NOT prove the rule will fire in a live Chronicle instance — it can't, since that depends entirely on which UDM field your pipeline actually populates with agent content (see README). 
What it DOES prove is narrower but still useful: given the field is populated correctly, does the converted AND/OR logic match what the rule author intended?

Since patterns are now validated with a real RE2 compile check at parse time (see parser.compile_check), the surviving patterns behave equivalently under Python's re module for constructs this converter
allows through, which makes re a valid local stand-in for this check without needing a live Chronicle instance.
"""

from __future__ import annotations

import re as _re
from dataclasses import dataclass

from atr_to_yaral.parser import AtrRule


@dataclass
class CaseResult:
    case_type: str  # "true_positive" or "true_negative"
    text: str
    expected_match: bool
    actual_match: bool

    @property
    def passed(self) -> bool:
        return self.expected_match == self.actual_match


@dataclass
class CanaryReport:
    rule_id: str
    results: list[CaseResult]

    @property
    def has_test_cases(self) -> bool:
        return len(self.results) > 0

    @property
    def all_passed(self) -> bool:
        return all(r.passed for r in self.results)

    @property
    def failures(self) -> list[CaseResult]:
        return [r for r in self.results if not r.passed]


def _rule_matches(rule: AtrRule, text: str) -> bool:
    matches = [bool(_re.search(c.value, text)) for c in rule.conditions]
    if rule.condition_logic == "all":
        return all(matches)
    return any(matches)


def run_canary(rule: AtrRule) -> CanaryReport:
    results: list[CaseResult] = []

    for text in rule.true_positives:
        results.append(
            CaseResult(
                case_type="true_positive",
                text=text,
                expected_match=True,
                actual_match=_rule_matches(rule, text),
            )
        )

    for text in rule.true_negatives:
        results.append(
            CaseResult(
                case_type="true_negative",
                text=text,
                expected_match=False,
                actual_match=_rule_matches(rule, text),
            )
        )

    return CanaryReport(rule_id=rule.id, results=results)


def format_report(report: CanaryReport) -> str:
    if not report.has_test_cases:
        return f"{report.rule_id}: no test_cases in the source rule — nothing to verify"

    lines = []
    for r in report.results:
        status = "PASS" if r.passed else "FAIL"
        lines.append(f"  [{status}] {r.case_type}: {r.text[:70]!r}")

    summary = "all test cases passed" if report.all_passed else f"{len(report.failures)} of {len(report.results)} failed"
    lines.insert(0, f"{report.rule_id}: {summary}")
    return "\n".join(lines)
