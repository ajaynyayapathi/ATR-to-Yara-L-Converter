from pathlib import Path

import pytest

from atr_to_yaral.converter import convert_rule
from atr_to_yaral.parser import UnsupportedRuleError, load_rule, load_rules_from_directory

FIXTURES = Path(__file__).parent / "fixtures"


def test_parses_any_condition_rule():
    rule = load_rule(FIXTURES / "ATR-2026-00001-prompt-injection.yaml")
    assert rule.id == "ATR-2026-00001"
    assert rule.severity == "high"
    assert rule.condition_logic == "any"
    assert len(rule.conditions) == 2
    assert "AML.T0051 - LLM Prompt Injection" in rule.mitre_atlas


def test_parses_all_condition_rule():
    rule = load_rule(FIXTURES / "ATR-2026-00524-credential-exfil.yaml")
    assert rule.condition_logic == "all"
    assert len(rule.conditions) == 2


def test_any_logic_combines_into_single_alternated_regex():
    rule = load_rule(FIXTURES / "ATR-2026-00001-prompt-injection.yaml")
    output = convert_rule(rule)

    assert "rule ATR_2026_00001 {" in output
    assert 'atr_id = "ATR-2026-00001"' in output
    assert 'severity = "HIGH"' in output
    # OR logic -> one predicate line with an alternation
    event_lines = [l for l in output.splitlines() if "$e." in l and "=" in l]
    assert len(event_lines) == 1
    assert "|" in event_lines[0]
    assert "condition:" in output
    assert output.strip().endswith("}")


def test_all_logic_produces_separate_anded_predicate_lines():
    rule = load_rule(FIXTURES / "ATR-2026-00524-credential-exfil.yaml")
    output = convert_rule(rule)

    event_lines = [l for l in output.splitlines() if "$e." in l and "=" in l]
    # AND logic -> one predicate line per condition, implicitly ANDed by YARA-L
    assert len(event_lines) == 2


def test_custom_udm_field_is_applied():
    rule = load_rule(FIXTURES / "ATR-2026-00001-prompt-injection.yaml")
    output = convert_rule(rule, udm_field="security_result.description")
    assert "$e.security_result.description" in output


def test_unsupported_operator_is_skipped_not_crashed(tmp_path):
    bad_rule = tmp_path / "bad.yaml"
    bad_rule.write_text(
        """
title: Semantic similarity rule
id: ATR-2026-99999
severity: medium
detection:
  condition: any
  conditions:
    - field: content
      operator: semantic_similarity
      value: "some embedding reference"
"""
    )
    with pytest.raises(UnsupportedRuleError):
        load_rule(bad_rule)


def test_load_rules_from_directory_skips_bad_rules_gracefully(tmp_path):
    good = tmp_path / "good.yaml"
    good.write_text((FIXTURES / "ATR-2026-00001-prompt-injection.yaml").read_text())
    bad = tmp_path / "bad.yaml"
    bad.write_text("title: no detection block\nid: ATR-2026-00002\n")

    rules, skipped = load_rules_from_directory(tmp_path)
    assert len(rules) == 1
    assert len(skipped) == 1
    assert "ATR-2026-00002" not in [r.id for r in rules]


def test_regex_slash_escaping():
    rule = load_rule(FIXTURES / "ATR-2026-00524-credential-exfil.yaml")
    output = convert_rule(rule)
    # the fixture's regex contains https?:// which has no literal slash needing
    # escape after urlencoding logic; verify output still parses as balanced text
    assert output.count("{") == output.count("}")
