"""Converts ATR rules into YARA-L 2.0 rules for Google SecOps.

Scope for v1: only ATR rules with operator: regex conditions are supported, and only patterns that actually compile as RE2 (Chronicle's regex engine) — see parser.py's compile_check(). That covers the large majority of
published ATR rules.

The open question this converter has to make an assumption about: ATR rules match against agent-runtime events (LLM input, tool-call arguments, SKILL.md content) and there is currently no standard UDM field where that content
lands once ingested into Chronicle. This converter defaults to `metadata.description`, a generic free-text field present on any UDM event, and lets you override it with --udm-field to match your actual ingestion
pipeline. See README.md for why this matters before you deploy anything generated here.
"""

from __future__ import annotations

from atr_to_yaral.parser import AtrRule

DEFAULT_UDM_FIELD = "metadata.description"


def _escape_regex_for_yaral(pattern: str) -> str:
    """Escape forward slashes, since YARA-L regex literals are /-delimited."""
    return pattern.replace("/", r"\/")


def _sanitize_rule_name(atr_id: str) -> str:
    return atr_id.replace("-", "_")


def convert_rule(rule: AtrRule, udm_field: str = DEFAULT_UDM_FIELD) -> str:
    name = _sanitize_rule_name(rule.id)
    severity = rule.severity.upper()

    description = rule.description.replace('"', "'").replace("\n", " ").strip()
    if len(description) > 500:
        description = description[:497] + "..."

    lines = [f"rule {name} {{", "  meta:"]
    lines.append(f'    atr_id = "{rule.id}"')
    lines.append(f'    title = "{rule.title}"')
    if description:
        lines.append(f'    description = "{description}"')
    lines.append(f'    severity = "{severity}"')
    if rule.mitre_atlas:
        lines.append(f'    mitre_atlas = "{", ".join(rule.mitre_atlas)}"')
    if rule.owasp_agentic:
        lines.append(f'    owasp_agentic = "{", ".join(rule.owasp_agentic)}"')
    lines.append('    source = "Converted from Agent Threat Rules (ATR) — https://github.com/Agent-Threat-Rule/agent-threat-rules"')
    if rule.translated_unicode_escapes:
        lines.append('    converter_note = "unicode escapes were rewritten for RE2 compatibility"')

    lines.append("")
    lines.append("  events:")

    if rule.condition_logic == "any" and len(rule.conditions) > 1:
        # OR semantics: combine into a single alternated regex on one predicate line.
        patterns = [_escape_regex_for_yaral(c.value) for c in rule.conditions]
        combined = "|".join(f"(?:{p})" for p in patterns)
        lines.append(f"    $e.{udm_field} = /{combined}/ nocase")
    else:
        # AND semantics (or a single condition either way): one predicate per line.
        for c in rule.conditions:
            pattern = _escape_regex_for_yaral(c.value)
            lines.append(f"    $e.{udm_field} = /{pattern}/ nocase")

    lines.append("")
    lines.append("  condition:")
    lines.append("    $e")
    lines.append("}")

    return "\n".join(lines)


def convert_rules(rules: list[AtrRule], udm_field: str = DEFAULT_UDM_FIELD) -> str:
    """Convert a list of ATR rules into one YARA-L file, rules separated by blank lines."""
    return "\n\n".join(convert_rule(r, udm_field) for r in rules) + "\n"
