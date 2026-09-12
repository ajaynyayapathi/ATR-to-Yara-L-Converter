"""Parses ATR (Agent Threat Rules) YAML files into a minimal internal shape.

This only extracts the fields the YARA-L converter needs. It is not a full
ATR schema validator — see https://github.com/Agent-Threat-Rule/agent-threat-rules
for the authoritative spec (spec/atr-schema.yaml).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


class UnsupportedRuleError(Exception):
    """Raised when a rule uses a feature this converter doesn't handle yet."""


SUPPORTED_OPERATORS = {"regex"}


@dataclass
class Condition:
    field: str
    operator: str
    value: str


@dataclass
class AtrRule:
    id: str
    title: str
    description: str
    severity: str
    conditions: list[Condition]
    condition_logic: str  # "all" or "any"
    mitre_atlas: list[str] = field(default_factory=list)
    owasp_agentic: list[str] = field(default_factory=list)
    source_path: str = ""


def load_rule(path: str | Path) -> AtrRule:
    path = Path(path)
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    detection = data.get("detection", {})
    raw_conditions = detection.get("conditions", [])
    if not raw_conditions:
        raise UnsupportedRuleError(f"{path}: no detection.conditions found")

    conditions = []
    for c in raw_conditions:
        op = c.get("operator", "")
        if op not in SUPPORTED_OPERATORS:
            raise UnsupportedRuleError(
                f"{path}: operator '{op}' is not supported yet "
                f"(supported: {sorted(SUPPORTED_OPERATORS)})"
            )
        conditions.append(
            Condition(field=c.get("field", "content"), operator=op, value=c["value"])
        )

    references = data.get("references", {}) or {}

    return AtrRule(
        id=data["id"],
        title=data.get("title", data["id"]),
        description=(data.get("description") or "").strip(),
        severity=data.get("severity", "medium"),
        conditions=conditions,
        condition_logic=detection.get("condition", "any"),
        mitre_atlas=references.get("mitre_atlas", []) or [],
        owasp_agentic=references.get("owasp_agentic", []) or [],
        source_path=str(path),
    )


def load_rules_from_directory(directory: str | Path) -> tuple[list[AtrRule], list[tuple[str, str]]]:
    """Load every .yaml/.yml rule under a directory.

    Returns (loaded_rules, skipped) where skipped is a list of
    (path, reason) for rules this converter can't handle yet — most
    commonly non-regex operators, which are out of scope for v1.
    """
    directory = Path(directory)
    loaded: list[AtrRule] = []
    skipped: list[tuple[str, str]] = []

    for path in sorted(directory.rglob("*.yaml")) + sorted(directory.rglob("*.yml")):
        try:
            loaded.append(load_rule(path))
        except UnsupportedRuleError as e:
            skipped.append((str(path), str(e)))
        except (KeyError, yaml.YAMLError) as e:
            skipped.append((str(path), f"parse error: {e}"))

    return loaded, skipped
