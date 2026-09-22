"""Parses ATR (Agent Threat Rules) YAML files into a minimal internal shape.

This only extracts the fields the YARA-L converter needs. It is not a full
ATR schema validator — see https://github.com/Agent-Threat-Rule/agent-threat-rules
for the authoritative spec (spec/atr-schema.yaml).
"""

from __future__ import annotations

import contextlib
import os as _os
import re as _re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

try:
    import re2 as _re2

    _RE2_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only when the optional dep is missing
    _RE2_AVAILABLE = False


class UnsupportedRuleError(Exception):
    """Raised when a rule uses a feature this converter doesn't handle yet."""


SUPPORTED_OPERATORS = {"regex"}

# \u-prefixed escapes are valid PCRE/JS regex syntax but are NOT a Unicode
# codepoint escape in RE2 — RE2 spells the same codepoint \x{XXXX}. A
# pattern using \uXXXX compiles under RE2 without error (the hex digits
# are read as literal characters) and then matches nothing resembling the
# intended codepoint. That is a silent-breakage case, not a compile error,
# so it has to be caught and rewritten before compilation, not just
# detected by it.
#
# Two source forms are handled:
#   \u{XXXXX}  — braced ES6/PCRE Unicode escape, 1-6 hex digits, the only
#                standard \u-form that can express a supplementary-plane
#                codepoint (e.g. U+E0001, above the \uFFFF BMP ceiling)
#                directly rather than as a UTF-16 surrogate pair
#   \uXXXX     — exactly 4 hex digits, BMP-only by definition
#
# A UTF-16 surrogate pair (two consecutive \uD800-\uDBFF / \uDC00-\uDFFF
# escapes representing one supplementary-plane codepoint together) is NOT
# recombined by this translator — that's a real gap, documented in the
# README, not a silent guess. A pattern relying on a surrogate pair will
# fail the RE2 compile check downstream rather than being mistranslated.
_UNICODE_ESCAPE_BRACED = _re.compile(r"\\u\{([0-9a-fA-F]{1,6})\}")
_UNICODE_ESCAPE_FIXED4 = _re.compile(r"\\u([0-9a-fA-F]{4})")


def translate_unicode_escapes(pattern: str) -> tuple[str, bool]:
    """Rewrite \\u{XXXXX} and \\uXXXX escapes to RE2's \\x{XXXX} form.

    Returns (translated_pattern, changed).
    """
    changed = False

    def _sub(m: _re.Match) -> str:
        nonlocal changed
        changed = True
        return f"\\x{{{m.group(1)}}}"

    pattern = _UNICODE_ESCAPE_BRACED.sub(_sub, pattern)
    pattern = _UNICODE_ESCAPE_FIXED4.sub(_sub, pattern)
    return pattern, changed


def check_embedded_newline(pattern: str) -> bool:
    """True if the pattern contains a literal newline or carriage return
    character (as opposed to an escaped \\n sequence). A YARA-L regex
    literal is /-delimited on one line; an embedded literal newline breaks
    parsing outright regardless of which regex engine is asked to compile
    the pattern itself.
    """
    return "\n" in pattern or "\r" in pattern


@contextlib.contextmanager
def _suppress_native_stderr():
    """Silence C++-level stderr logging from google-re2's underlying absl
    logging during a compile attempt.

    google-re2 logs a raw C++ log line to the real stderr file descriptor
    (fd 2) on every rejected pattern, bypassing Python's own stderr and
    any of its redirection. At the scale of a full ATR corpus scan
    (hundreds of rules, tens of expected rejections), that drowns out this
    tool's own "skipped: <reason>" messages in raw engine noise. This
    redirects fd 2 to /dev/null only for the duration of one compile call,
    then restores it — Python-level exceptions are unaffected and still
    propagate normally.
    """
    devnull_fd = _os.open(_os.devnull, _os.O_WRONLY)
    saved_fd = _os.dup(2)
    try:
        _os.dup2(devnull_fd, 2)
        yield
    finally:
        _os.dup2(saved_fd, 2)
        _os.close(saved_fd)
        _os.close(devnull_fd)


def compile_check(pattern: str) -> str | None:
    """Attempt to compile the pattern as RE2 (Chronicle's regex engine).

    Returns None if it compiles cleanly, or an error description if not.
    Falls back to a hand-rolled check for known-unsupported constructs when
    the google-re2 bindings aren't installed, since that's a strictly
    weaker but still useful signal — real compilation is preferred whenever
    it's available.
    """
    if _RE2_AVAILABLE:
        try:
            with _suppress_native_stderr():
                _re2.compile(pattern)
            return None
        except _re2.error as e:
            # re2.error carries its message as raw bytes; decode it so the
            # error reads as text rather than a Python bytes repr (b'...').
            msg = e.args[0] if e.args else str(e)
            if isinstance(msg, bytes):
                msg = msg.decode("utf-8", errors="replace")
            return msg

    return _fallback_construct_check(pattern)


# Fallback only: a hand-checked list of constructs RE2 rejects at compile
# time. This is what the converter used before a real RE2 engine was wired
# in, and it's kept only as a degraded mode for environments where
# google-re2 can't be installed. It catches fewer cases than real
# compilation (e.g. it won't catch a bad repeat-count ceiling), so
# compile_check() prefers the real engine whenever it's importable.
_RE2_UNSUPPORTED_PATTERNS = [
    (r"\(\?=", "lookahead (?=...)"),
    (r"\(\?!", "negative lookahead (?!...)"),
    (r"\(\?<=", "lookbehind (?<=...)"),
    (r"\(\?<!", "negative lookbehind (?<!...)"),
    (r"\\[1-9]", "numbered backreference (\\1 etc.)"),
    (r"\\k<", "named backreference (\\k<name>)"),
    (r"\(\?P=", "named backreference ((?P=name))"),
]


def _fallback_construct_check(pattern: str) -> str | None:
    for regex, description in _RE2_UNSUPPORTED_PATTERNS:
        if _re.search(regex, pattern):
            return f"uses {description}, which RE2 does not support"
    return None


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
    true_positives: list[str] = field(default_factory=list)
    true_negatives: list[str] = field(default_factory=list)
    source_path: str = ""
    translated_unicode_escapes: bool = False  # true if any condition's \uXXXX was rewritten


def load_rule(path: str | Path) -> AtrRule:
    path = Path(path)
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if data is None:
        raise UnsupportedRuleError(f"{path}: file is empty")
    if not isinstance(data, dict):
        raise UnsupportedRuleError(f"{path}: file does not contain a YAML mapping at the top level")
    if "id" not in data:
        raise UnsupportedRuleError(f"{path}: missing required field 'id'")

    detection = data.get("detection", {})
    raw_conditions = detection.get("conditions", [])
    if not raw_conditions:
        raise UnsupportedRuleError(f"{path}: no detection.conditions found")

    conditions = []
    any_translated = False
    for c in raw_conditions:
        op = c.get("operator", "")
        if op not in SUPPORTED_OPERATORS:
            raise UnsupportedRuleError(
                f"{path}: operator '{op}' is not supported yet "
                f"(supported: {sorted(SUPPORTED_OPERATORS)})"
            )
        value = c["value"]

        if check_embedded_newline(value):
            raise UnsupportedRuleError(
                f"{path}: condition contains a literal newline/carriage-return character "
                f"inside the regex value. This breaks YARA-L's /-delimited regex literal "
                f"regardless of engine — the source YAML needs fixing, not just the converter."
            )

        # Mechanically translate \uXXXX -> \x{XXXX} before validating, since
        # \uXXXX is silently-wrong-not-broken under RE2 (see
        # translate_unicode_escapes docstring): it compiles but matches
        # nothing resembling the intended codepoint.
        value, translated = translate_unicode_escapes(value)
        any_translated = any_translated or translated

        incompatible = compile_check(value)
        if incompatible:
            engine_note = "" if _RE2_AVAILABLE else " (checked against a known-construct list — install google-re2 for a real compile check)"
            raise UnsupportedRuleError(
                f"{path}: condition does not compile as RE2 (Chronicle's regex engine){engine_note}: "
                f"{incompatible}. This pattern would either fail to compile in Chronicle or "
                f"silently match differently than intended. Rewrite the pattern before converting."
            )

        conditions.append(
            Condition(field=c.get("field", "content"), operator=op, value=value)
        )

    references = data.get("references", {}) or {}
    test_cases = data.get("test_cases", {}) or {}

    return AtrRule(
        id=data["id"],
        title=data.get("title", data["id"]),
        description=(data.get("description") or "").strip(),
        severity=data.get("severity", "medium"),
        conditions=conditions,
        condition_logic=detection.get("condition", "any"),
        mitre_atlas=references.get("mitre_atlas", []) or [],
        owasp_agentic=references.get("owasp_agentic", []) or [],
        true_positives=test_cases.get("true_positives", []) or [],
        true_negatives=test_cases.get("true_negatives", []) or [],
        source_path=str(path),
        translated_unicode_escapes=any_translated,
    )


def load_rules_from_directory(directory: str | Path) -> tuple[list[AtrRule], list[tuple[str, str]]]:
    """Load every .yaml/.yml rule under a directory.

    Returns (loaded_rules, skipped) where skipped is a list of
    (path, reason) for rules this converter can't handle yet — most
    commonly a non-regex operator or a pattern that doesn't compile as RE2.
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
