# atr-to-yaral

Convert [Agent Threat Rules (ATR)](https://github.com/Agent-Threat-Rule/agent-threat-rules) into [YARA-L 2.0](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax) rules for Google SecOps (Chronicle).

ATR is an open, MIT-licensed detection standard for AI agent threats, prompt injection, tool poisoning, context exfiltration, and more, with 680+ rules already adopted by Microsoft's Agent Governance Toolkit, Cisco AI Defense, and MISP. Chronicle has no native way to consume it. This closes that gap for the rules that matter most: the regex-based detections that make up the large majority of the ATR corpus.

This was prompted by a feature request on Google's own [`google/mcp-security` repository (issue #255)](https://github.com/google/mcp-security/issues/255), asking for a way to pull external rule packs like ATR into Chronicle through the SecOps MCP server. A Google maintainer closed it, pointing instead to `chronicle/detection-rules`' `content_manager` tooling as the right place for this. This project is the conversion layer that path still needed: something that turns ATR YAML into `.yaral` files `content_manager` can then validate and push.

## What it does

```bash
atr-to-yaral path/to/ATR-2026-00001-prompt-injection.yaml
```

Takes an ATR rule like this:

```yaml
title: Direct Prompt Injection via User Input
id: ATR-2026-00001
severity: high
detection:
  condition: any
  conditions:
    - field: content
      operator: regex
      value: "(?i)ignore\\s+(all\\s+)?(previous|prior|above)\\s+instructions"
    - field: content
      operator: regex
      value: "(?i)disregard\\s+(your|the)\\s+system\\s+prompt"
```

And produces a working YARA-L rule:

```
rule ATR_2026_00001 {
  meta:
    atr_id = "ATR-2026-00001"
    title = "Direct Prompt Injection via User Input"
    severity = "HIGH"
    mitre_atlas = "AML.T0051 - LLM Prompt Injection"
    source = "Converted from Agent Threat Rules (ATR) — https://github.com/Agent-Threat-Rule/agent-threat-rules"

  events:
    $e.metadata.description = /(?:(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions)|(?:(?i)disregard\s+(your|the)\s+system\s+prompt)/ nocase

  condition:
    $e
}
```

Point it at a whole directory of ATR rules and it converts every convertible one into a single YARA-L file, skipping and reporting anything it can't handle yet rather than failing the whole batch.

```bash
atr-to-yaral path/to/agent-threat-rules/rules/ -o chronicle_rules.yaral
```

## Deploying the output to a real Chronicle instance

This tool stops at generating `.yaral` files. To actually validate and push them into Chronicle, use Google's own [`chronicle/detection-rules`](https://github.com/chronicle/detection-rules), specifically the `tools/content_manager` CLI inside it. It handles YARA-L validation against a live instance, rule creation and versioning, and enable/disable/archive state, all via the SecOps REST API.

The full pipeline looks like this:

```
ATR YAML rules  →  atr-to-yaral  →  .yaral files  →  content_manager  →  live in Chronicle
```

```bash
atr-to-yaral path/to/agent-threat-rules/rules/ -o chronicle_rules.yaral
# then, using content_manager from chronicle/detection-rules:
# validate the generated rules compile before pushing anything
content_manager rules validate --file chronicle_rules.yaral
```

Validating your output this way is worth doing before trusting any generated rule: this project's own testing only confirms the output matches Google's documented YARA-L grammar, not that it compiles against a live instance. If you run generated rules through `content_manager` and hit a real compilation issue, please open one here, that's exactly the kind of gap this project needs found early.

## Install

```bash
pip install -r requirements.txt
python -m atr_to_yaral.cli --help
```

## Regex compatibility: RE2, not PCRE

Chronicle's YARA-L regex literals compile with [RE2](https://github.com/google/re2), the same engine behind Go's `regexp` package. RE2 does not support lookahead, lookbehind, or backreferences, and it spells Unicode codepoints differently than PCRE/JavaScript-style regex.

This converter validates every regex against a real RE2 engine (via [`google-re2`](https://pypi.org/project/google-re2/)) before emitting it, not just against a hand-picked list of unsupported constructs:

- **Unsupported constructs** (lookahead, lookbehind, backreferences, and anything else RE2's real compiler rejects) cause the rule to be skipped with the actual RE2 compiler error, not silently converted into something that will fail — or worse, silently misbehave — in Chronicle.
- **`\uXXXX` / `\u{XXXXX}` Unicode escapes** (valid in PCRE/JS, not a Unicode codepoint escape in RE2) are mechanically rewritten to RE2's `\x{XXXX}` form before validation. Left alone, these compile under RE2 without error but match nothing resembling the intended codepoint — a silent-breakage case, not a compile failure. A rule with a rewritten escape gets a `converter_note` in its generated meta block so this is visible in the output, not just in this README.
- **Embedded literal newlines** inside a regex value (most often introduced by a YAML block scalar in the source rule) are rejected outright. A YARA-L regex literal is `/`-delimited on a single line; a literal newline breaks that regardless of which engine is asked to compile it.

**Known gap:** a UTF-16 surrogate pair used to express a supplementary-plane codepoint (two consecutive `\uD800`–`\uDBFF` / `\uDC00`–`\uDFFF` escapes) is not recombined by this translator. A pattern relying on a surrogate pair fails the RE2 compile check rather than being mistranslated — the safer failure mode, but still a gap. Use the braced `\u{XXXXX}` form in your ATR source if you need a codepoint above U+FFFF.

## The assumption you need to check before deploying anything this generates

ATR rules match against agent-runtime content: LLM input, tool-call arguments, SKILL.md files. Chronicle's UDM has no standard field for that yet, because there is no standard way to ingest AI agent telemetry into Chronicle today. That's a real, currently-unsolved gap, not an oversight in this tool.

This converter defaults every generated rule to matching against `metadata.description`, a generic free-text field present on any UDM event. That is a placeholder, not a recommendation. Before you deploy generated rules:

1. Figure out how your agent/LLM telemetry is actually being ingested into Chronicle (custom parser, generic log forwarder, whatever you're using).
2. Identify which UDM field the relevant text lands in.
3. Re-run the converter with `--udm-field your.actual.field`.

Rules generated against the wrong field will compile and load into Chronicle without error and will never fire. Test against known-positive samples before trusting any of these in production.

## Canary testing

Every converted rule can be checked against the ATR source rule's own `test_cases.true_positives` / `true_negatives` with `--canary`. This catches a rule whose regex logic doesn't actually fire on the traffic it claims to detect — a real failure mode independent of whether the pattern compiles at all. It does not prove a rule fires in a live Chronicle instance; only `content_manager` against a real deployment does that.

## Scope (v1)

- **Supported**: ATR rules with `operator: regex` conditions, combined with either `condition: all` (AND, emitted as separate predicate lines) or `condition: any` (OR, emitted as a single alternated regex).
- **Not yet supported**: non-regex ATR operators (semantic similarity, structural checks against tool-call schemas). These get skipped with a reason printed to stderr rather than silently dropped or crashing the batch.
- **Not attempted**: multi-event correlation rules, ATR's `match`/window semantics, or outcome scoring. ATR rules are evaluated per-event; this converter produces single-event YARA-L rules to match that model.

## Contributing

The most useful contributions right now are support for additional ATR operators and real-world UDM field mappings from people who've actually ingested agent telemetry into Chronicle, if you have one that works, open a PR adding it to the README as a documented example. See `CONTRIBUTING.md`.

## License

MIT. See `LICENSE`.
