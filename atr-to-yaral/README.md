# atr-to-yaral

Convert [Agent Threat Rules (ATR)](https://github.com/Agent-Threat-Rule/agent-threat-rules) into [YARA-L 2.0](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax) rules for Google SecOps (Chronicle).

ATR is an open, MIT-licensed detection standard for AI agent threats, prompt injection, tool poisoning, context exfiltration, and more, with 680+ rules already adopted by Microsoft's Agent Governance Toolkit, Cisco AI Defense, and MISP. Chronicle has no native way to consume it. This closes that gap for the rules that matter most: the regex-based detections that make up the large majority of the ATR corpus.

This was prompted directly by an open, unresolved request on Google's own [`google/mcp-security` repository (issue #255)](https://github.com/google/mcp-security/issues/255), asking for a way to pull external rule packs like ATR into Chronicle through the SecOps MCP server. Nobody had built the conversion layer that request depends on. This is that layer.

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

## The assumption you need to check before deploying anything this generates

ATR rules match against agent-runtime content: LLM input, tool-call arguments, SKILL.md files. Chronicle's UDM has no standard field for that yet, because there is no standard way to ingest AI agent telemetry into Chronicle today. That's a real, currently-unsolved gap, not an oversight in this tool.

This converter defaults every generated rule to matching against `metadata.description`, a generic free-text field present on any UDM event. That is a placeholder, not a recommendation. Before you deploy generated rules:

1. Figure out how your agent/LLM telemetry is actually being ingested into Chronicle (custom parser, generic log forwarder, whatever you're using).
2. Identify which UDM field the relevant text lands in.
3. Re-run the converter with `--udm-field your.actual.field`.

Rules generated against the wrong field will compile and load into Chronicle without error and will never fire. Test against known-positive samples before trusting any of these in production.

## Scope (v1)

- **Supported**: ATR rules with `operator: regex` conditions, combined with either `condition: all` (AND, emitted as separate predicate lines) or `condition: any` (OR, emitted as a single alternated regex).
- **Not yet supported**: non-regex ATR operators (semantic similarity, structural checks against tool-call schemas). These get skipped with a reason printed to stderr rather than silently dropped or crashing the batch.
- **Not attempted**: multi-event correlation rules, ATR's `match`/window semantics, or outcome scoring. ATR rules are evaluated per-event; this converter produces single-event YARA-L rules to match that model.

## Contributing

The most useful contributions right now are support for additional ATR operators and real-world UDM field mappings from people who've actually ingested agent telemetry into Chronicle, if you have one that works, open a PR adding it to the README as a documented example. See `CONTRIBUTING.md`.

## License

MIT. See `LICENSE`.
