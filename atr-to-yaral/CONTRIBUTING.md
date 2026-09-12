# Contributing

1. Run `pytest tests/` before opening a PR. All tests must pass.
2. New operator support needs a fixture in `tests/fixtures/` demonstrating a real ATR rule using it, plus a test.
3. If you've found a real UDM field mapping that works for your Chronicle ingestion pipeline, add it as a documented example in the README rather than changing the default, every environment's ingestion setup is different, and the default has to stay honestly a placeholder.
4. Keep the converter's output valid YARA-L. If you're unsure a generated rule actually compiles in Chronicle, say so in the PR description rather than asserting it does.
