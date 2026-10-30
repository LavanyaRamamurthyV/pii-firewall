# Contributing

Thanks for helping keep personal data out of AI tools.

## Ground rules

- **Never commit real personal data.** Use fake values: test card numbers like `4111 1111 1111 1111`, SSNs from `evals/generate.py`, `example.com` emails, `555-01xx` phone numbers.
- Detection changes go in **both** engines: `core/python/pii_firewall/detectors.py` and `core/js/pii-core.js`.
- Every detection change needs a case in `core/fixtures/cases.json` (both engines are tested against it).
- Run `./scripts/sync-core.sh` so the extension gets the updated JS core.

## Before opening a pull request

```bash
pytest core/python mcp-server
node --test core/js/test/core.test.js
python evals/run.py          # must pass the floors and show 100% parity
ruff check .
```

## Good first contributions

- New hard test cases (real-world formats the detector misses), added to `evals/generate.py`
- ID formats for other countries
- Adapters for more AI chat sites (add the URL to `extension/manifest.json` and check the composer works)
