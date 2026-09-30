# SARIF golden fixtures

Offline SARIF 2.1.0 snapshots from `aag.sarif.decision_to_sarif` against `examples/policy.yaml`.

- `deny.sarif.json` — `github.delete_repository` → deny finding (level error)
- `allow.sarif.json` — `github.get_repo` read → empty results (clean)

```bash
PYTHONPATH=src python3 -m aag.cli decide examples/policy.yaml '{"tool":"github.delete_repository","args":{"name":"demo"}}' --format sarif
```
