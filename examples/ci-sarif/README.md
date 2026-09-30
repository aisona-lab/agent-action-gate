# Example: SARIF upload in GitHub Actions

Demo workflow that runs **Agent Action Gate** offline on fixture tool-calls,
writes a SARIF 2.1.0 log (`aag decide` / `decisions_to_sarif`), and uploads it
with `github/codeql-action/upload-sarif` so deny / approval findings can appear
under the repository **Security → Code scanning** tab.

This is **not** CodeQL analysis and does not claim CodeQL equivalence. It is a
policy-gate export in SARIF form for CI / hiring demos.

## Constraints

- No LLM keys; no Anthropic / Grok (or other) API calls in CI
- Install from **this repository** (`pip install -e .`), not live PyPI
- Does not change core gate semantics (`src/aag/core.py`)

## Layout

| Path | Role |
|------|------|
| `policy.yaml` | Demo policy (deny delete, allow github read, approval for prod terraform) |
| `calls/*.json` | Fixture `ToolCall` objects (includes at least one deny) |
| `generate_sarif.py` | Evaluate all calls → combined SARIF |
| `run.sh` | Editable install from repo root + generate |

## Local

```bash
# from repo root
./examples/ci-sarif/run.sh /tmp/aag-example.sarif
# or:
pip install -e .
python examples/ci-sarif/generate_sarif.py --out /tmp/aag-example.sarif
```

Expect stderr lines for each call (`deny-delete.json -> deny (...)`) and at least
one SARIF result with `"level": "error"` for the deny.

## CI

Workflow: [`.github/workflows/example-sarif.yml`](../../.github/workflows/example-sarif.yml)

- Triggers: `workflow_dispatch`, and push / pull_request path-filtered to this
  example, the workflow file, and `src/aag/**`
- Permissions: `contents: read`, `security-events: write`
- **SARIF upload** runs on `push` to `main` and on `workflow_dispatch` from this
  repo. Pull requests still generate SARIF (artifact) but skip upload when the
  head is a fork (GitHub often denies `security-events` write on fork PRs).
- Visibility: GitHub may only show third-party code scanning results on the
  **default branch**, and only when code scanning is available for the repo
  (public repos, or private with GitHub Advanced Security).

Main [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) stays keyless
and unchanged by this example.
