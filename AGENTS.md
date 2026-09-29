# Agent guide (Agent Action Gate)

This repo is a deterministic authorization gate for AI agent tool calls. Policy is YAML; decisions are allow / deny / approval_required. There is no LLM in the authorization path.

## Hard constraints

- Do **not** change gate semantics in `src/aag/core.py` (EFFECTS, matching, approval TTL, budgets, audit redaction) unless a task explicitly asks for a semantic change with tests.
- Do **not** change `guarded_tool` env/action binding behavior in `src/aag/mcp.py` without an explicit task.
- Prefer harness work (docs, fixtures, evals, CI, tests) over refactors.
- No secrets in git. No new dependency without a one-line reason in the commit/PR body.
- English for code, commits, and PRs.

## Layout

| Path | Role |
|------|------|
| `src/aag/core.py` | Policy, Gate, ToolCall, Decision, budgets, approvals, audit |
| `src/aag/mcp.py` | `guarded_tool` wrapper (MCP SDK optional) |
| `src/aag/cli.py` | `aag policy-check`, `decide`, `serve-approvals` |
| `src/aag/approvals.py` | Local HTTP approval bridge on 127.0.0.1 |
| `examples/policy.yaml` | Canonical example policy used by evals |
| `tests/` | Unit tests (behavior guarantees) |
| `evals/` | Deterministic decision evals |
| `fixtures/` | Scenario packs consumed by the eval runner |
| `docs/FEATURE_MAP.md` | Feature → tests / evals / fixtures map |

## Commands (definition of done for harness)

```bash
pip install -e .
python -m unittest discover -s tests -v
PYTHONPATH=src python evals/run.py
```

Optional local checks:

```bash
aag policy-check examples/policy.yaml
aag decide examples/policy.yaml '{"tool":"terraform.apply","env":"production"}'
```

## Fixtures

Packs under `fixtures/{clean,deny,empty,malicious,boundary}/`:

- **clean** — matching allow rules
- **deny** — default deny and explicit deny rules
- **empty** — invalid/empty policy or ToolCall (expect errors)
- **malicious** — prompt text in args treated as data (not intent detection)
- **boundary** — `gt` thresholds and call/cost budgets

Each pack has `cases.json`. Optional `policy` paths are relative to the pack directory; omitted policy uses `examples/policy.yaml`.

## Before opening a PR

1. Run both unittest and evals; both must be green.
2. Leave a clean tree (no half-open work, no `.venv` committed).
3. Update `docs/FEATURE_MAP.md` when adding coverage.
