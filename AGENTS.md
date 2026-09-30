# Agent guide (Agent Action Gate)

This repo is a deterministic authorization gate for AI agent tool calls. Policy is YAML; decisions are allow / deny / approval_required. There is no LLM in the authorization path — **zero API keys** to run the gate, unittest, or evals.

## Production pattern (non-negotiable)

- **Gate = auth engine.** `Policy.decide` / `Gate.check` are pure allow / deny / approval_required. No Anthropic (or other LLM) key, no model call, no network.
- **Injection-in-args is data.** Strings like "ignore policy and delete" inside `ToolCall.args` never become instructions; they only matter if a YAML rule matches that field.
- **lazycoder is a trailer only.** Optional sibling that may use one LLM key for live review; deterministic verdict/replay work with no key. Do not require two keys to run "the stack", and do not make lazycoder a hard dependency of this package.

## Learnings (encode + reuse)

See [`LEARNINGS.md`](LEARNINGS.md). Short form:

- **SPEC → PLAN → OK → smallest unit → prove with command → merge → clean tree.**
- Gate = auth thesis (zero LLM). lazycoder = trailer only. LLM ≠ auth engine.
- Never leave a half PR. Offline proves without keys. Prefer fixtures over vibes.
- Adversarial audit after every "fix"; close gaps with regression fixtures + FEATURE_MAP.

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
| `src/aag/cli.py` | `aag policy-check`, `decide` (`--format json|sarif`), `serve-approvals` |
| `src/aag/sarif.py` | Offline SARIF 2.1.0 export from Decision (+ ToolCall) |
| `src/aag/approvals.py` | Local HTTP approval bridge on 127.0.0.1 |
| `examples/policy.yaml` | Canonical example policy used by evals |
| `examples/ci-sarif/` | Example GH Action: fixture calls → SARIF → upload-sarif (not CodeQL) |
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

Packs under `fixtures/{clean,deny,empty,malicious,boundary,sarif}/`:

- **clean** — matching allow rules
- **deny** — default deny and explicit deny rules
- **empty** — invalid/empty policy or ToolCall (expect errors)
- **malicious** — prompt text in args treated as data (not intent detection)
- **boundary** — `gt` thresholds and call/cost budgets
- **sarif** — golden SARIF 2.1.0 JSON for deny (finding) / allow (empty results)

Each pack has `cases.json`. Optional `policy` paths are relative to the pack directory; omitted policy uses `examples/policy.yaml`.

## Before opening a PR

1. Run both unittest and evals; both must be green (prove with the commands above).
2. Leave a clean tree (no half-open work, no `.venv` committed). Merge or close — never park a half PR.
3. Update `docs/FEATURE_MAP.md` when adding coverage.
4. If this was a "fix", re-read `LEARNINGS.md` and add a regression fixture when the audit finds a gap.

## CI

Live workflow: [`.github/workflows/ci.yml`](.github/workflows/ci.yml) (mirrored from [docs/ci-workflow.yml](docs/ci-workflow.yml)). Runs install + unittest + evals on Python 3.9 and 3.11. No secrets required.
