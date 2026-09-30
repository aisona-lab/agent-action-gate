# Feature map

Maps Gate / Policy / CLI / MCP surfaces to unit tests, eval cases, and fixture packs. Harness-only: does not define new gate semantics.

**Production pattern:** the gate has **zero LLM dependency**. Authorization is
deterministic YAML (`Policy.decide`); prompt / LLM text in `ToolCall.args` is
untrusted data (see `malicious/` + `test_llm_text_in_args_does_not_change_decide`).
[lazycoder](https://github.com/aisona-lab/lazycoder) is a trailer-only sibling —
optional LLM analysis, deterministic verdict/replay — not an auth engine and
not required to run this package.

Process lessons: [`LEARNINGS.md`](../LEARNINGS.md) (SPEC→PLAN→OK→prove→merge; gate=auth thesis, zero LLM).

## Core (`src/aag/core.py`)

| Feature | Unit tests | Evals (`evals/cases.json`) | Fixtures |
|---------|------------|----------------------------|----------|
| Allow via tool/action match | (via execute paths) | `allow-read` | `clean/` |
| Default deny when no rule matches | `test_denied_tool_does_not_run` | `deny-default` | `deny/` |
| Explicit deny rule (`github.delete_*`) | `test_denied_tool_does_not_run` | — | `deny/` |
| `approval_required` (env / args) | `test_approval_*`, `test_execute_creates_*` | `approval-prod`, `approval-large-refund` | `boundary/` |
| Args `gt` numeric match | — | `approval-large-refund`, `bad-refund-amount-denies` | `boundary/` |
| Non-numeric `gt` operand does not match | — | `bad-refund-amount-denies` | `boundary/` |
| Prompt text in args is data only | `test_llm_text_in_args_does_not_change_decide` | `injection-is-data` | `malicious/` |
| Tool-call budget | `test_budget_blocks_second_execution`, SQLite concurrency | `tool-budget` | `boundary/` |
| Estimated-cost budget | `test_invalid_tool_call_cannot_lower_a_budget` | `cost-budget` | `boundary/` |
| Invalid policy rejected | `test_invalid_policy_conditions_are_rejected` | — | `empty/` |
| Invalid ToolCall rejected | `test_invalid_tool_call_cannot_lower_a_budget` | — | `empty/` |
| Approval single-use + call binding | `test_approval_is_single_use`, `test_approval_token_is_bound_*` | — | — |
| Approval TTL / expiry | `test_expired_approval_is_rejected` | — | — |
| Audit redaction | `test_audit_redacts_*` | — | — |
| SQLite persistence | `test_sqlite_persists_*`, `test_sqlite_budget_*` | — | — |

## MCP (`src/aag/mcp.py`)

| Feature | Unit tests | Evals | Fixtures |
|---------|------------|-------|----------|
| `guarded_tool` blocks before callable runs | `test_mcp_compatible_wrapper_blocks_before_the_tool_runs` | — | — |
| Env/action bound at wrap time | covered by wrapper constructing `ToolCall` | — | — |

## CLI (`src/aag/cli.py`) / approvals HTTP

| Feature | Unit tests | Evals | Fixtures |
|---------|------------|-------|----------|
| Local approval HTTP approve flow | `test_local_http_server_approves_a_call` | — | — |
| `aag policy-check` / `decide` | manual / CI can invoke policy-check on example | fixture policies validated via runner | `empty/` (invalid) |
| `decide --format sarif` (SARIF 2.1.0 export) | `tests/test_sarif.py` | — | `fixtures/sarif/` |


## Example CI SARIF upload (`examples/ci-sarif/`)

| Feature | Tests / proof | Notes |
|---------|---------------|-------|
| Offline decide → SARIF + upload-sarif workflow | `examples/ci-sarif/`, `.github/workflows/example-sarif.yml` | Demo only; not CodeQL. Path-filtered + `workflow_dispatch`. Upload on main push / dispatch; PRs artifact only. Example adds physicalLocation for GitHub. Main `ci.yml` unchanged / keyless. |

## How to run

```bash
pip install -e .
python -m unittest discover -s tests -v
PYTHONPATH=src python evals/run.py
```

CI: `.github/workflows/ci.yml` (source template `docs/ci-workflow.yml`). Runs install + unittest + evals on Python 3.9 and 3.11. No API keys.
