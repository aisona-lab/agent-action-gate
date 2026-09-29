# agent-action-gate — delivery learnings

Short rules from the aisona-lab harness loop. This repo is the **auth thesis**.

## Delivery loop (non-negotiable)

**SPEC → PLAN → OK → smallest unit → prove with a command → merge → clean tree.**

1. Name the claim (e.g. "injection-in-args is data; decide is unchanged").
2. Plan the smallest harness change that proves it (fixture + test, not a rewrite).
3. Human OK when the change would touch gate semantics.
4. One concern per PR; never leave a half-merged branch.
5. Prove with real commands; merge only on green CI + clean tree.

## Architecture thesis

| Role | Meaning |
|------|---------|
| **This gate** | Authorization engine. Pure allow / deny / approval_required. **Zero** LLM keys. |
| **lazycoder** | Trailer only — optional sibling for LLM code review. Not required here. |
| Injection in `ToolCall.args` | Untrusted **data**. Never instructions. Match only if YAML says so. |

Do not make lazycoder a hard dependency. Do not put an LLM in the auth path.
Do not claim "the stack" needs two API keys.

## Offline proof (definition of done)

```bash
pip install -e .
python -m unittest discover -s tests -v
PYTHONPATH=src python evals/run.py
```

No secrets. No network. Prefer harness (docs, fixtures, evals, FEATURE_MAP, CI)
over changing `src/aag/core.py` unless the task explicitly asks for a semantic
change with tests.

## After every "fix"

Adversarial audit: deny + poison-in-args still denies; malicious pack treats
prompt text as data; empty/invalid policy fails loud. Close gaps with
**regression fixtures / unit tests**, then update `docs/FEATURE_MAP.md`.

## Honesty

- No fake precision elsewhere in the stack spills into this gate — decisions
  here are deterministic, not scored ML metrics.
- Leave a clean tree. English for code, commits, and PRs.
