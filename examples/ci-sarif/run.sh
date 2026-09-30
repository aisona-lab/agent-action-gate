#!/usr/bin/env bash
# Local / CI helper: install from this repo (editable) and emit SARIF.
# No PyPI, no LLM keys, no Anthropic/Grok API calls.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

if command -v python >/dev/null 2>&1; then
  PYTHON=python
elif command -v python3 >/dev/null 2>&1; then
  PYTHON=python3
else
  echo "error: python or python3 not found on PATH" >&2
  exit 1
fi

OUT="${1:-aag-example.sarif}"

if ! "$PYTHON" -c "import aag" >/dev/null 2>&1; then
  echo "==> pip install -e . (repo root; not live PyPI)" >&2
  if ! "$PYTHON" -m pip install -e .; then
    echo "==> Editable install unavailable; using PYTHONPATH=src" >&2
    export PYTHONPATH="${ROOT}/src${PYTHONPATH:+:$PYTHONPATH}"
  fi
fi

"$PYTHON" examples/ci-sarif/generate_sarif.py --out "$OUT"
