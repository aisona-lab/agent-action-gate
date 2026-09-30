#!/usr/bin/env bash
# Offline local proof: unit tests + evals (same as CI). No API keys required.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if command -v python >/dev/null 2>&1; then
  PYTHON=python
elif command -v python3 >/dev/null 2>&1; then
  PYTHON=python3
else
  echo "error: python or python3 not found on PATH" >&2
  exit 1
fi

if ! "$PYTHON" -c "import aag" >/dev/null 2>&1; then
  echo "==> Installing package editable (aag not importable)"
  if ! "$PYTHON" -m pip install -e .; then
    echo "==> Editable install unavailable; using PYTHONPATH=src"
    export PYTHONPATH="${ROOT}/src${PYTHONPATH:+:$PYTHONPATH}"
  fi
fi

echo "==> Unit tests"
"$PYTHON" -m unittest discover -s tests -v

echo "==> Evals and fixtures"
PYTHONPATH="${ROOT}/src${PYTHONPATH:+:$PYTHONPATH}" "$PYTHON" evals/run.py

echo "OK: unit tests + evals passed (offline, no ANTHROPIC_API_KEY)"
