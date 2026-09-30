#!/usr/bin/env python3
"""Offline: evaluate fixture tool-calls and write a combined SARIF 2.1.0 log.

No LLM keys, no network. Uses Gate.check + aag.sarif.decisions_to_sarif only.

GitHub code scanning requires a physicalLocation on each result; the core
export uses logicalLocations (tool name). This example adds a physical
location pointing at the fixture call JSON so upload-sarif can process the
file. That is CI/demo packaging — not a change to Gate / Policy semantics.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

from aag import Gate, ToolCall
from aag.core import Decision
from aag.sarif import decisions_to_sarif

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
DEFAULT_POLICY = HERE / "policy.yaml"
DEFAULT_CALLS = HERE / "calls"


def _load_call(path: Path) -> ToolCall:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit("call file must be a JSON object: %s" % path)
    return ToolCall(**data)


def _with_physical_locations(
    log: Dict[str, Any],
    finding_uris: List[str],
) -> Dict[str, Any]:
    """Attach artifact URIs for GitHub code scanning (physicalLocation required)."""
    results = log["runs"][0]["results"]
    if len(results) != len(finding_uris):
        raise SystemExit(
            "internal error: %d results vs %d finding uris" % (len(results), len(finding_uris))
        )
    for result, uri in zip(results, finding_uris):
        physical = {
            "artifactLocation": {"uri": uri},
            "region": {"startLine": 1},
        }
        locations = result.setdefault("locations", [])
        if locations:
            locations[0]["physicalLocation"] = physical
        else:
            locations.append({"physicalLocation": physical})
    return log


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate SARIF from ci-sarif fixture calls")
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--calls-dir", type=Path, default=DEFAULT_CALLS)
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("aag-example.sarif"),
        help="output SARIF path (default: aag-example.sarif)",
    )
    args = parser.parse_args()

    if not args.policy.is_file():
        print("error: policy not found: %s" % args.policy, file=sys.stderr)
        return 1
    call_files = sorted(args.calls_dir.glob("*.json"))
    if not call_files:
        print("error: no call JSON files under %s" % args.calls_dir, file=sys.stderr)
        return 1

    gate = Gate.from_file(str(args.policy))
    items: List[Tuple[Decision, ToolCall]] = []
    finding_uris: List[str] = []
    for path in call_files:
        call = _load_call(path)
        decision = gate.check(call)
        items.append((decision, call))
        print(
            "%s -> %s (%s)" % (path.name, decision.effect, decision.rule_id),
            file=sys.stderr,
        )
        if decision.effect != "allow":
            try:
                uri = path.resolve().relative_to(REPO_ROOT.resolve()).as_posix()
            except ValueError:
                uri = path.name
            finding_uris.append(uri)

    log = _with_physical_locations(decisions_to_sarif(items), finding_uris)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(log, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    findings = len(log["runs"][0]["results"])
    print("wrote %s (%d finding(s))" % (args.out, findings), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
