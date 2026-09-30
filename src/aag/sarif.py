"""Offline SARIF 2.1.0 export for Gate decisions (no network, no LLM)."""

from typing import Any, Dict, List, Optional, Sequence, Tuple

from .core import Decision, ToolCall

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "agent-action-gate"
TOOL_URI = "https://github.com/aisona-lab/agent-action-gate"

# Findings only for non-allow effects. Allow → empty results (clean scan).
_LEVEL = {
    "deny": "error",
    "approval_required": "warning",
}


def _location(call: ToolCall) -> Dict[str, Any]:
    return {
        "logicalLocations": [
            {
                "fullyQualifiedName": call.tool,
                "kind": "tool",
                "name": call.tool,
            }
        ],
        "message": {
            "text": "tool=%s action=%s env=%s" % (call.tool, call.action, call.env),
        },
    }


def _result(decision: Decision, call: Optional[ToolCall]) -> Optional[Dict[str, Any]]:
    level = _LEVEL.get(decision.effect)
    if level is None:
        return None
    properties: Dict[str, Any] = {
        "aag.effect": decision.effect,
        "aag.rule_id": decision.rule_id,
    }
    if decision.approval_id:
        properties["aag.approval_id"] = decision.approval_id
    result: Dict[str, Any] = {
        "level": level,
        "message": {"text": decision.reason},
        "properties": properties,
        "ruleId": decision.rule_id,
    }
    if call is not None:
        properties["aag.action"] = call.action
        properties["aag.env"] = call.env
        properties["aag.tool"] = call.tool
        result["locations"] = [_location(call)]
    return result


def decisions_to_sarif(
    items: Sequence[Tuple[Decision, Optional[ToolCall]]],
    *,
    tool_name: str = TOOL_NAME,
    tool_uri: str = TOOL_URI,
) -> Dict[str, Any]:
    """Map (Decision, optional ToolCall) pairs to a SARIF 2.1.0 log dict.

    Allow decisions produce no results. Deny → error; approval_required → warning.
    Does not alter Gate / Policy decision semantics.
    """
    results: List[Dict[str, Any]] = []
    rules_by_id: Dict[str, Dict[str, Any]] = {}
    for decision, call in items:
        item = _result(decision, call)
        if item is None:
            continue
        results.append(item)
        if decision.rule_id not in rules_by_id:
            rules_by_id[decision.rule_id] = {
                "defaultConfiguration": {"level": _LEVEL[decision.effect]},
                "id": decision.rule_id,
                "shortDescription": {"text": decision.reason},
            }
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "results": results,
                "tool": {
                    "driver": {
                        "informationUri": tool_uri,
                        "name": tool_name,
                        "rules": sorted(rules_by_id.values(), key=lambda rule: rule["id"]),
                    }
                },
            }
        ],
    }


def decision_to_sarif(
    decision: Decision,
    call: Optional[ToolCall] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Convenience wrapper for a single Decision (+ optional ToolCall)."""
    return decisions_to_sarif([(decision, call)], **kwargs)
