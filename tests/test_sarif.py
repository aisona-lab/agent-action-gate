"""Offline SARIF 2.1.0 export tests (no network, no API keys)."""

import json
import unittest
from pathlib import Path

from aag import Gate, Policy, ToolCall
from aag.sarif import SARIF_VERSION, decision_to_sarif, decisions_to_sarif

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "sarif"
EXAMPLE_POLICY = ROOT / "examples" / "policy.yaml"

POLICY = {
    "defaults": {"effect": "deny"},
    "rules": [
        {"id": "read", "match": {"tool": "github.*", "action": "read"}, "effect": "allow", "reason": "reads ok"},
        {
            "id": "prod",
            "match": {"tool": "terraform.apply", "env": "production"},
            "effect": "approval_required",
            "reason": "needs human",
        },
        {
            "id": "dangerous-delete",
            "match": {"tool": "github.delete_*"},
            "effect": "deny",
            "reason": "Repository deletion is disabled.",
        },
    ],
}


class SarifExportTests(unittest.TestCase):
    def test_deny_emits_error_result(self):
        policy = Policy.from_dict(POLICY)
        call = ToolCall("github.delete_repository", args={"name": "demo"})
        decision = policy.decide(call)
        log = decision_to_sarif(decision, call)
        self.assertEqual(log["version"], SARIF_VERSION)
        self.assertEqual(log["version"], "2.1.0")
        results = log["runs"][0]["results"]
        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual(result["ruleId"], "dangerous-delete")
        self.assertEqual(result["level"], "error")
        self.assertIn("deletion", result["message"]["text"].lower())
        self.assertEqual(result["properties"]["aag.effect"], "deny")
        self.assertEqual(result["locations"][0]["logicalLocations"][0]["name"], "github.delete_repository")
        rules = log["runs"][0]["tool"]["driver"]["rules"]
        self.assertEqual(rules[0]["id"], "dangerous-delete")

    def test_allow_emits_empty_results(self):
        policy = Policy.from_dict(POLICY)
        call = ToolCall("github.get_repo", action="read")
        decision = policy.decide(call)
        self.assertEqual(decision.effect, "allow")
        log = decision_to_sarif(decision, call)
        self.assertEqual(log["version"], "2.1.0")
        self.assertEqual(log["runs"][0]["results"], [])
        self.assertEqual(log["runs"][0]["tool"]["driver"]["rules"], [])

    def test_approval_required_emits_warning(self):
        policy = Policy.from_dict(POLICY)
        call = ToolCall("terraform.apply", env="production")
        decision = policy.decide(call)
        self.assertEqual(decision.effect, "approval_required")
        log = decision_to_sarif(decision, call)
        result = log["runs"][0]["results"][0]
        self.assertEqual(result["level"], "warning")
        self.assertEqual(result["ruleId"], "prod")
        self.assertEqual(result["properties"]["aag.effect"], "approval_required")

    def test_golden_deny_fixture(self):
        gate = Gate.from_file(str(EXAMPLE_POLICY))
        call = ToolCall("github.delete_repository", args={"name": "demo"})
        actual = decision_to_sarif(gate.check(call), call)
        expected = json.loads((FIXTURES / "deny.sarif.json").read_text(encoding="utf-8"))
        self.assertEqual(actual, expected)

    def test_golden_allow_fixture(self):
        gate = Gate.from_file(str(EXAMPLE_POLICY))
        call = ToolCall("github.get_repo", action="read")
        actual = decision_to_sarif(gate.check(call), call)
        expected = json.loads((FIXTURES / "allow.sarif.json").read_text(encoding="utf-8"))
        self.assertEqual(actual, expected)

    def test_decisions_to_sarif_batches(self):
        policy = Policy.from_dict(POLICY)
        deny = policy.decide(ToolCall("github.delete_repository"))
        allow = policy.decide(ToolCall("github.get_repo", action="read"))
        log = decisions_to_sarif([(deny, None), (allow, None)])
        self.assertEqual(len(log["runs"][0]["results"]), 1)
        self.assertEqual(log["runs"][0]["results"][0]["level"], "error")


if __name__ == "__main__":
    unittest.main()
