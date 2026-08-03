import unittest
from tempfile import TemporaryDirectory
from threading import Barrier, Thread
from urllib.request import Request, urlopen
import json

from aag import ApprovalRequired, ApprovalServer, Gate, Policy, PolicyError, ToolCall, guarded_tool


POLICY = {
    "defaults": {"effect": "deny"},
    "rules": [
        {"id": "read", "match": {"tool": "github.*", "action": "read"}, "effect": "allow"},
        {"id": "prod", "match": {"tool": "terraform.apply", "env": "production"}, "effect": "approval_required"},
    ],
    "budgets": {"max_tool_calls_per_task": 1, "max_estimated_cost_usd": 1},
    "redact": ["args.customer.email"],
}


class GateTests(unittest.TestCase):
    def setUp(self):
        self.gate = Gate(Policy.from_dict(POLICY))

    def test_denied_tool_does_not_run(self):
        called = []
        with self.assertRaises(PermissionError):
            self.gate.execute(ToolCall("github.delete_repository"), lambda: called.append(True))
        self.assertEqual(called, [])

    def test_approval_is_single_use(self):
        self.gate = Gate(Policy.from_dict({**POLICY, "budgets": {"max_tool_calls_per_task": 2, "max_estimated_cost_usd": 1}}))
        call = ToolCall("terraform.apply", args={"plan": "prod"}, env="production")
        decision = self.gate.check(call)
        token = self.gate.approve(decision.approval_id)
        self.assertEqual(self.gate.execute(call, lambda plan: plan, token), "prod")
        with self.assertRaises(ApprovalRequired):
            self.gate.execute(call, lambda plan: plan, token)

    def test_approval_token_is_bound_to_the_exact_call(self):
        call = ToolCall("terraform.apply", args={"plan": "safe"}, env="production")
        token = self.gate.approve(self.gate.check(call).approval_id)
        changed = ToolCall("terraform.apply", args={"plan": "dangerous"}, env="production")
        with self.assertRaises(ApprovalRequired):
            self.gate.execute(changed, lambda plan: plan, token)
        self.assertEqual(self.gate.execute(call, lambda plan: plan, token), "safe")

    def test_execute_creates_a_usable_approval_request(self):
        call = ToolCall("terraform.apply", args={"plan": "prod"}, env="production")
        with self.assertRaises(ApprovalRequired) as pending:
            self.gate.execute(call, lambda plan: plan)
        token = self.gate.approve(pending.exception.decision.approval_id)
        self.assertEqual(self.gate.execute(call, lambda plan: plan, token), "prod")

    def test_budget_blocks_second_execution(self):
        call = ToolCall("github.get_repo", action="read")
        self.assertEqual(self.gate.execute(call, lambda: "ok"), "ok")
        with self.assertRaises(PermissionError):
            self.gate.execute(call, lambda: "must not run")

    def test_audit_redacts_nested_and_standard_secret_keys(self):
        gate = Gate(Policy.from_dict(POLICY))
        call = ToolCall("github.get_repo", action="read", args={"token": "top-secret", "customer": {"email": "a@b.c"}})
        gate.execute(call, lambda token, customer: "ok")
        encoded = str(gate.audit.events)
        self.assertNotIn("top-secret", encoded)
        self.assertNotIn("a@b.c", encoded)

    def test_mcp_compatible_wrapper_blocks_before_the_tool_runs(self):
        calls = []

        @guarded_tool(self.gate, "github.delete_repository")
        def delete_repository(name):
            calls.append(name)
            return "deleted"

        with self.assertRaises(PermissionError):
            delete_repository("demo")
        self.assertEqual(calls, [])

    def test_sqlite_persists_approval_and_budget_without_storing_token(self):
        with TemporaryDirectory() as directory:
            path = directory + "/aag.db"
            call = ToolCall("terraform.apply", args={"plan": "prod"}, env="production")
            first = Gate(Policy.from_dict(POLICY), state_path=path)
            approval_id = first.check(call).approval_id
            first.close()
            second = Gate(Policy.from_dict(POLICY), state_path=path)
            token = second.approve(approval_id)
            self.assertEqual(second.execute(call, lambda plan: plan, token), "prod")
            self.assertNotIn(token, str(second._db.execute("SELECT token_hash FROM aag_approvals").fetchall()))
            second.close()

    def test_expired_approval_is_rejected(self):
        gate = Gate(Policy.from_dict(POLICY), approval_ttl_seconds=0)
        decision = gate.check(ToolCall("terraform.apply", env="production"))
        with self.assertRaises(PolicyError):
            gate.approve(decision.approval_id)
        self.assertEqual(gate.approval_status(decision.approval_id), "expired")

    def test_invalid_policy_conditions_are_rejected(self):
        invalid_policies = [
            {"defaults": {"effect": "deny"}, "rules": [{"id": "bad", "match": {"unknown": "x"}, "effect": "allow"}]},
            {"defaults": {"effect": "deny"}, "rules": [{"id": "bad", "match": {"args": {"amount": {"lt": 2}}}, "effect": "allow"}]},
            {"defaults": {"effect": "deny"}, "rules": [{"id": "same", "match": {}, "effect": "allow"}, {"id": "same", "match": {}, "effect": "deny"}]},
        ]
        for policy in invalid_policies:
            with self.assertRaises(PolicyError):
                Policy.from_dict(policy)

    def test_invalid_tool_call_cannot_lower_a_budget(self):
        with self.assertRaises(ValueError):
            ToolCall("github.get_repo", action="read", estimated_cost_usd=-1)
        with self.assertRaises(ValueError):
            ToolCall("github.get_repo", action="read", estimated_cost_usd=True)

    def test_audit_redacts_compound_secret_key(self):
        gate = Gate(Policy.from_dict(POLICY))
        call = ToolCall("github.get_repo", action="read", args={"access_token": "top-secret"})
        gate.execute(call, lambda access_token: "ok")
        self.assertNotIn("top-secret", str(gate.audit.events))

    def test_local_http_server_approves_a_call(self):
        gate = Gate(Policy.from_dict(POLICY))
        server = ApprovalServer(gate, ("127.0.0.1", 0))
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            call = ToolCall("terraform.apply", args={"plan": "prod"}, env="production")
            approval_id = gate.check(call).approval_id
            base = "http://127.0.0.1:%d/approvals/%s" % (server.server_port, approval_id)
            status = json.loads(urlopen(base).read())
            self.assertEqual(status["status"], "pending")
            approved = json.loads(urlopen(Request(base + "/approve", method="POST")).read())
            self.assertEqual(gate.execute(call, lambda plan: plan, approved["token"]), "prod")
        finally:
            server.shutdown()
            server.server_close()

    def test_sqlite_budget_allows_only_one_concurrent_execution(self):
        with TemporaryDirectory() as directory:
            path = directory + "/aag.db"
            first = Gate(Policy.from_dict(POLICY), state_path=path)
            second = Gate(Policy.from_dict(POLICY), state_path=path)
            call = ToolCall("github.get_repo", action="read", task_id="shared")
            barrier = Barrier(3)
            outcomes = []
            executed = []

            def attempt(gate):
                barrier.wait()
                try:
                    gate.execute(call, lambda: executed.append(True))
                    outcomes.append("allowed")
                except PermissionError:
                    outcomes.append("denied")

            threads = [Thread(target=attempt, args=(gate,)) for gate in (first, second)]
            for thread in threads:
                thread.start()
            barrier.wait()
            for thread in threads:
                thread.join()
            self.assertCountEqual(outcomes, ["allowed", "denied"])
            self.assertEqual(executed, [True])
            first.close()
            second.close()


if __name__ == "__main__":
    unittest.main()
