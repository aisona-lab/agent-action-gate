from pathlib import Path

from aag import ApprovalRequired, Gate, ToolCall


policy = Path(__file__).with_name("policy.yaml")
gate = Gate.from_file(str(policy), str(Path(__file__).with_name("audit.jsonl")))
call = ToolCall("terraform.apply", args={"plan": "prod.tfplan"}, env="production", task_id="deploy-42")

try:
    gate.execute(call, lambda plan: "applied " + plan)
except ApprovalRequired as pending:
    token = gate.approve(pending.decision.approval_id)
    print(gate.execute(call, lambda plan: "applied " + plan, token))
