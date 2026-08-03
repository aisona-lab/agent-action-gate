import json
from pathlib import Path

from aag import Gate, ToolCall


ROOT = Path(__file__).resolve().parents[1]
cases = json.loads((ROOT / "evals" / "cases.json").read_text())
for case in cases:
    gate = Gate.from_file(str(ROOT / "examples" / "policy.yaml"))
    for prior in case.get("setup", []):
        gate.execute(ToolCall(**prior), lambda **arguments: None)
    decision = gate.check(ToolCall(**case["call"]))
    assert decision.effect == case["effect"], "%s: %s" % (case["id"], decision)
print("%d evals passed" % len(cases))
