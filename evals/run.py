"""Run deterministic eval cases and fixture packs."""

import json
from pathlib import Path

from aag import Gate, Policy, PolicyError, ToolCall


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_POLICY = ROOT / "examples" / "policy.yaml"
ERROR_TYPES = {"PolicyError": PolicyError, "ValueError": ValueError}


def _load_cases(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _policy_path(case, pack_dir: Path) -> Path:
    relative = case.get("policy")
    if not relative:
        return EXAMPLE_POLICY
    return (pack_dir / relative).resolve()


def _run_expect_error(case, pack_dir: Path) -> None:
    expected_name = case["expect_error"]
    expected = ERROR_TYPES[expected_name]
    if "policy" in case and "call" not in case:
        with _expect(expected, case["id"]):
            Policy.from_file(str(_policy_path(case, pack_dir)))
        return
    if "call" in case:
        policy_file = _policy_path(case, pack_dir) if case.get("policy") else None
        with _expect(expected, case["id"]):
            call = ToolCall(**case["call"])
            if policy_file is not None:
                gate = Gate.from_file(str(policy_file))
                gate.check(call)
        return
    raise AssertionError("%s: expect_error cases need policy and/or call" % case["id"])


class _expect:
    def __init__(self, exc_type, case_id):
        self.exc_type = exc_type
        self.case_id = case_id

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            raise AssertionError("%s: expected %s" % (self.case_id, self.exc_type.__name__))
        if not issubclass(exc_type, self.exc_type):
            return False
        return True


def _run_decision(case, pack_dir: Path) -> None:
    gate = Gate.from_file(str(_policy_path(case, pack_dir)))
    for prior in case.get("setup", []):
        gate.execute(ToolCall(**prior), lambda **arguments: None)
    decision = gate.check(ToolCall(**case["call"]))
    assert decision.effect == case["effect"], "%s: expected %s got %s (%s)" % (
        case["id"],
        case["effect"],
        decision.effect,
        decision,
    )


def run_case(case, pack_dir: Path) -> None:
    if "expect_error" in case:
        _run_expect_error(case, pack_dir)
    else:
        _run_decision(case, pack_dir)


def main() -> None:
    passed = 0
    for case in _load_cases(ROOT / "evals" / "cases.json"):
        run_case(case, ROOT / "evals")
        passed += 1

    fixtures_root = ROOT / "fixtures"
    for pack_dir in sorted(path for path in fixtures_root.iterdir() if path.is_dir()):
        cases_path = pack_dir / "cases.json"
        if not cases_path.exists():
            continue
        for case in _load_cases(cases_path):
            run_case(case, pack_dir)
            passed += 1

    print("%d evals passed" % passed)


if __name__ == "__main__":
    main()
