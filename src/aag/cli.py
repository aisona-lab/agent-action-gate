import argparse
import json

from .core import Gate, Policy, ToolCall
from .approvals import ApprovalServer


def main() -> None:
    parser = argparse.ArgumentParser(prog="aag", description="Check agent tool calls against a policy.")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("policy-check", help="validate a policy file")
    check.add_argument("policy")
    decide = sub.add_parser("decide", help="evaluate a call JSON object")
    decide.add_argument("policy")
    decide.add_argument("call", help="JSON object with tool, action, args, env and task_id")
    serve = sub.add_parser("serve-approvals", help="serve local human approvals on 127.0.0.1")
    serve.add_argument("policy")
    serve.add_argument("--state", default="aag.db", help="SQLite state path (default: aag.db)")
    serve.add_argument("--port", type=int, default=8787)
    args = parser.parse_args()
    if args.command == "policy-check":
        Policy.from_file(args.policy)
        print("valid")
        return
    if args.command == "serve-approvals":
        server = ApprovalServer(Gate.from_file(args.policy, state_path=args.state), ("127.0.0.1", args.port))
        print("serving local approvals on http://127.0.0.1:%d" % server.server_port)
        server.serve_forever()
        return
    gate = Gate.from_file(args.policy)
    decision = gate.check(ToolCall(**json.loads(args.call)))
    print(json.dumps(decision.__dict__, sort_keys=True))


if __name__ == "__main__":
    main()
