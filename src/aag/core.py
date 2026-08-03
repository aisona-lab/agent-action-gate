"""The deliberately small, deterministic core of Agent Action Gate."""

from dataclasses import asdict, dataclass, field
from fnmatch import fnmatchcase
from hashlib import sha256
from contextlib import contextmanager
import json
from pathlib import Path
import secrets
import sqlite3
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

import yaml


EFFECTS = {"allow", "deny", "approval_required"}
SENSITIVE_KEYS = {"authorization", "password", "secret", "token", "api_key", "apikey"}


class PolicyError(ValueError):
    pass


class ApprovalRequired(RuntimeError):
    def __init__(self, decision: "Decision") -> None:
        self.decision = decision
        super().__init__(decision.reason)


@dataclass(frozen=True)
class ToolCall:
    tool: str
    action: str = "write"
    args: Dict[str, Any] = field(default_factory=dict)
    env: str = "development"
    task_id: str = "default"
    estimated_cost_usd: float = 0.0

    def __post_init__(self) -> None:
        for field_name in ("tool", "action", "env", "task_id"):
            if not isinstance(getattr(self, field_name), str) or not getattr(self, field_name):
                raise ValueError("%s must be a non-empty string" % field_name)
        if not isinstance(self.args, dict):
            raise ValueError("args must be a mapping")
        if isinstance(self.estimated_cost_usd, bool) or not isinstance(self.estimated_cost_usd, (int, float)) or self.estimated_cost_usd < 0:
            raise ValueError("estimated_cost_usd must be a non-negative number")

    def fingerprint(self) -> str:
        payload = asdict(self)
        return sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


@dataclass(frozen=True)
class Decision:
    effect: str
    rule_id: str
    reason: str
    approval_id: Optional[str] = None

    @property
    def allowed(self) -> bool:
        return self.effect == "allow"


@dataclass(frozen=True)
class Rule:
    id: str
    match: Dict[str, Any]
    effect: str
    reason: str


@dataclass(frozen=True)
class Policy:
    default_effect: str
    rules: Tuple[Rule, ...]
    max_tool_calls_per_task: Optional[int] = None
    max_estimated_cost_usd: Optional[float] = None
    redact: Tuple[str, ...] = ()

    @classmethod
    def from_file(cls, path: str) -> "Policy":
        with Path(path).open(encoding="utf-8") as policy_file:
            data = yaml.safe_load(policy_file) or {}
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Policy":
        defaults = data.get("defaults") or {}
        effect = defaults.get("effect")
        if effect not in EFFECTS:
            raise PolicyError("defaults.effect must be allow, deny, or approval_required")
        rules = []
        rule_ids = set()
        for item in data.get("rules") or []:
            if not isinstance(item, dict) or not item.get("id"):
                raise PolicyError("every rule needs a non-empty id")
            if item.get("effect") not in EFFECTS:
                raise PolicyError("rule %s has an invalid effect" % item["id"])
            if not isinstance(item.get("match", {}), dict):
                raise PolicyError("rule %s match must be a mapping" % item["id"])
            if item["id"] in rule_ids:
                raise PolicyError("rule ids must be unique")
            _validate_match(item["match"])
            rule_ids.add(item["id"])
            rules.append(Rule(item["id"], item.get("match", {}), item["effect"], item.get("reason", item["id"])))
        budgets = data.get("budgets") or {}
        calls = budgets.get("max_tool_calls_per_task")
        cost = budgets.get("max_estimated_cost_usd")
        if calls is not None and (not isinstance(calls, int) or calls < 1):
            raise PolicyError("max_tool_calls_per_task must be a positive integer")
        if cost is not None and (isinstance(cost, bool) or not isinstance(cost, (int, float)) or cost < 0):
            raise PolicyError("max_estimated_cost_usd must be a non-negative number")
        return cls(effect, tuple(rules), calls, float(cost) if cost is not None else None, tuple(data.get("redact") or ()))

    def decide(self, call: ToolCall, calls_used: int = 0, cost_used: float = 0.0) -> Decision:
        if self.max_tool_calls_per_task is not None and calls_used >= self.max_tool_calls_per_task:
            return Decision("deny", "budget-tool-calls", "Tool-call budget exhausted.")
        if self.max_estimated_cost_usd is not None and cost_used + call.estimated_cost_usd > self.max_estimated_cost_usd:
            return Decision("deny", "budget-cost", "Estimated-cost budget exceeded.")
        for rule in self.rules:
            if _matches(rule.match, call):
                return Decision(rule.effect, rule.id, rule.reason)
        return Decision(self.default_effect, "default", "No policy rule matched.")


def _matches(match: Dict[str, Any], call: ToolCall) -> bool:
    for field_name in ("tool", "action", "env"):
        expected = match.get(field_name)
        if expected is not None and not fnmatchcase(str(getattr(call, field_name)), str(expected)):
            return False
    for name, expected in (match.get("args") or {}).items():
        actual = call.args.get(name)
        if isinstance(expected, dict):
            if "gt" in expected and not (isinstance(actual, (int, float)) and actual > expected["gt"]):
                return False
            if "gte" in expected and not (isinstance(actual, (int, float)) and actual >= expected["gte"]):
                return False
            if "eq" in expected and actual != expected["eq"]:
                return False
        elif actual != expected:
            return False
    return True


def _validate_match(match: Dict[str, Any]) -> None:
    unknown = set(match) - {"tool", "action", "env", "args"}
    if unknown:
        raise PolicyError("unknown match fields: %s" % ", ".join(sorted(unknown)))
    args = match.get("args")
    if args is not None and not isinstance(args, dict):
        raise PolicyError("match.args must be a mapping")
    for name, condition in (args or {}).items():
        if not isinstance(condition, dict):
            continue
        unknown_condition = set(condition) - {"gt", "gte", "eq"}
        if not condition or unknown_condition:
            raise PolicyError("argument %s has an invalid condition" % name)
        for operator in ("gt", "gte"):
            if operator in condition and (isinstance(condition[operator], bool) or not isinstance(condition[operator], (int, float))):
                raise PolicyError("argument %s %s must be numeric" % (name, operator))


class AuditLog:
    def __init__(self, path: Optional[str], redact: Tuple[str, ...]) -> None:
        self.path = Path(path) if path else None
        self.redact = set(redact)
        self.events: List[Dict[str, Any]] = []

    def write(self, event: str, call: ToolCall, **extra: Any) -> None:
        record = {"event": event, "at": time.time(), "call": _redact(asdict(call), self.redact)}
        record.update(extra)
        self.events.append(record)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as output:
                output.write(json.dumps(record, sort_keys=True, default=str) + "\n")


def _redact(value: Any, paths: set, prefix: str = "") -> Any:
    if isinstance(value, dict):
        clean = {}
        for key, item in value.items():
            path = (prefix + "." if prefix else "") + key
            if _is_sensitive(key) or path in paths:
                clean[key] = "[REDACTED]"
            else:
                clean[key] = _redact(item, paths, path)
        return clean
    if isinstance(value, list):
        return [_redact(item, paths, prefix) for item in value]
    return value


def _is_sensitive(key: str) -> bool:
    lowered = key.lower()
    return lowered in SENSITIVE_KEYS or any(marker in lowered for marker in ("token", "secret", "password", "authorization"))


class Gate:
    """Thread-safe gate with optional SQLite state for budgets and approvals."""

    def __init__(self, policy: Policy, audit_path: Optional[str] = None, state_path: Optional[str] = None, approval_ttl_seconds: int = 600) -> None:
        if approval_ttl_seconds < 0:
            raise ValueError("approval_ttl_seconds must not be negative")
        self.policy = policy
        self.audit = AuditLog(audit_path, policy.redact)
        self._usage: Dict[str, Tuple[int, float]] = {}
        self._approvals: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._approval_ttl_seconds = approval_ttl_seconds
        self._db = sqlite3.connect(state_path, check_same_thread=False) if state_path else None
        if self._db:
            self._db.execute("CREATE TABLE IF NOT EXISTS aag_usage (task_id TEXT PRIMARY KEY, calls INTEGER NOT NULL, cost REAL NOT NULL)")
            self._db.execute("CREATE TABLE IF NOT EXISTS aag_approvals (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, status TEXT NOT NULL, token_hash TEXT, expires_at REAL NOT NULL)")
            self._db.commit()

    @classmethod
    def from_file(cls, path: str, audit_path: Optional[str] = None, state_path: Optional[str] = None, approval_ttl_seconds: int = 600) -> "Gate":
        return cls(Policy.from_file(path), audit_path, state_path, approval_ttl_seconds)

    def close(self) -> None:
        if self._db:
            self._db.close()
            self._db = None

    @contextmanager
    def _transaction(self):
        if self._db:
            self._db.execute("BEGIN IMMEDIATE")
        try:
            yield
        except Exception:
            if self._db:
                self._db.rollback()
            raise
        else:
            if self._db:
                self._db.commit()

    def _usage_for(self, task_id: str) -> Tuple[int, float]:
        if not self._db:
            return self._usage.get(task_id, (0, 0.0))
        row = self._db.execute("SELECT calls, cost FROM aag_usage WHERE task_id = ?", (task_id,)).fetchone()
        return (row[0], row[1]) if row else (0, 0.0)

    def _set_usage(self, task_id: str, calls: int, cost: float) -> None:
        if not self._db:
            self._usage[task_id] = (calls, cost)
            return
        self._db.execute("INSERT INTO aag_usage(task_id, calls, cost) VALUES (?, ?, ?) ON CONFLICT(task_id) DO UPDATE SET calls = excluded.calls, cost = excluded.cost", (task_id, calls, cost))

    def check(self, call: ToolCall) -> Decision:
        with self._lock:
            with self._transaction():
                calls, cost = self._usage_for(call.task_id)
                decision = self.policy.decide(call, calls, cost)
                if decision.effect == "approval_required":
                    decision = self._request_approval(call, decision)
                self.audit.write("decision", call, effect=decision.effect, rule_id=decision.rule_id, approval_id=decision.approval_id)
                return decision

    def _request_approval(self, call: ToolCall, decision: Decision) -> Decision:
        approval_id = "apr_" + secrets.token_urlsafe(12)
        approval = {"fingerprint": call.fingerprint(), "status": "pending", "token_hash": None, "expires_at": time.time() + self._approval_ttl_seconds}
        if self._db:
            self._db.execute("INSERT INTO aag_approvals(id, fingerprint, status, token_hash, expires_at) VALUES (?, ?, ?, ?, ?)", (approval_id, approval["fingerprint"], approval["status"], None, approval["expires_at"]))
        else:
            self._approvals[approval_id] = approval
        return Decision(decision.effect, decision.rule_id, decision.reason, approval_id)

    def approve(self, approval_id: str) -> str:
        with self._lock:
            with self._transaction():
                approval = self._approval(approval_id)
                if approval and approval["status"] == "pending" and approval["expires_at"] <= time.time():
                    self._update_approval(approval_id, "expired", approval["token_hash"])
                if not approval or approval["status"] != "pending" or approval["expires_at"] <= time.time():
                    raise PolicyError("approval is unavailable")
                token = secrets.token_urlsafe(24)
                self._update_approval(approval_id, "approved", _token_hash(token))
                return token

    def approval_status(self, approval_id: str) -> str:
        with self._lock:
            with self._transaction():
                approval = self._approval(approval_id)
                if not approval:
                    return "missing"
                if approval["status"] in {"pending", "approved"} and approval["expires_at"] <= time.time():
                    self._update_approval(approval_id, "expired", approval["token_hash"])
                    return "expired"
                return approval["status"]

    def _approval(self, approval_id: str) -> Optional[Dict[str, Any]]:
        if not self._db:
            return self._approvals.get(approval_id)
        row = self._db.execute("SELECT fingerprint, status, token_hash, expires_at FROM aag_approvals WHERE id = ?", (approval_id,)).fetchone()
        return None if not row else {"fingerprint": row[0], "status": row[1], "token_hash": row[2], "expires_at": row[3]}

    def _update_approval(self, approval_id: str, status: str, token_hash: Optional[str]) -> None:
        if self._db:
            self._db.execute("UPDATE aag_approvals SET status = ?, token_hash = ? WHERE id = ?", (status, token_hash, approval_id))
        else:
            self._approvals[approval_id].update(status=status, token_hash=token_hash)

    def _consume_approval(self, call: ToolCall, token: Optional[str]) -> bool:
        token_hash = _token_hash(token) if token else None
        if self._db:
            row = self._db.execute("SELECT id, fingerprint, status, expires_at FROM aag_approvals WHERE token_hash = ?", (token_hash,)).fetchone()
            if not row or row[1] != call.fingerprint() or row[2] != "approved" or row[3] <= time.time():
                return False
            self._update_approval(row[0], "consumed", token_hash)
            return True
        approval = next((item for item in self._approvals.values() if item["token_hash"] == token_hash), None)
        if not approval or approval["status"] != "approved" or approval["fingerprint"] != call.fingerprint() or approval["expires_at"] <= time.time():
            return False
        approval["status"] = "consumed"
        return True

    def execute(self, call: ToolCall, tool: Callable[..., Any], approval_token: Optional[str] = None) -> Any:
        with self._lock:
            with self._transaction():
                calls, cost = self._usage_for(call.task_id)
                decision = self.policy.decide(call, calls, cost)
                if decision.effect == "deny":
                    self.audit.write("blocked", call, effect="deny", rule_id=decision.rule_id)
                    raise PermissionError(decision.reason)
                if decision.effect == "approval_required" and not self._consume_approval(call, approval_token):
                    pending = self._request_approval(call, decision)
                    self.audit.write("blocked", call, effect="approval_required", rule_id=decision.rule_id, approval_id=pending.approval_id)
                    raise ApprovalRequired(pending)
                self._set_usage(call.task_id, calls + 1, cost + call.estimated_cost_usd)
                self.audit.write("executing", call, effect="allow", rule_id=decision.rule_id)
        try:
            result = tool(**call.args)
        except Exception as error:
            with self._lock:
                self.audit.write("failed", call, error=type(error).__name__)
            raise
        with self._lock:
            self.audit.write("completed", call)
        return result


def _token_hash(token: str) -> str:
    return sha256(token.encode()).hexdigest()
