"""A deliberately local HTTP bridge for human approval workflows."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from typing import Tuple
from urllib.parse import urlparse

from .core import Gate, PolicyError


class ApprovalServer(ThreadingHTTPServer):
    def __init__(self, gate: Gate, address: Tuple[str, int] = ("127.0.0.1", 8787)) -> None:
        self.gate = gate
        super().__init__(address, _handler)


class _handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        approval_id = _approval_id(self.path)
        if not approval_id:
            self._json(404, {"error": "not found"})
            return
        status = self.server.gate.approval_status(approval_id)
        self._json(404 if status == "missing" else 200, {"approval_id": approval_id, "status": status})

    def do_POST(self) -> None:
        approval_id = _approval_id(self.path, "/approve")
        if not approval_id:
            self._json(404, {"error": "not found"})
            return
        try:
            token = self.server.gate.approve(approval_id)
        except PolicyError as error:
            self._json(409, {"error": str(error)})
            return
        self._json(200, {"approval_id": approval_id, "token": token})

    def log_message(self, format: str, *args: object) -> None:
        return

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _approval_id(path: str, suffix: str = "") -> str:
    route = urlparse(path).path
    prefix = "/approvals/"
    if not route.startswith(prefix) or (suffix and not route.endswith(suffix)):
        return ""
    approval_id = route[len(prefix):len(route) - len(suffix) if suffix else None]
    return approval_id if approval_id and "/" not in approval_id else ""
