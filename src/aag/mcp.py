"""MCP-compatible tool wrappers without making the MCP SDK a core dependency."""

from functools import wraps
import inspect
from typing import Any, Callable

from .core import Gate, ToolCall


def guarded_tool(
    gate: Gate,
    tool: str,
    *,
    action: str = "write",
    env: str = "development",
    task_id: str = "default",
    estimated_cost_usd: float = 0.0,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Wrap a callable before registering it with an MCP server.

    Use ``@mcp.tool()`` above this decorator. The wrapper preserves the
    function signature metadata FastMCP uses while making AAG the execution
    boundary.
    """

    def decorate(function: Callable[..., Any]) -> Callable[..., Any]:
        signature = inspect.signature(function)

        @wraps(function)
        def guarded(*args: Any, **kwargs: Any) -> Any:
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            call = ToolCall(tool, action, dict(bound.arguments), env, task_id, estimated_cost_usd)
            return gate.execute(call, lambda **arguments: function(**arguments))

        return guarded

    return decorate
