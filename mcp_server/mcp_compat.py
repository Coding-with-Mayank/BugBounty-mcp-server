"""
mcp_compat.py — one registration path for both MCP Python SDK generations.

The SDK changed how a low-level Server learns its handlers:

  1.x   @server.list_tools() / @server.call_tool()  decorators
  2.x   decorators removed; handlers are registered by method name with
        add_request_handler(method, params_model, handler(ctx, params))

Everything else this project uses (Server, stdio_server, create_initialization_options,
server.run, mcp.types.Tool/TextContent) is unchanged across the two, so this
module only bridges registration and keeps one behaviour 1.x gave for free:
tool arguments are validated against the tool's inputSchema before the handler runs.
"""
from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from importlib import metadata
from typing import Any

import mcp.types as types
from mcp.server import Server


def sdk_major() -> int:
    try:
        return int(metadata.version("mcp").split(".")[0])
    except (metadata.PackageNotFoundError, ValueError):
        return 1


MCP_MAJOR = sdk_major()

ListToolsFn = Callable[[], Awaitable[list[types.Tool]]]
CallToolFn = Callable[[str, dict | None], Awaitable[Sequence[types.TextContent]]]


def _validation_error(tools: Sequence[types.Tool], name: str, arguments: dict | None) -> str | None:
    """jsonschema validation, matching the 1.x low-level server's behaviour/message."""
    import jsonschema

    tool = next((t for t in tools if t.name == name), None)
    # The field is `inputSchema` on SDK 1.x and `input_schema` on 2.x.
    schema = (getattr(tool, "input_schema", None) or getattr(tool, "inputSchema", None)) if tool else None
    if not schema:
        return None            # unknown tool: the handler reports it in its own words
    try:
        jsonschema.validate(arguments or {}, schema)
    except jsonschema.ValidationError as exc:
        return f"Input validation error: {exc.message}"
    except jsonschema.SchemaError:
        return None
    return None


def register_tools(server: Server, list_tools: ListToolsFn, call_tool: CallToolFn,
                   tools: Sequence[types.Tool]) -> None:
    """Attach the project's tool handlers to `server` on whichever SDK is installed."""
    if MCP_MAJOR >= 2:
        async def _list(_ctx: Any, _params: Any) -> types.ListToolsResult:
            return types.ListToolsResult(tools=list(await list_tools()))

        async def _call(_ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
            err = _validation_error(tools, params.name, params.arguments)
            if err:
                return types.CallToolResult(content=[types.TextContent(type="text", text=err)], is_error=True)
            content = await call_tool(params.name, params.arguments)
            return types.CallToolResult(content=list(content))

        v2: Any = server                      # add_request_handler exists only on 2.x
        v2.add_request_handler("tools/list", types.PaginatedRequestParams, _list)
        v2.add_request_handler("tools/call", types.CallToolRequestParams, _call)
    else:
        v1: Any = server                      # the decorator API exists only on 1.x (absent from 2.x's types)
        v1.list_tools()(list_tools)
        v1.call_tool()(call_tool)
