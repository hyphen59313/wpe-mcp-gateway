"""最小实现的 MCP 服务端核心（JSON-RPC 2.0）。

只依赖标准库：MCP 的 stdio 传输就是「一行一个 JSON-RPC 消息」，
因此不需要官方 SDK 也能实现一个完全合规的服务端。
"""

from __future__ import annotations

import json
import sys
import traceback
from typing import Any, Callable, Dict, Iterable, List, Optional

JSON = Dict[str, Any]

SUPPORTED_PROTOCOLS = ("2024-11-05", "2025-03-26", "2025-06-18")
DEFAULT_PROTOCOL = "2025-06-18"

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


class ToolError(Exception):
    """工具执行失败，会作为 isError=true 的正常结果返回给客户端。"""

    def __init__(self, message: str, *, hint: Optional[str] = None) -> None:
        super().__init__(message)
        self.hint = hint


class Tool:
    def __init__(
        self,
        name: str,
        description: str,
        input_schema: Optional[JSON],
        handler: Callable[[JSON], Any],
        mutating: bool = False,
    ) -> None:
        self.name = name
        self.description = description
        self.input_schema = input_schema or {"type": "object", "properties": {}}
        self.handler = handler
        self.mutating = mutating

    def descriptor(self) -> JSON:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


class Registry:
    def __init__(self) -> None:
        self._tools: Dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def add(
        self,
        name: str,
        description: str,
        input_schema: Optional[JSON] = None,
        mutating: bool = False,
    ) -> Callable[[Callable[[JSON], Any]], Callable[[JSON], Any]]:
        def wrapper(fn: Callable[[JSON], Any]) -> Callable[[JSON], Any]:
            self.register(Tool(name, description, input_schema, fn, mutating))
            return fn

        return wrapper

    def get(self, name: str) -> Optional[Tool]:
        return self._tools.get(name)

    def names(self) -> List[str]:
        return sorted(self._tools)

    def descriptors(self) -> List[JSON]:
        return [t.descriptor() for t in self._tools.values()]

    def __iter__(self) -> Iterable[Tool]:
        return iter(self._tools.values())


def _text_result(payload: Any, is_error: bool = False) -> JSON:
    if isinstance(payload, str):
        text = payload
    else:
        text = json.dumps(payload, ensure_ascii=False, indent=2, default=str)
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


class McpServerCore:
    """把 Registry 里的工具暴露成一个 MCP 服务端。"""

    def __init__(self, name: str, version: str, registry: Registry, log=None) -> None:
        self.name = name
        self.version = version
        self.registry = registry
        self.log = log or (lambda *a, **k: None)
        self.protocol_version = DEFAULT_PROTOCOL
        self.client_info: JSON = {}

    # ---- 协议入口 -------------------------------------------------
    def handle(self, message: Any) -> Optional[JSON]:
        if not isinstance(message, dict) or "method" not in message:
            if isinstance(message, dict) and "id" in message:
                return self._error(message.get("id"), INVALID_REQUEST, "Invalid Request")
            return None

        msg_id = message.get("id")
        method = message.get("method")
        params = message.get("params") or {}

        if msg_id is None:  # 通知，不需要返回
            self._handle_notification(method, params)
            return None

        handler = getattr(self, "_m_" + method.replace("/", "_"), None)
        if handler is None:
            # 常见但可忽略的能力探测
            if method in ("resources/list", "prompts/list", "resources/templates/list"):
                return {"jsonrpc": "2.0", "id": msg_id, "result": _empty_for(method)}
            if method == "ping":
                return {"jsonrpc": "2.0", "id": msg_id, "result": {}}
            return self._error(msg_id, METHOD_NOT_FOUND, f"Method not found: {method}")

        try:
            return {"jsonrpc": "2.0", "id": msg_id, "result": handler(params)}
        except ToolError as exc:
            return {"jsonrpc": "2.0", "id": msg_id, "result": _text_result(str(exc), True)}
        except Exception as exc:  # noqa: BLE001
            self.log("error", f"{method} failed", error=repr(exc))
            self.log("debug", traceback.format_exc())
            return self._error(msg_id, INTERNAL_ERROR, f"{type(exc).__name__}: {exc}")

    def _handle_notification(self, method: str, params: JSON) -> None:
        if method == "notifications/initialized":
            self.log("info", "client initialized")
        elif method == "notifications/cancelled":
            pass
        else:
            self.log("debug", f"ignored notification {method}")

    # ---- 方法实现 -------------------------------------------------
    def _m_initialize(self, params: JSON) -> JSON:
        requested = params.get("protocolVersion")
        if requested in SUPPORTED_PROTOCOLS:
            self.protocol_version = requested
        self.client_info = params.get("clientInfo") or {}
        self.log("info", f"initialize from {self.client_info.get('name', 'unknown')}")
        return {
            "protocolVersion": self.protocol_version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": self.name, "version": self.version},
            "instructions": (
                "WPE 封包网关。先用 wpe_status 确认上游 WPE 是否在线，"
                "再用 wpe_tools 查看底层能力；改包/发包/注入类工具需要二次确认。"
            ),
        }

    def _m_tools_list(self, params: JSON) -> JSON:
        return {"tools": self.registry.descriptors()}

    def _m_tools_call(self, params: JSON) -> JSON:
        name = params.get("name")
        arguments = params.get("arguments") or {}
        tool = self.registry.get(name)
        if tool is None:
            raise ToolError(
                f"未知工具：{name}",
                hint="可用工具：" + ", ".join(self.registry.names()),
            )
        if not isinstance(arguments, dict):
            raise ToolError("arguments 必须是对象")
        result = tool.handler(arguments)
        if isinstance(result, dict) and set(result) == {"content"}:
            return result
        if isinstance(result, dict) and result.get("__mcp_passthrough__"):
            result.pop("__mcp_passthrough__")
            return _text_result(result)
        return _text_result(result)

    def _m_logging_setLevel(self, params: JSON) -> JSON:
        return {}

    @staticmethod
    def _error(msg_id: Any, code: int, message: str) -> JSON:
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def _empty_for(method: str) -> JSON:
    if method == "resources/list":
        return {"resources": []}
    if method == "resources/templates/list":
        return {"resourceTemplates": []}
    if method == "prompts/list":
        return {"prompts": []}
    return {}


def run_stdio(core: McpServerCore, stdin=None, stdout=None) -> None:
    """标准输入输出循环：一行一条 JSON-RPC 消息。"""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for raw in stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            response = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": PARSE_ERROR, "message": f"Parse error: {exc}"},
            }
        else:
            response = core.handle(message)
        if response is not None:
            stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
            stdout.flush()
