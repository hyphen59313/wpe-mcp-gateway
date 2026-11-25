"""极简 HTTP 传输层：给不支持本地 stdio 的客户端用。

- POST /mcp  ← JSON-RPC（Accept: application/json 或 text/event-stream 都支持）
- GET  /health ← 健康检查
- 默认只绑 127.0.0.1；绑非回环地址时必须配 token。
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

from .config import HttpConfig
from .protocol import McpServerCore, PARSE_ERROR


class _Handler(BaseHTTPRequestHandler):
    server_version = "wpe-mcp-gateway"
    core: McpServerCore = None  # type: ignore[assignment]
    http_cfg: HttpConfig = None  # type: ignore[assignment]

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        if self.core.log:
            self.core.log("debug", f"http {self.address_string()} {fmt % args}")

    # ---- 鉴权 -----------------------------------------------------
    def _authorized(self) -> bool:
        token = self.http_cfg.token
        if not token:
            return self._is_loopback()
        header = self.headers.get("Authorization", "")
        return header == f"Bearer {token}" or self.headers.get("X-WPE-MCP-Token") == token

    def _is_loopback(self) -> bool:
        client = self.client_address[0] if self.client_address else ""
        return client in ("127.0.0.1", "::1", "localhost")

    def _reject(self) -> None:
        self._send_json(
            401,
            {"jsonrpc": "2.0", "id": None, "error": {"code": -32000, "message": "Unauthorized"}},
        )

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_sse(self, payload: dict) -> None:
        body = ("event: message\ndata: " + json.dumps(payload, ensure_ascii=False) + "\n\n").encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ---- 路由 -----------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        if self.path.rstrip("/") in ("/health", "/"):
            ctx = getattr(self.core, "_context", None)
            upstream_status = {}
            if ctx is not None:
                try:
                    upstream_status = ctx.upstream.status()
                except Exception as exc:  # noqa: BLE001
                    upstream_status = {"connected": False, "error": str(exc)}
            self._send_json(200, {"status": "ok", "upstream": upstream_status})
            return
        if self.path.rstrip("/") == "/mcp":
            # 不提供长连接 SSE 流；客户端用 POST 即可
            self._send_json(405, {"error": "Use POST /mcp for JSON-RPC"})
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path.rstrip("/") != "/mcp":
            self._send_json(404, {"error": "not found"})
            return
        if not self._authorized():
            self._reject()
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length)
            message = json.loads(raw.decode("utf-8"))
        except (ValueError, json.JSONDecodeError) as exc:
            self._send_json(400, {"jsonrpc": "2.0", "id": None, "error": {"code": PARSE_ERROR, "message": str(exc)}})
            return

        accepts_sse = "text/event-stream" in (self.headers.get("Accept") or "")
        if isinstance(message, list):  # 批量请求一律回 JSON
            responses = [r for r in (self.core.handle(m) for m in message) if r is not None]
            self._send_json(200, responses)  # type: ignore[arg-type]
            return

        response = self.core.handle(message)
        if response is None:
            self.send_response(202)
            self.end_headers()
            return

        if accepts_sse:
            self._send_sse(response)
        else:
            self._send_json(200, response)


def serve(core: McpServerCore, cfg: HttpConfig) -> None:
    if cfg.host not in ("127.0.0.1", "localhost", "::1") and not cfg.token:
        raise SystemExit(
            "拒绝在非回环地址上无鉴权启动：请在 config.toml 的 [http] token 或 "
            f"{cfg.token_env} 环境变量里配置访问令牌"
        )
    handler = type("Handler", (_Handler,), {"core": core, "http_cfg": cfg})
    httpd = ThreadingHTTPServer((cfg.host, cfg.port), handler)
    core.log("info", f"HTTP 模式已启动：http://{cfg.host}:{cfg.port}/mcp")
    thread = threading.Thread(target=httpd.serve_forever, name="wpe-mcp-http", daemon=True)
    thread.start()
    try:
        thread.join()
    except KeyboardInterrupt:
        httpd.shutdown()
