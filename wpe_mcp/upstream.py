"""上游 WPE MCP 客户端：以子进程方式驱动 C:\\WPE64DB\\McpServer\\WPEMcpServer.exe。

WPE 自带的是 stdio MCP 服务，本模块用 JSON-RPC 行协议跟它对话，
并把工具清单缓存下来供网关做语义映射。
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional

JSON = Dict[str, Any]


class UpstreamError(RuntimeError):
    pass


class UpstreamUnavailable(UpstreamError):
    pass


class StdioUpstream:
    def __init__(
        self,
        command: List[str],
        cwd: Optional[str] = None,
        startup_timeout: float = 20.0,
        call_timeout: float = 30.0,
        client_name: str = "wpe-mcp-gateway",
        log=None,
    ) -> None:
        self.command = command
        self.cwd = cwd
        self.startup_timeout = startup_timeout
        self.call_timeout = call_timeout
        self.client_name = client_name
        self.log = log or (lambda *a, **k: None)

        self._proc: Optional[subprocess.Popen] = None
        self._inbox: "queue.Queue[JSON]" = queue.Queue()
        self._stderr_buf: List[str] = []
        self._next_id = 0
        self._lock = threading.Lock()
        self._tools: List[JSON] = []
        self._tools_dirty = True
        self.server_info: JSON = {}
        self.protocol_version = ""
        self.started_at: Optional[float] = None
        self.last_error: Optional[str] = None

    # ---- 生命周期 -------------------------------------------------
    @property
    def connected(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def start(self) -> None:
        if self.connected:
            return
        if not self.command:
            raise UpstreamUnavailable("未配置上游命令（config.toml → [upstream] command）")

        exe = self.command[0]
        if not os.path.isabs(exe) and not os.path.exists(exe):
            pass  # 交给系统在 PATH 中查找
        elif not os.path.exists(exe):
            raise UpstreamUnavailable(
                f"找不到 WPE MCP 连接器：{exe}\n"
                "请确认已安装 WPE x64 2.3+，并让它至少启动过一次（连接器会被同步到该固定路径）。"
            )

        try:
            self._proc = subprocess.Popen(
                self.command,
                cwd=self.cwd or None,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except OSError as exc:
            raise UpstreamUnavailable(f"启动上游失败：{exc}") from exc

        self.started_at = time.time()
        threading.Thread(target=self._read_stdout, name="wpe-upstream-stdout", daemon=True).start()
        threading.Thread(target=self._read_stderr, name="wpe-upstream-stderr", daemon=True).start()

        self._handshake()

    def close(self) -> None:
        proc = self._proc
        self._proc = None
        if proc is None:
            return
        try:
            if proc.stdin:
                proc.stdin.close()
        except OSError:
            pass
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:  # noqa: BLE001
            try:
                proc.kill()
            except Exception:  # noqa: BLE001
                pass
        for stream in (proc.stdout, proc.stderr):
            try:
                if stream:
                    stream.close()
            except Exception:  # noqa: BLE001
                pass

    # ---- 读取线程 -------------------------------------------------
    def _read_stdout(self) -> None:
        proc = self._proc
        if proc is None or proc.stdout is None:
            return
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                self.log("debug", f"上游非 JSON 输出：{line[:200]}")
                continue
            self._inbox.put(message)

    def _read_stderr(self) -> None:
        proc = self._proc
        if proc is None or proc.stderr is None:
            return
        for line in proc.stderr:
            line = line.rstrip()
            if not line:
                continue
            self._stderr_buf.append(line)
            del self._stderr_buf[:-40]
            self.log("debug", f"上游 stderr：{line[:300]}")

    @property
    def stderr_tail(self) -> str:
        return "\n".join(self._stderr_buf[-10:])

    # ---- 请求 -----------------------------------------------------
    def _send(self, payload: JSON) -> None:
        proc = self._proc
        if proc is None or proc.stdin is None or proc.poll() is not None:
            raise UpstreamUnavailable("上游进程已退出")
        proc.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
        proc.stdin.flush()

    def request(self, method: str, params: Optional[JSON] = None, timeout: Optional[float] = None) -> JSON:
        with self._lock:
            self._next_id += 1
            msg_id = self._next_id
        payload: JSON = {"jsonrpc": "2.0", "id": msg_id, "method": method}
        if params is not None:
            payload["params"] = params
        self._send(payload)

        deadline = time.monotonic() + (timeout or self.call_timeout)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise UpstreamError(f"上游 {method} 超时（{timeout or self.call_timeout}s）")
            try:
                message = self._inbox.get(timeout=remaining)
            except queue.Empty:
                raise UpstreamError(f"上游 {method} 超时（{timeout or self.call_timeout}s）")
            if message.get("id") != msg_id:
                # 可能是通知（tools/list_changed 等）
                if message.get("method") == "notifications/tools/list_changed":
                    self._tools_dirty = True
                continue
            if "error" in message:
                err = message["error"]
                raise UpstreamError(f"{err.get('message', '上游错误')} (code={err.get('code')})")
            return message.get("result") or {}

    def _handshake(self) -> None:
        result = self.request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {"roots": {"listChanged": False}},
                "clientInfo": {"name": self.client_name, "version": "0.1.0"},
            },
            timeout=self.startup_timeout,
        )
        self.protocol_version = result.get("protocolVersion", "")
        self.server_info = result.get("serverInfo", {}) or {}
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        self.log("info", f"上游已连接：{self.server_info.get('name', 'WPE')} v{self.server_info.get('version', '?')}")

    # ---- 工具 -----------------------------------------------------
    def tools(self, refresh: bool = False) -> List[JSON]:
        if refresh or self._tools_dirty or not self._tools:
            if not self.connected:
                self.start()
            result = self.request("tools/list", {})
            self._tools = list(result.get("tools") or [])
            self._tools_dirty = False
            self.log("info", f"拉取到上游工具 {len(self._tools)} 个")
        return self._tools

    def find_tool_exact(self, name: str) -> Optional[JSON]:
        for tool in self.tools():
            if tool.get("name") == name:
                return tool
        return None

    def call(self, name: str, arguments: Optional[JSON] = None) -> JSON:
        if not self.connected:
            self.start()
        result = self.request(
            "tools/call",
            {"name": name, "arguments": arguments or {}},
            timeout=self.call_timeout,
        )
        return result

    def status(self) -> JSON:
        connected = self.connected
        return {
            "connected": connected,
            "command": " ".join(self.command),
            "protocol_version": self.protocol_version,
            "server": self.server_info,
            "tools_cached": len(self._tools),
            "uptime_sec": round(time.time() - self.started_at, 1) if self.started_at and connected else 0,
            "stderr_tail": self.stderr_tail if not connected else "",
        }
