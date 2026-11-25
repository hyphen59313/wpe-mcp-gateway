"""把配置、上游客户端、策略、工具表组装成一个可运行的 MCP 服务端。"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Callable, Optional

from .__about__ import __title__, __version__
from .config import Config
from .policy import Policy
from .protocol import McpServerCore
from .tools import Context, build_registry
from .upstream import StdioUpstream

LOG_LEVELS = {"debug": 10, "info": 20, "warning": 30, "error": 40}


def make_logger(level: str = "info") -> Callable[..., None]:
    threshold = LOG_LEVELS.get(level, 20)

    def log(event_level: str = "info", message: str = "", **extra) -> None:
        if LOG_LEVELS.get(event_level, 20) < threshold:
            return
        stamp = time.strftime("%H:%M:%S")
        suffix = ""
        if extra:
            suffix = " " + " ".join(f"{k}={v}" for k, v in extra.items() if v is not None)
        sys.stderr.write(f"[{stamp}] [{event_level}] {message}{suffix}\n")
        sys.stderr.flush()

    return log


def fake_upstream_path() -> Optional[Path]:
    candidate = Path(__file__).resolve().parent.parent / "tests" / "fake_wpe_mcp.py"
    return candidate if candidate.exists() else None


def build(config: Config, *, mock: bool = False, log_level: str = "info") -> McpServerCore:
    log = make_logger(log_level)

    if mock:
        script = fake_upstream_path()
        if script is None:
            raise FileNotFoundError("找不到 tests/fake_wpe_mcp.py，无法进入 --mock 模式")
        command = [sys.executable, str(script)]
        log("info", "mock 模式：使用内置假上游")
    else:
        command = list(config.upstream.command)

    upstream = StdioUpstream(
        command=command,
        cwd=config.upstream.cwd,
        startup_timeout=config.upstream.startup_timeout_sec,
        call_timeout=config.upstream.call_timeout_sec,
        client_name=config.upstream.client_name,
        log=log,
    )
    policy = Policy(config.policy, config.audit_path, log=log)
    ctx = Context(config=config, upstream=upstream, policy=policy, log=log, mock=mock)
    registry = build_registry(ctx)
    core = McpServerCore(__title__, __version__, registry, log=log)
    core._context = ctx  # 供 HTTP 模式 / 诊断使用
    return core
