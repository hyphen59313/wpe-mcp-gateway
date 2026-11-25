"""配置加载：TOML，零依赖（Python 3.11+ 自带 tomllib）。"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


def default_data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_STATE_HOME") or Path.home()
    return Path(base) / "wpe-mcp"


DEFAULT_CONFIG_PATHS = (
    Path.cwd() / "config.toml",
    default_data_dir() / "config.toml",
)


@dataclass
class UpstreamConfig:
    command: List[str] = field(
        default_factory=lambda: [r"C:\WPE64DB\McpServer\WPEMcpServer.exe"]
    )
    cwd: Optional[str] = None
    startup_timeout_sec: float = 20.0
    call_timeout_sec: float = 30.0
    client_name: str = "wpe-mcp-gateway"


@dataclass
class PolicyConfig:
    confirm_ttl_sec: int = 180
    mutations_per_minute: int = 20
    min_send_interval_ms: int = 50
    max_send_times: int = 100
    audit_log: Optional[str] = None
    auto_confirm_tools: List[str] = field(default_factory=list)


@dataclass
class HttpConfig:
    host: str = "127.0.0.1"
    port: int = 7801
    token_env: str = "WPE_MCP_TOKEN"
    token: str = ""


@dataclass
class Config:
    upstream: UpstreamConfig = field(default_factory=UpstreamConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    http: HttpConfig = field(default_factory=HttpConfig)
    pins: Dict[str, str] = field(default_factory=dict)
    source_path: Optional[Path] = None

    @property
    def audit_path(self) -> Path:
        if self.policy.audit_log:
            return Path(os.path.expandvars(os.path.expanduser(self.policy.audit_log)))
        return default_data_dir() / "audit.jsonl"


def load_config(path: Optional[str] = None) -> Config:
    if path:
        candidate = Path(os.path.expandvars(os.path.expanduser(path)))
        if not candidate.exists():
            raise FileNotFoundError(f"配置文件不存在：{candidate}")
    else:
        candidate = next((p for p in DEFAULT_CONFIG_PATHS if p.exists()), None)
        if candidate is None:
            return Config()

    with candidate.open("rb") as fh:
        raw = tomllib.load(fh)

    cfg = Config(source_path=candidate)
    up = raw.get("upstream", {}) or {}
    if "command" in up:
        cmd = up["command"]
        cfg.upstream.command = [cmd] if isinstance(cmd, str) else list(cmd)
    cfg.upstream.cwd = up.get("cwd") or cfg.upstream.cwd
    cfg.upstream.startup_timeout_sec = float(up.get("startup_timeout_sec", 20))
    cfg.upstream.call_timeout_sec = float(up.get("call_timeout_sec", 30))

    po = raw.get("policy", {}) or {}
    cfg.policy.confirm_ttl_sec = int(po.get("confirm_ttl_sec", 180))
    cfg.policy.mutations_per_minute = int(po.get("mutations_per_minute", 20))
    cfg.policy.min_send_interval_ms = int(po.get("min_send_interval_ms", 50))
    cfg.policy.max_send_times = int(po.get("max_send_times", 100))
    cfg.policy.audit_log = po.get("audit_log")
    cfg.policy.auto_confirm_tools = list(po.get("auto_confirm_tools", []) or [])

    hc = raw.get("http", {}) or {}
    cfg.http.host = hc.get("host", cfg.http.host)
    cfg.http.port = int(hc.get("port", cfg.http.port))
    cfg.http.token_env = hc.get("token_env", cfg.http.token_env)
    cfg.http.token = hc.get("token", "") or os.environ.get(cfg.http.token_env, "")

    cfg.pins = {k: str(v) for k, v in (raw.get("pins", {}) or {}).items()}
    return cfg
