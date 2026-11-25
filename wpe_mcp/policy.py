"""安全策略：二次确认令牌、速率限制、审计日志。

改包 / 发包 / 注入 / 启停机器人这些动作一旦落地就真的会改变目标程序行为，
所以默认「第一次调用只返回预览 + 令牌，第二次带令牌才执行」。
"""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Deque, Dict, Optional

from .config import PolicyConfig
from .protocol import ToolError

JSON = Dict[str, Any]


def _canonical(args: JSON) -> str:
    filtered = {k: v for k, v in args.items() if k != "confirm_token"}
    return json.dumps(filtered, sort_keys=True, ensure_ascii=False, default=str)


class Policy:
    def __init__(self, cfg: PolicyConfig, audit_path: Path, log=None) -> None:
        self.cfg = cfg
        self.audit_path = audit_path
        self.log = log or (lambda *a, **k: None)
        self._tokens: Dict[str, Dict[str, Any]] = {}
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    # ---- 确认令牌 -------------------------------------------------
    def issue(self, tool: str, args: JSON, preview: Optional[JSON] = None) -> JSON:
        token = secrets.token_urlsafe(12)
        digest = hashlib.sha256(_canonical(args).encode("utf-8")).hexdigest()[:16]
        with self._lock:
            self._prune()
            self._tokens[token] = {
                "tool": tool,
                "digest": digest,
                "expires": time.time() + self.cfg.confirm_ttl_sec,
            }
        self.audit({"event": "confirm_required", "tool": tool, "args": _safe(args), "token": token})
        return {
            "status": "confirm_required",
            "tool": tool,
            "confirm_token": token,
            "expires_in_sec": self.cfg.confirm_ttl_sec,
            "preview": preview or _safe(args),
            "next_step": f"确认无误后，用同样的参数再调用一次 {tool}，并带上 confirm_token={token}",
        }

    def verify(self, tool: str, args: JSON, token: Optional[str]) -> None:
        if not token:
            raise ToolError(
                "该操作会改变目标程序的行为，需要二次确认",
                hint=f"先不带 confirm_token 调用 {tool} 取得令牌，再带令牌调用执行",
            )
        with self._lock:
            self._prune()
            record = self._tokens.get(token)
        if record is None:
            raise ToolError("确认令牌无效或已过期", hint="重新调用一次以获取新令牌")
        if record["tool"] != tool:
            raise ToolError(f"确认令牌属于 {record['tool']}，不能用于 {tool}")
        if record["digest"] != hashlib.sha256(_canonical(args).encode("utf-8")).hexdigest()[:16]:
            raise ToolError("参数与申请令牌时不一致；请用同一组参数重新申请")
        with self._lock:
            self._tokens.pop(token, None)
        self.audit({"event": "confirm_ok", "tool": tool, "token": token})

    def auto_confirmed(self, tool: str) -> bool:
        return tool in self.cfg.auto_confirm_tools

    # ---- 速率限制 -------------------------------------------------
    def rate_check(self, tool: str) -> None:
        limit = self.cfg.mutations_per_minute
        if limit <= 0:
            return
        now = time.monotonic()
        with self._lock:
            window = self._hits[tool]
            while window and now - window[0] > 60:
                window.popleft()
            if len(window) >= limit:
                raise ToolError(
                    f"{tool} 触发速率限制（{limit} 次/分钟）",
                    hint="批量操作请改用发送列表/机器人，而不是逐条调用",
                )
            window.append(now)

    # ---- 审计 -----------------------------------------------------
    def audit(self, record: JSON) -> None:
        record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **record}
        try:
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)
            with self.audit_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        except OSError as exc:
            self.log("warning", f"审计日志写入失败：{exc}")

    def tail(self, limit: int = 20) -> list[JSON]:
        if not self.audit_path.exists():
            return []
        with self.audit_path.open("r", encoding="utf-8") as fh:
            lines = fh.readlines()[-limit:]
        out = []
        for line in lines:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out

    def _prune(self) -> None:
        now = time.time()
        for token in [t for t, r in self._tokens.items() if r["expires"] < now]:
            self._tokens.pop(token, None)


def _safe(args: JSON) -> JSON:
    """审计/预览里把长十六进制串截断，避免日志爆掉。"""
    out: JSON = {}
    for key, value in args.items():
        if key == "confirm_token":
            continue
        if isinstance(value, str) and len(value) > 96:
            out[key] = value[:96] + f"...({len(value)} chars)"
        else:
            out[key] = value
    return out
