"""命令行入口。

    python -m wpe_mcp                 # stdio（给 Claude Code / VS Code / Cursor 用）
    python -m wpe_mcp --http          # HTTP 模式（默认 127.0.0.1:7801）
    python -m wpe_mcp --mock          # 不装 WPE 也能跑：使用内置假上游演示
    python -m wpe_mcp --selftest      # 对当前配置做一次自检并打印报告
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .__about__ import __title__, __version__
from .config import load_config
from .protocol import run_stdio
from .server import build


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="wpe-mcp", description="WPE 封包网关（MCP 服务端）")
    parser.add_argument("--version", action="version", version=f"{__title__} {__version__}")
    parser.add_argument("--config", help="config.toml 路径（默认当前目录或 %%LOCALAPPDATA%%\\wpe-mcp）")
    parser.add_argument("--http", action="store_true", help="以 HTTP 方式监听，而不是 stdio")
    parser.add_argument("--host", help="HTTP 监听地址（覆盖配置）")
    parser.add_argument("--port", type=int, help="HTTP 监听端口（覆盖配置）")
    parser.add_argument("--mock", action="store_true", help="使用内置假上游（演示/联调）")
    parser.add_argument("--log-level", default="info", choices=["debug", "info", "warning", "error"])
    parser.add_argument("--selftest", action="store_true", help="连一次上游、列出工具、跑一遍本地解码，然后退出")
    args = parser.parse_args(argv)

    try:
        config = load_config(args.config)
    except (FileNotFoundError, ValueError) as exc:
        print(f"配置错误：{exc}", file=sys.stderr)
        return 2

    if args.mock:
        config.policy.audit_log = str(Path(config.audit_path).with_name("audit.mock.jsonl"))

    core = build(config, mock=args.mock, log_level=args.log_level)

    if args.selftest:
        return _selftest(core, config)

    if args.http:
        from .http_transport import serve

        if args.host:
            config.http.host = args.host
        if args.port:
            config.http.port = args.port
        serve(core, config.http)
        return 0

    run_stdio(core)
    return 0


def _selftest(core, config) -> int:
    ctx = core._context
    report: dict = {"config": str(config.source_path) if config.source_path else "(默认值)"}
    try:
        ctx.upstream.start()
        tools = ctx.upstream.tools()
        report["upstream"] = {
            "connected": True,
            "server": ctx.upstream.server_info,
            "tool_count": len(tools),
            "sample": [t.get("name") for t in tools[:10]],
        }
    except Exception as exc:  # noqa: BLE001
        report["upstream"] = {"connected": False, "error": str(exc)}

    report["gateway_tools"] = core.registry.names()

    decode = core.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "decode_payload", "arguments": {"data_hex": "1A 2B 3C 00 01", "mode": "auto"}},
        }
    )
    try:
        report["decode_ok"] = json.loads(decode["result"]["content"][0]["text"])["bytes"] == 5
    except (KeyError, TypeError, json.JSONDecodeError):
        report["decode_ok"] = False

    print(json.dumps(report, ensure_ascii=False, indent=2))
    ctx.upstream.close()
    return 0 if report.get("decode_ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
