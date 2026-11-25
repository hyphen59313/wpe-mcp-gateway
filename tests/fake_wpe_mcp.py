"""假的上游 WPE MCP 服务，用来在没有安装 WPE 时跑测试和演示。

实现要点：和真实连接器一样，走 stdio + 一行一个 JSON-RPC 消息，
工具名刻意取了和 WPE 相近的写法（wpe_get_* / wpe_*），
用来验证网关的语义映射是不是真的能在「名字不完全一样」的情况下找到工具。
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, List

JSON = Dict[str, Any]

TOOLS: List[JSON] = [
    {
        "name": "wpe_get_packet_list",
        "description": "读取封包列表，支持 limit / socket 过滤",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer"},
                "socket": {"type": "string"},
            },
        },
    },
    {
        "name": "wpe_search_packets",
        "description": "按十六进制特征搜索已抓到的封包",
        "inputSchema": {
            "type": "object",
            "properties": {"pattern": {"type": "string"}, "limit": {"type": "integer"}},
            "required": ["pattern"],
        },
    },
    {
        "name": "wpe_get_system_log",
        "description": "读取系统日志",
        "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer"}}},
    },
    {
        "name": "wpe_get_filter_list",
        "description": "列出滤镜规则",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "wpe_filter_add",
        "description": "新增一条滤镜",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "match": {"type": "string"},
                "replace": {"type": "string"},
                "enabled": {"type": "boolean"},
            },
            "required": ["name", "match"],
        },
    },
    {
        "name": "wpe_filter_delete",
        "description": "删除滤镜",
        "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}},
    },
    {
        "name": "wpe_get_process_list",
        "description": "列出可注入进程",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "wpe_send_packet",
        "description": "发送/重放封包",
        "inputSchema": {
            "type": "object",
            "properties": {
                "packet": {"type": "string"},
                "count": {"type": "integer"},
                "interval": {"type": "integer"},
                "socket": {"type": "string"},
            },
            "required": ["packet"],
        },
    },
    {
        "name": "wpe_sender_start",
        "description": "启动发送列表中的条目",
        "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}},
    },
    {
        "name": "wpe_sender_stop",
        "description": "停止发送列表",
        "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}},
    },
    {
        "name": "wpe_robot_start",
        "description": "启动机器人脚本",
        "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}},
    },
    {
        "name": "wpe_robot_stop",
        "description": "停止机器人脚本",
        "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}},
    },
    {
        "name": "wpe_proxy_stop",
        "description": "停止代理模式",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "wpe_inject_process",
        "description": "注入目标进程",
        "inputSchema": {"type": "object", "properties": {"process": {"type": "string"}}},
    },
    {
        "name": "wpe_proxy_start",
        "description": "启动代理模式",
        "inputSchema": {"type": "object", "properties": {"port": {"type": "integer"}}},
    },
]

STATE: JSON = {
    "packets": [
        {"index": 1, "direction": "C->S", "socket": "127.0.0.1:51000", "len": 12, "hex": "01 00 0A FF 00 00 00 00 12 34 56 78"},
        {"index": 2, "direction": "S->C", "socket": "127.0.0.1:51000", "len": 8, "hex": "02 00 04 00 00 00 00 01"},
        {"index": 3, "direction": "C->S", "socket": "127.0.0.1:51000", "len": 20, "hex": "03 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"},
    ],
    "filters": [{"name": "demo-1", "match": "01 00 0A", "replace": "01 00 0B", "enabled": True}],
    "log": ["[INFO] proxy started on 8888", "[INFO] injected pid 4242", "[WARN] socket 51000 closed"],
    "senders": [{"name": "login-loop", "count": 10}],
    "robots": [{"name": "daily-quest"}],
}


def _ok(payload: Any) -> JSON:
    return {"content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False)}], "isError": False}


def call_tool(name: str, args: JSON) -> JSON:
    limit = int(args.get("limit") or 20)
    if name == "wpe_get_packet_list":
        return _ok(STATE["packets"][:limit])
    if name == "wpe_search_packets":
        pattern = str(args.get("pattern", "")).replace(" ", "").upper()
        hits = [p for p in STATE["packets"] if pattern in p["hex"].replace(" ", "").upper()]
        return _ok(hits)
    if name == "wpe_get_system_log":
        return _ok(STATE["log"][-limit:])
    if name == "wpe_get_filter_list":
        return _ok(STATE["filters"])
    if name == "wpe_filter_add":
        STATE["filters"].append(
            {
                "name": args.get("name"),
                "match": args.get("match"),
                "replace": args.get("replace"),
                "enabled": args.get("enabled", True),
            }
        )
        return _ok({"added": args.get("name")})
    if name == "wpe_filter_delete":
        STATE["filters"] = [f for f in STATE["filters"] if f["name"] != args.get("name")]
        return _ok({"deleted": args.get("name")})
    if name == "wpe_get_process_list":
        return _ok([{"pid": 4242, "name": "game.exe"}, {"pid": 8888, "name": "emulator.exe"}])
    if name == "wpe_send_packet":
        sent = len(str(args.get("packet", "")).replace(" ", "")) // 2 * int(args.get("count") or 1)
        return _ok({"sent_bytes": sent, "count": args.get("count") or 1})
    if name in ("wpe_sender_start", "wpe_sender_stop", "wpe_robot_start", "wpe_robot_stop"):
        return _ok({"action": name, "name": args.get("name")})
    if name == "wpe_inject_process":
        return _ok({"injected": args.get("process")})
    if name == "wpe_proxy_start":
        return _ok({"proxy": "started", "port": args.get("port") or 8888})
    if name == "wpe_proxy_stop":
        return _ok({"proxy": "stopped"})
    return {"content": [{"type": "text", "text": f"unknown tool {name}"}], "isError": True}


def main() -> None:
    for raw in sys.stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        method = message.get("method")
        msg_id = message.get("id")
        if msg_id is None:
            continue
        if method == "initialize":
            result = {
                "protocolVersion": message.get("params", {}).get("protocolVersion", "2025-06-18"),
                "capabilities": {"tools": {"listChanged": True}},
                "serverInfo": {"name": "fake-wpe", "version": "1.0.0"},
            }
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            params = message.get("params") or {}
            result = call_tool(params.get("name"), params.get("arguments") or {})
        elif method == "ping":
            result = {}
        else:
            print(
                json.dumps({"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": method}}),
                flush=True,
            )
            continue
        print(json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": result}, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
