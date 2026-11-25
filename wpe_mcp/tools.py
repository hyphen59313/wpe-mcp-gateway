"""工具层：把 WPE 自带的几十上百个底层工具，收敛成一组语义化工具。

命名原则：能读的先读、要改的都要二次确认、能本地算的不占用上游。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from . import codec
from .__about__ import __version__
from .config import Config
from .protocol import Registry, ToolError
from .upstream import StdioUpstream, UpstreamError

JSON = Dict[str, Any]

# 上游工具名的语义映射。required 是必须命中的词族（任意一组命中即可），
# boost / avoid 用来在候选里排序。真实名字未知时，靠这套打分去猜，
# 猜不中就让 AI 调 wpe_tools 看清单，再把名字写进 config.toml 的 [pins]。
INTENTS: Dict[str, Dict[str, Any]] = {
    "packets_list": {
        "required": [["packet", "封包"], ["list", "列表", "get", "read", "query", "all", "records"]],
        "boost": ["list", "get", "read", "query", "all", "记录"],
        "avoid": ["send", "write", "delete", "set", "update", "add", "filter", "inject"],
    },
    "packets_search": {
        "required": [["search", "find", "query", "查找", "搜索", "filter"]],
        "boost": ["packet", "封包", "hex", "pattern"],
        "avoid": ["delete", "remove"],
    },
    "logs": {
        "required": [["log", "日志"]],
        "boost": ["tail", "get", "list", "read", "system"],
        "avoid": ["clear", "delete"],
    },
    "filters": {
        "required": [["filter", "滤镜"]],
        "boost": ["list", "get", "read", "all"],
        "avoid": ["delete", "remove", "clear"],
    },
    "senders": {
        "required": [["sender", "发送", "sendlist", "send_list"]],
        "boost": ["list", "get", "read", "all"],
        "avoid": ["start", "stop", "run", "delete"],
    },
    "robots": {
        "required": [["robot", "机器人", "bot"]],
        "boost": ["list", "get", "read", "all"],
        "avoid": ["start", "stop", "run", "delete"],
    },
    "processes": {
        "required": [["process", "进程"]],
        "boost": ["list", "get", "read", "enum", "all"],
        "avoid": ["inject", "kill", "attach"],
    },
    "packet_send": {
        "required": [["send", "发送", "replay", "重放"]],
        "boost": ["packet", "封包", "socket"],
        "avoid": ["list", "log", "history"],
    },
    "filter_write": {
        "required": [["filter", "滤镜"]],
        "boost": ["add", "set", "update", "create", "upsert", "save", "新增", "修改"],
        "avoid": ["list", "get", "delete"],
    },
    "filter_delete": {
        "required": [["filter", "滤镜"]],
        "boost": ["delete", "remove", "del", "删除"],
    },
    "sender_control": {
        "required": [["sender", "发送列表", "sendlist"]],
        "boost": ["start", "stop", "run", "execute", "启动", "停止"],
    },
    "robot_control": {
        "required": [["robot", "机器人", "bot"]],
        "boost": ["start", "stop", "run", "execute", "启动", "停止"],
    },
    "inject": {
        "required": [["inject", "attach", "注入", "hook"]],
        "boost": ["process", "pid", "target"],
        "avoid": ["list", "get", "process_list", "enum"],
    },
    "proxy": {
        "required": [["proxy", "代理"]],
        "boost": ["start", "stop", "enable", "set", "启动", "开启"],
    },
}

# 我们自己参数名 → 上游可能用的参数名
ARG_ALIASES: Dict[str, List[str]] = {
    "packet_hex": ["packet", "data", "hex", "packet_data", "content", "payload"],
    "times": ["count", "times", "loop", "repeat", "loops"],
    "interval_ms": ["interval", "delay", "interval_ms", "sleep", "speed"],
    "socket": ["socket", "sock", "socket_type", "client"],
    "name": ["name", "filter_name", "title", "key"],
    "match_hex": ["match", "pattern", "search", "match_hex", "rule"],
    "replace_hex": ["replace", "replacement", "replace_hex", "to"],
    "enabled": ["enabled", "enable", "active", "on"],
    "process": ["process", "process_name", "name", "target", "pid"],
    "action": ["action", "op", "operation"],
    "limit": ["limit", "count", "max", "size", "top"],
    "keyword": ["keyword", "query", "filter", "search"],
}

MUTATING_HINTS = (
    "send", "write", "delete", "remove", "set", "update", "add", "create",
    "start", "stop", "run", "inject", "attach", "enable", "disable", "clear",
    "save", "import", "restore", "kill", "edit",
)

# start/stop 的同义词：动词必须真的出现在工具名里，避免「停止」被错发成「启动」
VERBS: Dict[str, List[str]] = {
    "start": ["start", "enable", "begin", "run", "resume", "启动", "开启"],
    "stop": ["stop", "disable", "close", "halt", "pause", "停止", "关闭"],
}


@dataclass
class Context:
    config: Config
    upstream: StdioUpstream
    policy: Any
    log: Any
    mock: bool = False


# ---------------------------------------------------------------- 基础设施
def _payload(raw: JSON) -> Tuple[str, Any]:
    content = raw.get("content") or []
    texts = [c.get("text", "") for c in content if isinstance(c, dict) and c.get("type") == "text"]
    text = "\n".join(t for t in texts if t)
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        parsed = None
    return text, parsed


def _tool_text(tool: JSON) -> str:
    return (str(tool.get("name", "")) + " " + str(tool.get("description", ""))).lower()


def _score(tool: JSON, spec: JSON) -> int:
    text = _tool_text(tool)
    required = spec.get("required") or []
    if required and not all(any(term in text for term in group) for group in required):
        return -1
    name = str(tool.get("name", "")).lower()
    score = 0
    for term in spec.get("boost") or []:
        if term in name:
            score += 4
        elif term in text:
            score += 1
    for term in spec.get("avoid") or []:
        if term in name:
            score -= 5
    return score


def resolve_intent(ctx: Context, intent: str, verb: Optional[str] = None) -> str:
    pinned = ctx.config.pins.get(intent)
    if pinned:
        if ctx.upstream.find_tool_exact(pinned):
            return pinned
        raise ToolError(
            f"config.toml 里 pins.{intent} 指向的 {pinned} 在上游不存在",
            hint="用 wpe_tools 查看当前上游工具名，或删掉该 pin 让网关自动匹配",
        )

    spec = INTENTS[intent]
    tools = ctx.upstream.tools()
    ranked = sorted(((t, _score(t, spec)) for t in tools), key=lambda x: -x[1])
    ranked = [(t, s) for t, s in ranked if s > 0]

    # start / stop 这类动词必须真的出现在工具名里，否则宁可不调，
    # 避免把「停止」错发成「启动」。
    if verb:
        synonyms = VERBS.get(verb, [verb])
        subset = []
        for tool, score in ranked:
            name = str(tool.get("name", "")).lower()
            if any(word in name for word in synonyms):
                subset.append((tool, score + 10))
        if not subset:
            raise ToolError(
                f"上游没有与「{verb}」对应的 {intent} 工具",
                hint="用 wpe_tools 看清单确认是否支持该动作；"
                "若工具名特殊，请在 config.toml 用 [pins] 把 intent 直接指向具体工具",
            )
        ranked = subset

    if not ranked:
        raise ToolError(
            f"没能在上游找到对应「{intent}」的工具",
            hint="先调 wpe_tools 看工具清单（可用 keyword 过滤），再把选中的名字写进 config.toml 的 [pins]",
        )
    if len(ranked) > 1 and ranked[0][1] == ranked[1][1]:
        names = [t.get("name") for t, _ in ranked[:5]]
        raise ToolError(
            f"「{intent}」的候选工具打分并列，无法自动确定",
            hint="候选：" + ", ".join(str(n) for n in names) + "；请用 pins 固定其中一个",
        )
    return str(ranked[0][0].get("name"))


def _map_args(schema: JSON, args: JSON) -> JSON:
    props = (schema or {}).get("properties") or {}
    if not props:
        return dict(args)
    mapped: JSON = {}
    for key, value in args.items():
        if key in props:
            mapped[key] = value
            continue
        for alias in ARG_ALIASES.get(key, []):
            if alias in props:
                mapped[alias] = value
                break
    return mapped


def _invoke(ctx: Context, intent: str, args: JSON, verb: Optional[str] = None) -> Tuple[str, JSON, str, Any]:
    if not ctx.upstream.connected:
        ctx.upstream.start()
    name = resolve_intent(ctx, intent, verb)
    tool = ctx.upstream.find_tool_exact(name) or {}
    mapped = _map_args(tool.get("inputSchema") or {}, args)
    try:
        raw = ctx.upstream.call(name, mapped)
    except UpstreamError as exc:
        raise ToolError(f"上游调用失败：{exc}", hint=ctx.upstream.stderr_tail or None) from exc
    text, parsed = _payload(raw)
    return name, raw, text, parsed


def _grepline(text: str, needle: str, regex: bool, limit: int) -> List[str]:
    out: List[str] = []
    pattern = re.compile(needle, re.IGNORECASE) if regex else None
    for line in text.splitlines():
        if regex:
            if pattern and pattern.search(line):
                out.append(line.strip())
        elif needle.lower() in line.lower():
            out.append(line.strip())
        if len(out) >= limit:
            break
    return out


def _guard(
    ctx: Context,
    tool: str,
    args: JSON,
    intent: Optional[str],
    upstream_args: Optional[JSON] = None,
    preview: Optional[JSON] = None,
    verb: Optional[str] = None,
) -> JSON:
    """统一处理：确认令牌 → 限速 → 审计 → 调上游。"""
    confirm = args.get("confirm_token")
    if not ctx.policy.auto_confirmed(tool):
        if not confirm:
            return {"__mcp_passthrough__": True, **ctx.policy.issue(tool, args, preview)}
        ctx.policy.verify(tool, args, confirm)

    ctx.policy.rate_check(tool)
    upstream_name = None
    try:
        if intent:
            upstream_name, _raw, text, parsed = _invoke(ctx, intent, upstream_args or {}, verb)
        else:
            text, parsed = "", None
    except ToolError as exc:
        ctx.policy.audit({"event": "failed", "tool": tool, "error": str(exc)})
        raise
    ctx.policy.audit({"event": "executed", "tool": tool, "upstream": upstream_name})
    result: JSON = {"status": "ok", "tool": tool}
    if upstream_name:
        result["upstream_tool"] = upstream_name
        result["result"] = parsed if parsed is not None else text
    return result


# ---------------------------------------------------------------- 注册表
def build_registry(ctx: Context) -> Registry:
    reg = Registry()

    # ---------- 元信息 ----------
    @reg.add(
        "wpe_status",
        "查看网关与上游 WPE 的连接状态、协议版本、上游工具数量、配置与审计路径。"
        "第一次使用、或任何调用报错后都先调它。",
        {"type": "object", "properties": {}},
    )
    def wpe_status(args: JSON) -> JSON:
        upstream: JSON
        try:
            if not ctx.upstream.connected:
                ctx.upstream.start()
            upstream = ctx.upstream.status()
            upstream["tools"] = len(ctx.upstream.tools())
        except Exception as exc:  # noqa: BLE001
            upstream = {"connected": False, "error": str(exc), "command": " ".join(ctx.upstream.command)}
            upstream["hint"] = (
                "WPE 需要正在运行（连接器不会替你启动它）；"
                "确认 首页 → MCP 设置 的总开关已打开；"
                "路径固定为 C:\\WPE64DB\\McpServer\\WPEMcpServer.exe"
            )
        return {
            "gateway": {
                "name": "wpe-mcp-gateway",
                "version": __version__,
                "mock": ctx.mock,
                "config": str(ctx.config.source_path) if ctx.config.source_path else "(默认值)",
                "audit_log": str(ctx.config.audit_path),
                "confirm_ttl_sec": ctx.config.policy.confirm_ttl_sec,
                "mutations_per_minute": ctx.config.policy.mutations_per_minute,
            },
            "upstream": upstream,
        }

    @reg.add(
        "wpe_tools",
        "列出上游 WPE 的全部底层工具（可关键词过滤）。用于查看真实工具名，"
        "再把名字写进 config.toml 的 [pins] 固定映射。",
        {
            "type": "object",
            "properties": {
                "keyword": {"type": "string", "description": "关键词，匹配工具名或描述"},
                "limit": {"type": "integer", "default": 60},
                "refresh": {"type": "boolean", "default": False},
            },
        },
    )
    def wpe_tools(args: JSON) -> JSON:
        if not ctx.upstream.connected:
            ctx.upstream.start()
        tools = ctx.upstream.tools(refresh=bool(args.get("refresh")))
        keyword = (args.get("keyword") or "").lower()
        limit = int(args.get("limit") or 60)
        rows = []
        for tool in tools:
            text = _tool_text(tool)
            if keyword and keyword not in text:
                continue
            rows.append(
                {
                    "name": tool.get("name"),
                    "description": (tool.get("description") or "")[:120],
                    "arguments": sorted(((tool.get("inputSchema") or {}).get("properties") or {}).keys()),
                }
            )
            if len(rows) >= limit:
                break
        return {"total": len(tools), "shown": len(rows), "tools": rows}

    @reg.add(
        "wpe_call",
        "直接调用上游原始工具（逃生舱）。工具名必须完全准确，"
        "改包/发包/启停类工具同样需要二次确认。",
        {
            "type": "object",
            "properties": {
                "tool": {"type": "string"},
                "arguments": {"type": "object", "default": {}},
                "confirm_token": {"type": "string"},
            },
            "required": ["tool"],
        },
        mutating=True,
    )
    def wpe_call(args: JSON) -> JSON:
        name = args.get("tool") or ""
        upstream_args = args.get("arguments") or {}
        if not ctx.upstream.connected:
            ctx.upstream.start()
        tool = ctx.upstream.find_tool_exact(name)
        if tool is None:
            raise ToolError(
                f"上游没有工具 {name}",
                hint="调 wpe_tools 查看可用工具名（支持 keyword 过滤）",
            )
        dangerous = any(hint in name.lower() for hint in MUTATING_HINTS)
        if dangerous:
            return _guard_once(ctx, "wpe_call", args, name, upstream_args)
        raw = ctx.upstream.call(name, _map_args(tool.get("inputSchema") or {}, upstream_args))
        text, parsed = _payload(raw)
        return {"status": "ok", "upstream_tool": name, "result": parsed if parsed is not None else text}

    def _guard_once(c: Context, tool_name: str, args: JSON, upstream: str, upstream_args: JSON) -> JSON:
        confirm = args.get("confirm_token")
        if not c.policy.auto_confirmed(tool_name):
            if not confirm:
                return {"__mcp_passthrough__": True, **c.policy.issue(tool_name, args, {"upstream_tool": upstream, "arguments": upstream_args})}
            c.policy.verify(tool_name, args, confirm)
        c.policy.rate_check(tool_name)
        raw = c.upstream.call(upstream, upstream_args)
        text, parsed = _payload(raw)
        c.policy.audit({"event": "executed", "tool": tool_name, "upstream": upstream})
        return {"status": "ok", "upstream_tool": upstream, "result": parsed if parsed is not None else text}

    @reg.add(
        "gateway_audit",
        "读取网关自己的审计日志（每次改包/发包/注入都记一条），用于回溯 AI 做过什么。",
        {"type": "object", "properties": {"limit": {"type": "integer", "default": 20}}},
    )
    def gateway_audit(args: JSON) -> JSON:
        return {"path": str(ctx.config.audit_path), "records": ctx.policy.tail(int(args.get("limit") or 20))}

    # ---------- 只读 ----------
    @reg.add(
        "packets_list",
        "读取当前抓到的封包列表（只读）。可用 contains_hex 在结果文本里做本地筛选，"
        "min_len 过滤短包。",
        {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "default": 20},
                "contains_hex": {"type": "string", "description": "十六进制片段，如 '01 00 0A'"},
                "min_len": {"type": "integer", "description": "最小字节数"},
                "upstream_args": {"type": "object", "default": {}},
            },
        },
    )
    def packets_list(args: JSON) -> JSON:
        limit = int(args.get("limit") or 20)
        upstream_args = dict(args.get("upstream_args") or {})
        upstream_args.setdefault("limit", limit)
        name, _raw, text, parsed = _invoke(ctx, "packets_list", upstream_args)

        needle = (args.get("contains_hex") or "").replace(" ", "").upper()
        min_len = args.get("min_len")

        if isinstance(parsed, list):
            rows = parsed
            if needle:
                rows = [r for r in rows if needle in json.dumps(r, ensure_ascii=False).replace(" ", "").upper()]
            if min_len:
                rows = [r for r in rows if _guess_len(r) >= int(min_len)]
            rows = rows[:limit]
            return {"upstream_tool": name, "count": len(rows), "packets": rows}
        if needle:
            lines = _grepline(text, args["contains_hex"], False, limit)
            return {"upstream_tool": name, "matched_lines": lines, "raw_excerpt": text[:4000]}
        return {"upstream_tool": name, "raw": text[:6000]}

    @reg.add(
        "packets_search",
        "按十六进制特征搜索封包；上游没有搜索接口时自动退化为「取列表 + 本地匹配」。",
        {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "十六进制特征或正则"},
                "regex": {"type": "boolean", "default": False},
                "limit": {"type": "integer", "default": 20},
            },
            "required": ["pattern"],
        },
    )
    def packets_search(args: JSON) -> JSON:
        pattern = args["pattern"]
        limit = int(args.get("limit") or 20)
        try:
            name, _raw, text, parsed = _invoke(
                ctx, "packets_search", {"pattern": pattern, "search": pattern, "limit": limit}
            )
            if parsed is not None:
                return {"upstream_tool": name, "result": parsed}
            return {"upstream_tool": name, "raw": text[:6000]}
        except ToolError:
            name, _raw, text, parsed = _invoke(ctx, "packets_list", {"limit": limit, "count": limit})
            lines = _grepline(text, pattern, bool(args.get("regex")), limit)
            return {
                "upstream_tool": name,
                "mode": "本地匹配（上游无搜索工具）",
                "matched_lines": lines,
                "raw_excerpt": text[:3000],
            }

    @reg.add(
        "logs_tail",
        "读取 WPE 系统日志尾部（只读），排查注入/抓包失败最有用。",
        {"type": "object", "properties": {"limit": {"type": "integer", "default": 30}}},
    )
    def logs_tail(args: JSON) -> JSON:
        name, _raw, text, parsed = _invoke(ctx, "logs", {"limit": int(args.get("limit") or 30)})
        return {"upstream_tool": name, "result": parsed if parsed is not None else text[:8000]}

    def _list_tool(tool_name: str, intent: str, description: str) -> None:
        @reg.add(tool_name, description, {"type": "object", "properties": {"limit": {"type": "integer", "default": 50}}})
        def _handler(args: JSON) -> JSON:
            name, _raw, text, parsed = _invoke(ctx, intent, {"limit": int(args.get("limit") or 50)})
            return {"upstream_tool": name, "result": parsed if parsed is not None else text[:6000]}

    _list_tool("filters_list", "filters", "列出滤镜规则（只读）。改包前先看清现有规则，避免叠加冲突。")
    _list_tool("senders_list", "senders", "列出「发送列表」里的重放条目（只读）。")
    _list_tool("robots_list", "robots", "列出机器人脚本（只读）。")
    _list_tool("processes_list", "processes", "列出可注入的目标进程（只读）。")

    # ---------- 本地分析 ----------
    @reg.add(
        "decode_payload",
        "本地解码一段十六进制：文本预览、单字节异或爆破、Base64 尝试、已知密钥异或。不占用上游。",
        {
            "type": "object",
            "properties": {
                "data_hex": {"type": "string"},
                "mode": {"type": "string", "enum": ["auto", "text", "xor", "base64"], "default": "auto"},
                "xor_key_hex": {"type": "string"},
                "limit": {"type": "integer", "default": 8},
            },
            "required": ["data_hex"],
        },
    )
    def decode_payload(args: JSON) -> JSON:
        try:
            return codec.decode_payload(
                args["data_hex"],
                mode=args.get("mode") or "auto",
                xor_key_hex=args.get("xor_key_hex"),
                limit=int(args.get("limit") or 8),
            )
        except ValueError as exc:
            raise ToolError(str(exc), hint="支持 '03 00 0A FF' 或 '03000AFF' 两种写法") from exc

    @reg.add(
        "frame_analyze",
        "本地猜测帧结构：哪些偏移上的整数等于总长/剩余长、是否有重复包头（多帧粘包时看步长）。",
        {
            "type": "object",
            "properties": {
                "data_hex": {"type": "string"},
                "scan_offsets": {"type": "integer", "default": 24},
            },
            "required": ["data_hex"],
        },
    )
    def frame_analyze(args: JSON) -> JSON:
        try:
            blob = codec.parse_hex(args["data_hex"])
        except ValueError as exc:
            raise ToolError(str(exc)) from exc
        return codec.frame_analyze(blob, int(args.get("scan_offsets") or 24))

    # ---------- 变更（需确认） ----------
    @reg.add(
        "packet_send",
        "发送/重放一个封包（会真的发出去）。times 与 interval_ms 受策略限制，"
        "批量重放请改用发送列表。",
        {
            "type": "object",
            "properties": {
                "packet_hex": {"type": "string"},
                "times": {"type": "integer", "default": 1},
                "interval_ms": {"type": "integer", "default": 100},
                "socket": {"type": "string", "description": "可选：指定系统套接字/客户端"},
                "confirm_token": {"type": "string"},
            },
            "required": ["packet_hex"],
        },
        mutating=True,
    )
    def packet_send(args: JSON) -> JSON:
        try:
            size = len(codec.parse_hex(args["packet_hex"]))
        except ValueError as exc:
            raise ToolError(str(exc)) from exc
        times = int(args.get("times") or 1)
        interval = int(args.get("interval_ms") or 100)
        if times > ctx.config.policy.max_send_times:
            raise ToolError(
                f"times={times} 超过上限 {ctx.config.policy.max_send_times}",
                hint="大循环请走发送列表，避免 AI 侧逐条堆请求",
            )
        if interval < ctx.config.policy.min_send_interval_ms:
            raise ToolError(
                f"interval_ms={interval} 低于下限 {ctx.config.policy.min_send_interval_ms}",
                hint="过快会让目标服务器判定异常，也会撑爆网关速率限制",
            )
        upstream_args = {
            "packet_hex": args["packet_hex"],
            "times": times,
            "interval_ms": interval,
        }
        if args.get("socket"):
            upstream_args["socket"] = args["socket"]
        preview = {"bytes": size, "times": times, "interval_ms": interval, "total_bytes": size * times}
        return _guard(ctx, "packet_send", args, "packet_send", upstream_args, preview)

    @reg.add(
        "filter_upsert",
        "新增或修改一条滤镜（命中即改写封包）。match_hex 支持通配符写法，"
        "不确定就先 filters_list 看现有规则。",
        {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "match_hex": {"type": "string"},
                "replace_hex": {"type": "string"},
                "enabled": {"type": "boolean", "default": True},
                "confirm_token": {"type": "string"},
            },
            "required": ["name", "match_hex"],
        },
        mutating=True,
    )
    def filter_upsert(args: JSON) -> JSON:
        upstream_args = {
            "name": args["name"],
            "match_hex": args["match_hex"],
            "replace_hex": args.get("replace_hex", ""),
            "enabled": bool(args.get("enabled", True)),
        }
        preview = {"name": args["name"], "match": args["match_hex"], "replace": args.get("replace_hex", "")}
        return _guard(ctx, "filter_upsert", args, "filter_write", upstream_args, preview)

    @reg.add(
        "filter_delete",
        "删除一条滤镜。",
        {
            "type": "object",
            "properties": {"name": {"type": "string"}, "confirm_token": {"type": "string"}},
            "required": ["name"],
        },
        mutating=True,
    )
    def filter_delete(args: JSON) -> JSON:
        return _guard(ctx, "filter_delete", args, "filter_delete", {"name": args["name"]}, {"name": args["name"]})

    @reg.add(
        "runner_control",
        "启动/停止发送列表或机器人（会立刻在目标程序上产生流量）。",
        {
            "type": "object",
            "properties": {
                "target": {"type": "string", "enum": ["sender", "robot"]},
                "name": {"type": "string"},
                "action": {"type": "string", "enum": ["start", "stop"]},
                "confirm_token": {"type": "string"},
            },
            "required": ["target", "name", "action"],
        },
        mutating=True,
    )
    def runner_control(args: JSON) -> JSON:
        intent = "sender_control" if args["target"] == "sender" else "robot_control"
        upstream_args = {"name": args["name"], "action": args["action"]}
        return _guard(ctx, "runner_control", args, intent, upstream_args, upstream_args, verb=args["action"])

    @reg.add(
        "inject_process",
        "把 WPE 注入到目标进程开始抓包（注入失败最常见的原因是权限/位数不匹配）。",
        {
            "type": "object",
            "properties": {"process": {"type": "string"}, "confirm_token": {"type": "string"}},
            "required": ["process"],
        },
        mutating=True,
    )
    def inject_process(args: JSON) -> JSON:
        upstream_args = {"process": args["process"], "process_name": args["process"]}
        return _guard(ctx, "inject_process", args, "inject", upstream_args, {"process": args["process"]})

    @reg.add(
        "proxy_control",
        "启动/停止代理模式（SOCKS5 + HTTPS 中间人）。抓 HTTPS 明文走这条。",
        {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["start", "stop"]},
                "port": {"type": "integer"},
                "confirm_token": {"type": "string"},
            },
            "required": ["action"],
        },
        mutating=True,
    )
    def proxy_control(args: JSON) -> JSON:
        upstream_args = {"action": args["action"]}
        if args.get("port"):
            upstream_args["port"] = args["port"]
        return _guard(ctx, "proxy_control", args, "proxy", upstream_args, upstream_args, verb=args["action"])

    return reg


def _guess_len(row: Any) -> int:
    if not isinstance(row, dict):
        return 0
    for key in ("len", "length", "size", "bytes", "data_len"):
        value = row.get(key)
        if isinstance(value, int):
            return value
    for key in ("hex", "data", "packet", "raw"):
        value = row.get(key)
        if isinstance(value, str):
            return len(value.replace(" ", "")) // 2
    return 0
