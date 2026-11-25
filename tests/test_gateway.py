"""端到端测试：用假上游验证协议、映射、确认流程、HTTP 模式。

运行： python tests/test_gateway.py
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from wpe_mcp.config import Config  # noqa: E402
from wpe_mcp.server import build  # noqa: E402

FAKE = str(ROOT / "tests" / "fake_wpe_mcp.py")


class GatewayTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        config = Config()
        config.upstream.command = [sys.executable, FAKE]
        config.upstream.startup_timeout_sec = 15
        config.policy.audit_log = str(Path(cls.tmp.name) / "audit.jsonl")
        config.policy.confirm_ttl_sec = 60
        config.policy.mutations_per_minute = 100
        cls.core = build(config, log_level="error")
        cls.config = config
        cls.ctx = cls.core._context
        cls._id = 0

    @classmethod
    def tearDownClass(cls) -> None:
        cls.ctx.upstream.close()
        cls.tmp.cleanup()

    # ---- 工具方法 -------------------------------------------------
    @classmethod
    def rpc(cls, method: str, params=None):
        cls._id += 1
        return cls.core.handle({"jsonrpc": "2.0", "id": cls._id, "method": method, "params": params or {}})

    @classmethod
    def tool(cls, name: str, arguments=None):
        response = cls.rpc("tools/call", {"name": name, "arguments": arguments or {}})
        result = response["result"]
        text = result["content"][0]["text"]
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = {"_raw": text}
        payload["_isError"] = result.get("isError", False)
        return payload

    # ---- 协议 -----------------------------------------------------
    def test_initialize_and_list(self):
        resp = self.rpc(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "unit-test"},
            },
        )
        self.assertEqual(resp["result"]["protocolVersion"], "2025-06-18")
        self.assertEqual(resp["result"]["serverInfo"]["name"], "wpe-mcp-gateway")

        listing = self.rpc("tools/list")["result"]["tools"]
        names = {t["name"] for t in listing}
        for expected in ("wpe_status", "packets_list", "decode_payload", "packet_send"):
            self.assertIn(expected, names)
        self.assertTrue(all("inputSchema" in t for t in listing))

    def test_notification_returns_nothing(self):
        self.assertIsNone(self.rpc("notifications/initialized").get("result"))

    # ---- 上游映射 -------------------------------------------------
    def test_status(self):
        payload = self.tool("wpe_status")
        self.assertTrue(payload["upstream"]["connected"])
        self.assertGreaterEqual(payload["upstream"]["tools"], 10)

    def test_packets_list(self):
        payload = self.tool("packets_list", {"limit": 2})
        self.assertEqual(payload["upstream_tool"], "wpe_get_packet_list")
        self.assertEqual(payload["count"], 2)

    def test_packets_list_filter(self):
        payload = self.tool("packets_list", {"limit": 10, "contains_hex": "02 00 04"})
        self.assertGreaterEqual(payload["count"], 1)
        self.assertTrue(all("020004" in json.dumps(p).replace(" ", "").upper() for p in payload["packets"]))

    def test_packets_search(self):
        payload = self.tool("packets_search", {"pattern": "03 00 10"})
        self.assertEqual(payload["upstream_tool"], "wpe_search_packets")
        self.assertEqual(len(payload["result"]), 1)

    def test_logs_and_lists(self):
        self.assertIn("proxy started", json.dumps(self.tool("logs_tail"), ensure_ascii=False))
        self.assertGreaterEqual(len(self.tool("filters_list")["result"]), 1)
        self.assertGreaterEqual(len(self.tool("processes_list")["result"]), 1)

    # ---- 本地分析 -------------------------------------------------
    def test_decode_payload(self):
        payload = self.tool("decode_payload", {"data_hex": "48 65 6C 6C 6F 2C 20 57 50 45", "mode": "text"})
        self.assertEqual(payload["bytes"], 10)
        self.assertIn("Hello", payload["text"]["utf8"])

    def test_frame_analyze(self):
        # 4 字节小端长度 = 整包长度 12
        payload = self.tool("frame_analyze", {"data_hex": "0C 00 00 00 01 02 03 04 05 06 07 08"})
        self.assertEqual(payload["total_bytes"], 12)
        hits = payload["length_field_candidates"]
        self.assertTrue(any(h["offset"] == 0 and h["width"] == 4 and h["note"] == "等于整包长度" for h in hits))

    # ---- 确认流程 -------------------------------------------------
    def test_packet_send_requires_confirmation(self):
        first = self.tool("packet_send", {"packet_hex": "01 00 0A FF", "times": 2, "interval_ms": 100})
        self.assertEqual(first["status"], "confirm_required")
        self.assertTrue(first["_isError"] is False)
        token = first["confirm_token"]

        second = self.tool(
            "packet_send",
            {"packet_hex": "01 00 0A FF", "times": 2, "interval_ms": 100, "confirm_token": token},
        )
        self.assertEqual(second["status"], "ok")
        self.assertEqual(second["upstream_tool"], "wpe_send_packet")
        self.assertEqual(second["result"]["count"], 2)

    def test_token_bound_to_arguments(self):
        first = self.tool("packet_send", {"packet_hex": "AA BB", "times": 1})
        token = first["confirm_token"]
        payload = self.tool("packet_send", {"packet_hex": "CC DD", "times": 1, "confirm_token": token})
        self.assertTrue(payload["_isError"])
        self.assertIn("参数", payload["_raw"])

    def test_runner_control_routes_on_verb(self):
        first = self.tool("runner_control", {"target": "robot", "name": "daily-quest", "action": "stop"})
        done = self.tool(
            "runner_control",
            {"target": "robot", "name": "daily-quest", "action": "stop", "confirm_token": first["confirm_token"]},
        )
        self.assertEqual(done["upstream_tool"], "wpe_robot_stop")

    def test_interval_guard(self):
        payload = self.tool("packet_send", {"packet_hex": "AA", "times": 1, "interval_ms": 1})
        self.assertTrue(payload.get("_isError"))

    def test_filter_upsert_mapping(self):
        first = self.tool(
            "filter_upsert", {"name": "t-1", "match_hex": "01 00 0A", "replace_hex": "01 00 0B"}
        )
        token = first["confirm_token"]
        done = self.tool(
            "filter_upsert",
            {"name": "t-1", "match_hex": "01 00 0A", "replace_hex": "01 00 0B", "confirm_token": token},
        )
        self.assertEqual(done["upstream_tool"], "wpe_filter_add")
        self.assertEqual(done["result"]["added"], "t-1")

    def test_inject_process(self):
        first = self.tool("inject_process", {"process": "game.exe"})
        done = self.tool("inject_process", {"process": "game.exe", "confirm_token": first["confirm_token"]})
        self.assertEqual(done["result"]["injected"], "game.exe")

    def test_audit_log_written(self):
        self.ctx.policy.audit({"event": "unit-test"})
        path = Path(self.config.policy.audit_log)
        self.assertTrue(path.exists())
        self.assertIn("unit-test", path.read_text(encoding="utf-8"))


class HttpModeTest(unittest.TestCase):
    def test_http_roundtrip(self):
        from wpe_mcp.http_transport import serve

        config = Config()
        config.upstream.command = [sys.executable, FAKE]
        config.http.host = "127.0.0.1"
        config.http.port = 7811
        config.http.token = "test-token"
        core = build(config, log_level="error")

        thread = threading.Thread(target=serve, args=(core, config.http), daemon=True)
        thread.start()
        time.sleep(0.6)

        body = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        ).encode()
        request = urllib.request.Request(
            "http://127.0.0.1:7811/mcp",
            data=body,
            headers={"Content-Type": "application/json", "Authorization": "Bearer test-token"},
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode())
        names = {t["name"] for t in payload["result"]["tools"]}
        self.assertIn("packet_send", names)

        # 无 token 应 401
        bad = urllib.request.Request(
            "http://127.0.0.1:7811/mcp", data=body, headers={"Content-Type": "application/json"}
        )
        with self.assertRaises(urllib.error.HTTPError) as err:
            urllib.request.urlopen(bad, timeout=10)
        self.assertEqual(err.exception.code, 401)
        core._context.upstream.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
