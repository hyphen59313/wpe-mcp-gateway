"""本地封包分析工具：不调用 WPE，纯计算。

这些能力是网关相对 WPE 自带 MCP 的增量：
在 AI 读到一个十六进制串之后，立刻能给出可读文本、单字节异或爆破结果、
长度字段候选和帧切分猜测，省掉反复试错的往返。
"""

from __future__ import annotations

import base64
import binascii
import string
from typing import Any, Dict, List, Optional, Sequence

PRINTABLE = set(bytes(string.printable, "ascii")) - {0x0B, 0x0C}


def parse_hex(text: str) -> bytes:
    cleaned = (
        text.replace("0x", " ")
        .replace("0X", " ")
        .replace(",", " ")
        .replace("\\x", " ")
        .replace(":", " ")
        .replace("-", " ")
    )
    tokens = cleaned.split()
    if len(tokens) > 1:
        return bytes(int(t, 16) for t in tokens)
    compact = "".join(tokens)
    if len(compact) % 2:
        compact = compact[:-1]
    try:
        return bytes.fromhex(compact)
    except ValueError as exc:
        raise ValueError(f"不是合法的十六进制串：{exc}") from exc


def to_hex(data: bytes, sep: str = " ") -> str:
    return sep.join(f"{b:02X}" for b in data)


def as_text(data: bytes) -> str:
    for encoding in ("utf-8", "gbk", "latin-1"):
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return ""


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(1 for b in data if b in PRINTABLE) / len(data)


def hexdump(data: bytes, max_bytes: int = 256) -> List[str]:
    lines: List[str] = []
    for offset in range(0, min(len(data), max_bytes), 16):
        chunk = data[offset : offset + 16]
        hex_part = " ".join(f"{b:02X}" for b in chunk).ljust(47)
        text_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:04X}  {hex_part}  |{text_part}|")
    if len(data) > max_bytes:
        lines.append(f"... 共 {len(data)} 字节，仅显示前 {max_bytes} 字节")
    return lines


def xor_with_key(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def xor_bruteforce(data: bytes, top: int = 8) -> List[Dict[str, Any]]:
    """单字节异或爆破，按可读性排序。"""
    candidates: List[Dict[str, Any]] = []
    for key in range(1, 256):
        decoded = bytes(b ^ key for b in data)
        ratio = printable_ratio(decoded)
        if ratio < 0.6:
            continue
        candidates.append(
            {
                "key_hex": f"{key:02X}",
                "printable_ratio": round(ratio, 3),
                "text": as_text(decoded)[:200],
            }
        )
    candidates.sort(key=lambda c: -c["printable_ratio"])
    return candidates[:top]


def try_base64(text: str) -> Optional[bytes]:
    stripped = "".join(text.split())
    if len(stripped) < 8:
        return None
    padded = stripped + "=" * (-len(stripped) % 4)
    try:
        return base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None


def frame_analyze(blob: bytes, scan_offsets: int = 24) -> Dict[str, Any]:
    """猜测长度字段位置与帧切分方式。

    对单个封包：检查哪些偏移上的整数值等于「总长度」或「剩余长度」；
    对多个连续帧：找重复出现的二进制标记（magic）推算步长。
    """
    total = len(blob)
    result: Dict[str, Any] = {
        "total_bytes": total,
        "hex": to_hex(blob[:64]) + (" ..." if total > 64 else ""),
        "length_field_candidates": [],
        "repeated_markers": [],
        "hexdump": hexdump(blob),
    }

    for offset in range(min(scan_offsets, max(total - 1, 0))):
        for width in (1, 2, 4):
            if offset + width > total:
                continue
            for endian in ("little", "big"):
                raw = blob[offset : offset + width]
                value = int.from_bytes(raw, endian)
                if value == 0:
                    continue
                if value == total:
                    note = "等于整包长度"
                elif value + offset + width == total:
                    note = "等于其后的负载长度"
                elif value + offset == total:
                    note = "等于从该字段起的长度"
                else:
                    continue
                result["length_field_candidates"].append(
                    {
                        "offset": offset,
                        "width": width,
                        "endian": endian,
                        "value": value,
                        "note": note,
                    }
                )

    # 重复标记：取前 2/4 字节作为候选 magic，统计出现位置
    for magic_len in (2, 4):
        if total < magic_len * 2:
            continue
        magic = blob[:magic_len]
        positions = []
        start = 0
        while True:
            index = blob.find(magic, start)
            if index < 0:
                break
            positions.append(index)
            start = index + 1
        if len(positions) >= 3:
            strides = [positions[i + 1] - positions[i] for i in range(len(positions) - 1)]
            result["repeated_markers"].append(
                {
                    "magic_hex": to_hex(magic),
                    "positions": positions[:12],
                    "strides": strides[:10],
                    "mean_stride": round(sum(strides) / len(strides), 1),
                }
            )

    if not result["length_field_candidates"]:
        result["hint"] = "没有偏移上的整数刚好等于总长/剩余长；可先用 packets_search 抓多条同类型封包再比对。"
    return result


def decode_payload(
    data_hex: str,
    mode: str = "auto",
    xor_key_hex: Optional[str] = None,
    limit: int = 8,
) -> Dict[str, Any]:
    data = parse_hex(data_hex)
    payload: Dict[str, Any] = {
        "bytes": len(data),
        "hex": to_hex(data[:96]) + (" ..." if len(data) > 96 else ""),
        "hexdump": hexdump(data),
    }

    if mode in ("auto", "text"):
        payload["text"] = {
            "utf8": as_text(data),
            "printable_ratio": round(printable_ratio(data), 3),
        }

    if mode in ("auto", "xor"):
        payload["xor_single_byte"] = xor_bruteforce(data, top=limit)

    if mode in ("auto", "base64"):
        decoded = try_base64(data.decode("latin-1", "ignore"))
        if decoded is not None:
            payload["base64"] = {
                "bytes": len(decoded),
                "text": as_text(decoded)[:200],
                "hex": to_hex(decoded[:96]),
                "printable_ratio": round(printable_ratio(decoded), 3),
            }

    if xor_key_hex:
        key = parse_hex(xor_key_hex)
        decoded = xor_with_key(data, key)
        payload["xor_known_key"] = {
            "key_hex": to_hex(key),
            "text": as_text(decoded)[:400],
            "hex": to_hex(decoded[:96]),
        }

    return payload
