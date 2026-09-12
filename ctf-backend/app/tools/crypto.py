"""Lightweight crypto identification/decoding helpers.

These are cheap, deterministic transforms worth trying automatically before
handing anything to Gemini - most "crypto" CTF misc/warmup challenges are just
one of these stacked once or twice.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import re

from app.schemas import ToolResult

FLAG_HINT_RE = re.compile(r"[A-Za-z0-9_]{2,20}\{[^\s{}]{3,200}\}")


def _looks_like_flag(text: str) -> bool:
    return bool(FLAG_HINT_RE.search(text))


def try_base64(text: str) -> ToolResult:
    candidate = text.strip()
    try:
        decoded = base64.b64decode(candidate + "=" * (-len(candidate) % 4), validate=False)
        out = decoded.decode("utf-8", errors="replace")
        ok = bool(out.strip())
        summary = "base64 decode succeeded" + (" (looks like a flag!)" if _looks_like_flag(out) else "")
        return ToolResult(tool="base64-decode", ok=ok, summary=summary, detail=out[:5000])
    except (binascii.Error, ValueError) as exc:
        return ToolResult(tool="base64-decode", ok=False, summary="not valid base64", detail=str(exc))


def try_hex(text: str) -> ToolResult:
    candidate = re.sub(r"[^0-9a-fA-F]", "", text)
    if len(candidate) < 4 or len(candidate) % 2 != 0:
        return ToolResult(tool="hex-decode", ok=False, summary="not valid hex", detail="")
    try:
        decoded = bytes.fromhex(candidate).decode("utf-8", errors="replace")
        summary = "hex decode succeeded" + (" (looks like a flag!)" if _looks_like_flag(decoded) else "")
        return ToolResult(tool="hex-decode", ok=True, summary=summary, detail=decoded[:5000])
    except ValueError as exc:
        return ToolResult(tool="hex-decode", ok=False, summary="hex decode failed", detail=str(exc))


def try_rot_all(text: str) -> ToolResult:
    hits = []
    for shift in range(1, 26):
        rotated = codecs.encode(text, f"rot{shift}") if shift == 13 else _rot_n(text, shift)
        if _looks_like_flag(rotated):
            hits.append(f"ROT{shift}: {rotated[:300]}")
    if hits:
        return ToolResult(tool="rot-brute", ok=True, summary=f"{len(hits)} rotation(s) look flag-like", detail="\n".join(hits))
    # still return the rot13 attempt for visibility even if nothing flag-shaped matched
    return ToolResult(tool="rot-brute", ok=False, summary="no rotation looked like a flag", detail=_rot_n(text, 13)[:2000])


def _rot_n(text: str, n: int) -> str:
    def shift_char(c: str) -> str:
        if c.isupper():
            return chr((ord(c) - 65 + n) % 26 + 65)
        if c.islower():
            return chr((ord(c) - 97 + n) % 26 + 97)
        return c

    return "".join(shift_char(c) for c in text)


def try_xor_single_byte(data: bytes) -> ToolResult:
    hits = []
    for key in range(256):
        out = bytes(b ^ key for b in data)
        try:
            decoded = out.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if _looks_like_flag(decoded):
            hits.append(f"key=0x{key:02x}: {decoded[:300]}")
    if hits:
        return ToolResult(tool="xor-single-byte-brute", ok=True, summary=f"{len(hits)} key(s) produced flag-like output", detail="\n".join(hits[:20]))
    return ToolResult(tool="xor-single-byte-brute", ok=False, summary="no single-byte XOR key produced flag-like text", detail="")


def try_base32(text: str) -> ToolResult:
    candidate = text.strip().upper()
    try:
        decoded = base64.b32decode(candidate + "=" * (-len(candidate) % 8)).decode("utf-8", errors="replace")
        summary = "base32 decode succeeded" + (" (looks like a flag!)" if _looks_like_flag(decoded) else "")
        return ToolResult(tool="base32-decode", ok=True, summary=summary, detail=decoded[:5000])
    except (binascii.Error, ValueError) as exc:
        return ToolResult(tool="base32-decode", ok=False, summary="not valid base32", detail=str(exc))


def run_all_text_heuristics(text: str) -> list[ToolResult]:
    """Run every cheap text-based crypto guess against a text blob/ciphertext."""
    results = [try_base64(text), try_hex(text), try_base32(text), try_rot_all(text)]
    try:
        raw = bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", text)) if re.fullmatch(r"[0-9a-fA-F\s]+", text) else text.encode("utf-8", errors="ignore")
        results.append(try_xor_single_byte(raw))
    except ValueError:
        pass
    return results
