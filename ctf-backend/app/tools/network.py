"""Recon for `nc host port` style "launch instance" challenges (typically
pwn/misc). We can't solve binary exploitation blind, but grabbing the banner
and initial prompt text is often enough for Gemini to recognize the pattern
(a menu-driven challenge, a simple guessing game, a flag gated behind a
prompt, etc.) and reason about next steps or spot a flag handed out directly.
"""
from __future__ import annotations

import socket

from app.schemas import ToolResult

TIMEOUT = 6
MAX_RECV = 8000


def banner_grab(host: str, port: int) -> ToolResult:
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            sock.settimeout(TIMEOUT)
            chunks = []
            try:
                while True:
                    data = sock.recv(2048)
                    if not data:
                        break
                    chunks.append(data)
                    if sum(len(c) for c in chunks) >= MAX_RECV:
                        break
            except socket.timeout:
                pass  # normal - server may be waiting on input; we just wanted whatever it sent first
            received = b"".join(chunks).decode("utf-8", errors="replace")
            ok = bool(received.strip())
            summary = "connected, received data" if ok else "connected, no data before timeout"
            return ToolResult(tool="nc-banner-grab", ok=ok, summary=summary, detail=received[:MAX_RECV])
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as exc:
        return ToolResult(tool="nc-banner-grab", ok=False, summary="connection failed", detail=str(exc)[:1000])
