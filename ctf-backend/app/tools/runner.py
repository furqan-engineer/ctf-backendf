"""Shared, hardened subprocess runner for every CLI tool wrapper.

Rules enforced here so individual wrappers don't have to think about it:
- argv list only, never shell=True -> no shell injection via filenames/args
- hard timeout -> a hostile/huge file can't hang a worker forever
- captured output is size-capped -> can't exhaust memory with a giant strings dump
- never raises on tool failure; callers get a structured ToolResult instead
"""
from __future__ import annotations

import subprocess

from app.config import get_settings
from app.schemas import ToolResult

MAX_OUTPUT_CHARS = 20_000


def run_tool(tool_name: str, argv: list[str], *, timeout: int | None = None) -> ToolResult:
    settings = get_settings()
    timeout = timeout or settings.tool_timeout_seconds
    try:
        proc = subprocess.run(
            argv,
            shell=False,
            capture_output=True,
            timeout=timeout,
        )
        stdout = proc.stdout.decode("utf-8", errors="replace")
        stderr = proc.stderr.decode("utf-8", errors="replace")
        combined = (stdout + ("\n[stderr]\n" + stderr if stderr.strip() else ""))[:MAX_OUTPUT_CHARS]
        ok = proc.returncode == 0
        summary = f"{tool_name} exited {proc.returncode}"
        return ToolResult(tool=tool_name, ok=ok, summary=summary, detail=combined)
    except FileNotFoundError:
        return ToolResult(tool=tool_name, ok=False, summary=f"{tool_name} not installed", detail="")
    except subprocess.TimeoutExpired:
        return ToolResult(tool=tool_name, ok=False, summary=f"{tool_name} timed out after {timeout}s", detail="")
    except Exception as exc:  # noqa: BLE001 - we want a ToolResult, never a raise, here
        return ToolResult(tool=tool_name, ok=False, summary=f"{tool_name} error", detail=str(exc)[:MAX_OUTPUT_CHARS])
