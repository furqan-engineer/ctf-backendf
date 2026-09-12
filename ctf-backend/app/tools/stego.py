from __future__ import annotations

from pathlib import Path

from app.tools.runner import run_tool


def steghide_info(path: Path):
    # asks about embedded data without needing the passphrase
    return run_tool("steghide-info", ["steghide", "info", str(path), "-p", ""])


def steghide_extract_blank_pass(path: Path, outdir: Path):
    outdir.mkdir(parents=True, exist_ok=True)
    out_file = outdir / "steghide_out"
    return run_tool(
        "steghide-extract",
        ["steghide", "extract", "-sf", str(path), "-p", "", "-xf", str(out_file), "-f"],
    )


def zsteg_scan(path: Path):
    # zsteg only understands PNG/BMP; caller should only invoke it for those
    return run_tool("zsteg", ["zsteg", "-a", str(path)])


def zsteg_lsb_common(path: Path):
    return run_tool("zsteg-b1", ["zsteg", str(path), "-a", "--limit", "0"])
