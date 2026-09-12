from __future__ import annotations

from pathlib import Path

from app.tools.runner import run_tool


def unzip_list(path: Path):
    # -l: list contents (also reveals hidden/dotfiles inside the archive)
    return run_tool("unzip-list", ["unzip", "-l", str(path)])


def unzip_extract(path: Path, outdir: Path):
    outdir.mkdir(parents=True, exist_ok=True)
    return run_tool("unzip-extract", ["unzip", "-o", str(path), "-d", str(outdir)])


def sevenzip_list(path: Path):
    return run_tool("7z-list", ["7z", "l", str(path)])


def sevenzip_extract(path: Path, outdir: Path):
    outdir.mkdir(parents=True, exist_ok=True)
    return run_tool("7z-extract", ["7z", "x", f"-o{outdir}", "-y", str(path)])
