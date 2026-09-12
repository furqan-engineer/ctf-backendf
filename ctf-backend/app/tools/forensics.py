from __future__ import annotations

from pathlib import Path

from app.tools.runner import run_tool


def identify_file(path: Path):
    return run_tool("file", ["file", "--brief", "--mime-type", str(path)])


def exiftool_metadata(path: Path):
    return run_tool("exiftool", ["exiftool", "-a", "-u", "-g1", str(path)])


def strings_dump(path: Path, min_len: int = 6):
    return run_tool("strings", ["strings", "-n", str(min_len), str(path)])


def binwalk_scan(path: Path):
    # -B: signature scan only (no extraction) -> fast + safe first pass
    return run_tool("binwalk", ["binwalk", "-B", str(path)])


def binwalk_extract(path: Path, outdir: Path):
    outdir.mkdir(parents=True, exist_ok=True)
    return run_tool("binwalk-extract", ["binwalk", "-e", "--dd=.*", "-C", str(outdir), str(path)])


def foremost_carve(path: Path, outdir: Path):
    outdir.mkdir(parents=True, exist_ok=True)
    return run_tool("foremost", ["foremost", "-i", str(path), "-o", str(outdir)])


def hexdump_head(path: Path, n_bytes: int = 512):
    return run_tool("xxd", ["xxd", "-l", str(n_bytes), str(path)])


def tesseract_ocr(path: Path):
    # tesseract writes "<outbase>.txt"; we ask it to print to stdout instead
    return run_tool("tesseract", ["tesseract", str(path), "stdout"])
