from __future__ import annotations

from pathlib import Path

from app.categorizer import categorize, extract_targets
from app.schemas import Category, ToolResult
from app.tools import archive, crypto, forensics, network, stego, web
from app.workspace import SavedFile, Workspace

IMAGE_EXTS = {".png", ".bmp", ".jpg", ".jpeg", ".gif"}
ARCHIVE_EXTS = {".zip"}
SEVENZ_EXTS = {".7z"}


def _always_on(saved: SavedFile) -> list[ToolResult]:
    """Cheap, always-safe-to-run checks for every uploaded file, regardless
    of category: what is this file *actually*, and what metadata does it carry.
    Catches the classic "renamed extension" / "flag in EXIF" CTF tricks even
    when categorization guessed wrong.
    """
    results = [
        forensics.identify_file(saved.path),
        forensics.hexdump_head(saved.path),
        forensics.exiftool_metadata(saved.path),
    ]
    return results


def _run_forensics(saved: SavedFile, ws: Workspace) -> list[ToolResult]:
    results = [
        forensics.binwalk_scan(saved.path),
        forensics.strings_dump(saved.path),
    ]
    # only actually extract embedded files if the scan found signatures worth
    # pulling apart - keeps this fast for the common "nothing embedded" case
    scan = results[0]
    if scan.ok and scan.detail.strip().count("\n") > 1:
        outdir = ws.root / f"binwalk_{saved.path.stem}"
        results.append(forensics.binwalk_extract(saved.path, outdir))
    return results


def _run_stego(saved: SavedFile, ws: Workspace) -> list[ToolResult]:
    ext = saved.path.suffix.lower()
    results: list[ToolResult] = []
    if ext in {".png", ".bmp"}:
        results.append(stego.zsteg_scan(saved.path))
    if ext in {".jpg", ".jpeg", ".bmp", ".wav"}:
        results.append(stego.steghide_info(saved.path))
        outdir = ws.root / f"steghide_{saved.path.stem}"
        results.append(stego.steghide_extract_blank_pass(saved.path, outdir))
    if ext in IMAGE_EXTS:
        results.append(forensics.tesseract_ocr(saved.path))
    return results


def _run_archive(saved: SavedFile, ws: Workspace) -> list[ToolResult]:
    ext = saved.path.suffix.lower()
    outdir = ws.root / f"extracted_{saved.path.stem}"
    if ext in ARCHIVE_EXTS:
        return [archive.unzip_list(saved.path), archive.unzip_extract(saved.path, outdir)]
    if ext in SEVENZ_EXTS:
        return [archive.sevenzip_list(saved.path), archive.sevenzip_extract(saved.path, outdir)]
    # fall back to 7z which can usually at least list most archive formats
    return [archive.sevenzip_list(saved.path)]


_CATEGORY_RUNNERS = {
    Category.FORENSICS: _run_forensics,
    Category.STEGANOGRAPHY: _run_stego,
    Category.ARCHIVE: _run_archive,
}


def _run_web_targets(urls: list[str]) -> list[ToolResult]:
    """"Launch instance" web challenges: no file, just a URL the player was
    handed. Fetch it and probe a short list of common CTF-y paths.
    """
    results: list[ToolResult] = []
    for url in urls:
        results.append(web.fetch_page(url))
        results.append(web.probe_common_paths(url))
    return results


def _run_network_targets(nc_targets: list[tuple[str, int]]) -> list[ToolResult]:
    """"Launch instance" pwn/misc challenges: a `nc host port` line instead
    of a file. Grab whatever banner/prompt the service sends on connect.
    """
    return [network.banner_grab(host, port) for host, port in nc_targets]


def run_pipeline(text: str, files: list[SavedFile], ws: Workspace) -> tuple[list[Category], list[ToolResult]]:
    categories = categorize(text, files)
    results: list[ToolResult] = []

    for saved in files:
        results.extend(_always_on(saved))
        for cat in categories:
            runner = _CATEGORY_RUNNERS.get(cat)
            if runner:
                results.extend(runner(saved, ws))

    if Category.CRYPTO in categories and text.strip():
        results.extend(crypto.run_all_text_heuristics(text))

    # if there's no file at all and text looks like ciphertext, always try the
    # cheap crypto heuristics even if categorization leaned elsewhere
    if not files and text.strip() and Category.CRYPTO not in categories:
        results.extend(crypto.run_all_text_heuristics(text))

    # "launch instance" challenges: no file at all, just a URL or host:port
    # pulled straight out of the description text
    targets = extract_targets(text)
    if targets["urls"]:
        results.extend(_run_web_targets(targets["urls"]))
    if targets["nc_targets"]:
        results.extend(_run_network_targets(targets["nc_targets"]))

    return categories, results
