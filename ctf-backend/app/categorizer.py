from __future__ import annotations

import re

import magic  # python-magic

from app.schemas import Category
from app.workspace import SavedFile

_TEXT_KEYWORDS = {
    Category.CRYPTO: ["cipher", "rsa", "aes", "xor", "encrypt", "decrypt", "base64", "hash", "modulus", "public key", "private key"],
    Category.STEGANOGRAPHY: ["stego", "hidden image", "lsb", "steghide", "zsteg", "spectrogram"],
    Category.FORENSICS: ["forensic", "metadata", "pcap", "memory dump", "disk image", "exif", "wireshark"],
    Category.ARCHIVE: ["zip", "archive", "7z", "rar", "tarball", "extract"],
    Category.WEB: ["http", "cookie", "sql injection", "xss", "endpoint", "api", "website", "url", "burp"],
}

_EXT_MAP = {
    Category.STEGANOGRAPHY: {".png", ".bmp", ".jpg", ".jpeg", ".wav", ".gif"},
    Category.ARCHIVE: {".zip", ".7z", ".rar", ".tar", ".gz", ".tgz"},
    Category.FORENSICS: {".pcap", ".pcapng", ".raw", ".img", ".dmp", ".mem"},
}

_MIME_MAP = {
    Category.STEGANOGRAPHY: {"image/png", "image/bmp", "image/jpeg", "audio/x-wav", "image/gif"},
    Category.ARCHIVE: {"application/zip", "application/x-7z-compressed", "application/x-rar", "application/x-tar", "application/gzip"},
    Category.FORENSICS: {"application/vnd.tcpdump.pcap", "application/octet-stream"},
}


_URL_RE = re.compile(r"https?://[^\s\"'<>]+")
_NC_CMD_RE = re.compile(r"\b(?:nc|ncat|netcat)\s+([\w.\-]+)\s+(\d{2,5})\b", re.IGNORECASE)
_HOST_PORT_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3}|[\w-]+(?:\.[\w-]+)+)[:\s](\d{2,5})\b")


def extract_targets(text: str) -> dict[str, list]:
    """Pull "launch instance"-style targets straight out of the free-text
    description: a URL for web challenges, or a `nc host port` / `host:port`
    line for pwn/misc challenges that hand you a raw socket instead of a file.
    """
    text = text or ""
    urls = _URL_RE.findall(text)

    nc_targets: list[tuple[str, int]] = []
    for host, port in _NC_CMD_RE.findall(text):
        nc_targets.append((host, int(port)))
    if not nc_targets:
        for host, port in _HOST_PORT_RE.findall(text):
            # skip anything that's actually part of a URL we already matched
            if any(host in u for u in urls):
                continue
            nc_targets.append((host, int(port)))

    return {"urls": urls, "nc_targets": nc_targets}


def _mime_of(saved: SavedFile) -> str:
    try:
        return magic.from_file(str(saved.path), mime=True)
    except Exception:  # noqa: BLE001 - magic lib can be finicky; degrade gracefully
        return "application/octet-stream"


def categorize(text: str, files: list[SavedFile]) -> list[Category]:
    """Return one or more categories, most-likely first.

    Heuristic, not authoritative — the tool pipeline runs every matched
    category's tools, and Gemini gets the final say in reasoning, so a
    slightly-too-broad match here is cheap; a missed one is not.
    """
    scores: dict[Category, int] = {c: 0 for c in Category}
    lowered = (text or "").lower()

    for cat, words in _TEXT_KEYWORDS.items():
        for w in words:
            if w in lowered:
                scores[cat] += 2

    for saved in files:
        ext = saved.path.suffix.lower()
        for cat, exts in _EXT_MAP.items():
            if ext in exts:
                scores[cat] += 3

        mime = _mime_of(saved)
        for cat, mimes in _MIME_MAP.items():
            if mime in mimes:
                scores[cat] += 3

        if ext in {".zip", ".7z", ".rar", ".tar", ".gz"}:
            scores[Category.ARCHIVE] += 3
        if not ext or ext in {".bin", ".dat"}:
            scores[Category.FORENSICS] += 1

    # bare base64/hex-looking text blob with no files -> almost certainly crypto/misc
    if files == [] and re.fullmatch(r"[A-Za-z0-9+/=\s]{16,}", text or ""):
        scores[Category.CRYPTO] += 4

    targets = extract_targets(text)
    if targets["urls"]:
        scores[Category.WEB] += 5
    if targets["nc_targets"]:
        scores[Category.NETWORK] += 5

    ranked = [c for c, s in sorted(scores.items(), key=lambda kv: kv[1], reverse=True) if s > 0]
    if not ranked:
        ranked = [Category.MISC]
    return ranked
