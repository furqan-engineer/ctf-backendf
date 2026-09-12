"""Per-request isolated workspace for uploaded files.

Never trust client-supplied filenames for paths. Every uploaded file is written
under a random uuid directory with a random-ish safe name; the *original*
filename is kept only as metadata (useful for extension-based hints) and never
used to build a filesystem path.
"""
from __future__ import annotations

import shutil
import uuid
from dataclasses import dataclass, field
from pathlib import Path

BASE_DIR = Path("/tmp/ctf-backend-jobs")
BASE_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class SavedFile:
    path: Path
    original_name: str
    size: int


@dataclass
class Workspace:
    root: Path
    files: list[SavedFile] = field(default_factory=list)

    def cleanup(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


def new_workspace() -> Workspace:
    root = BASE_DIR / uuid.uuid4().hex
    root.mkdir(parents=True, exist_ok=True)
    return Workspace(root=root)


def _safe_suffix(original_name: str) -> str:
    # keep only a short, alnum/dot/dash/underscore suffix (extension hint),
    # everything else about the client filename is discarded
    suffix = Path(original_name).suffix
    if 1 < len(suffix) <= 10 and all(c.isalnum() or c in ".-_" for c in suffix):
        return suffix
    return ""


def save_upload(ws: Workspace, original_name: str, content: bytes) -> SavedFile:
    safe_name = f"{uuid.uuid4().hex}{_safe_suffix(original_name)}"
    dest = ws.root / safe_name
    dest.write_bytes(content)
    saved = SavedFile(path=dest, original_name=original_name or safe_name, size=len(content))
    ws.files.append(saved)
    return saved
