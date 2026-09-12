"""Recon for "launch instance" web challenges - the player gets a URL, not a
file. No external CLI tool needed; everything here is a plain HTTP request
with a short timeout, since these targets are player-controlled/ephemeral
challenge instances, not arbitrary third-party sites.
"""
from __future__ import annotations

import re

import requests

from app.schemas import ToolResult

TIMEOUT = 8
COMMON_PATHS = [
    "/robots.txt", "/flag", "/flag.txt", "/.git/config", "/.env",
    "/admin", "/source", "/backup.zip", "/api", "/.well-known/security.txt",
]
COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)


def fetch_page(url: str) -> ToolResult:
    try:
        resp = requests.get(url, timeout=TIMEOUT, allow_redirects=True)
    except requests.RequestException as exc:
        return ToolResult(tool="http-fetch", ok=False, summary="request failed", detail=str(exc)[:2000])

    headers_blob = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    cookies_blob = "; ".join(f"{c.name}={c.value}" for c in resp.cookies)
    comments = COMMENT_RE.findall(resp.text or "")
    comments_blob = "\n---\n".join(c.strip()[:500] for c in comments) if comments else "(none found)"

    detail = (
        f"status: {resp.status_code}\n\n[headers]\n{headers_blob}\n\n"
        f"[cookies]\n{cookies_blob or '(none)'}\n\n"
        f"[html comments]\n{comments_blob}\n\n"
        f"[body, first 3000 chars]\n{(resp.text or '')[:3000]}"
    )
    return ToolResult(tool="http-fetch", ok=True, summary=f"HTTP {resp.status_code}", detail=detail[:20000])


def probe_common_paths(base_url: str) -> ToolResult:
    base = base_url.rstrip("/")
    hits = []
    for path in COMMON_PATHS:
        try:
            resp = requests.get(base + path, timeout=TIMEOUT, allow_redirects=False)
            if resp.status_code < 400:
                hits.append(f"{path} -> {resp.status_code} ({len(resp.content)} bytes)")
        except requests.RequestException:
            continue
    if hits:
        return ToolResult(tool="common-path-probe", ok=True, summary=f"{len(hits)} path(s) responded", detail="\n".join(hits))
    return ToolResult(tool="common-path-probe", ok=False, summary="no common paths responded", detail="")
