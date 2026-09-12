from __future__ import annotations

import json
import re

import google.generativeai as genai

from app.config import get_settings
from app.schemas import Category, ToolResult

FLAG_RE = re.compile(r"[A-Za-z0-9_]{2,20}\{[^\s{}]{3,300}\}")

SYSTEM_PROMPT = """\
You are an expert CTF (Capture The Flag) player helping analyze a challenge.
You will be given the player's own description of the challenge, the
categories an automated pipeline guessed, and raw output from forensics /
stego / crypto / archive tools that were run against the provided file(s).

Your job:
1. Read all the tool output carefully - the flag or a strong lead toward it
   is very often already sitting in there (in strings/exiftool/binwalk/zsteg/
   steghide/hexdump output, or in a decoded crypto heuristic result).
2. If you can find or derive the flag, return it. Flags typically look like
   something{...} (e.g. flag{...}, CTF{...}, picoCTF{...}) but follow
   whatever convention the prompt or evidence suggests.
3. If you cannot be certain, say so honestly and instead give the most useful
   next steps the player should try - do not invent a flag that isn't
   supported by the evidence.
4. Explain your reasoning clearly enough that the player learns the technique,
   not just the answer.

Respond ONLY with minified JSON, no markdown fences, matching exactly:
{"flag": "<the flag string, or null if not found>", "reasoning": "<your full explanation>"}
"""


def _format_evidence(text: str, categories: list[Category], tool_results: list[ToolResult]) -> str:
    parts = [f"Player prompt/description:\n{text.strip() or '(none provided)'}"]
    parts.append(f"\nGuessed categories: {', '.join(c.value for c in categories)}")
    parts.append("\nTool outputs:")
    for r in tool_results:
        status = "OK" if r.ok else "FAILED/EMPTY"
        detail = r.detail.strip() or "(no output)"
        parts.append(f"\n--- {r.tool} [{status}] :: {r.summary} ---\n{detail[:4000]}")
    return "\n".join(parts)


def _extract_flag_fallback(blob: str) -> str | None:
    match = FLAG_RE.search(blob)
    return match.group(0) if match else None


def ask_gemini(text: str, categories: list[Category], tool_results: list[ToolResult]) -> tuple[str | None, str, str]:
    """Returns (flag, reasoning, raw_model_text)."""
    settings = get_settings()
    if not settings.gemini_api_key:
        # no key configured -> degrade to the regex fallback over raw evidence
        # so the service still returns *something* useful instead of a 500
        combined = _format_evidence(text, categories, tool_results)
        flag = _extract_flag_fallback(combined)
        reasoning = (
            "GEMINI_API_KEY is not configured, so this is only a regex scan over "
            "the collected tool evidence rather than full reasoning. Set "
            "GEMINI_API_KEY to enable the actual reasoning step."
        )
        return flag, reasoning, ""

    genai.configure(api_key=settings.gemini_api_key)
    model = genai.GenerativeModel(settings.gemini_model, system_instruction=SYSTEM_PROMPT)
    evidence = _format_evidence(text, categories, tool_results)

    response = model.generate_content(
        evidence,
        generation_config={"response_mime_type": "application/json"},
    )
    raw = response.text or ""

    try:
        parsed = json.loads(raw)
        flag = parsed.get("flag")
        reasoning = parsed.get("reasoning", "")
    except (json.JSONDecodeError, AttributeError):
        flag = _extract_flag_fallback(raw)
        reasoning = raw or "Model returned an unparsable response; falling back to regex scan."

    if not flag:
        # last resort: scan the model's own reasoning text and the evidence itself
        flag = _extract_flag_fallback(raw) or _extract_flag_fallback(evidence)

    return flag, reasoning, raw
