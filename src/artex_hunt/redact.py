"""증거 문자열에서 토큰·키 값을 가린다."""

from __future__ import annotations

import re

_SECRET = re.compile(
    r"(?i)"
    r"((?:authorization\s*[:=]\s*bearer\s+)"
    r"|(?:artex_token=)"
    r"|(?:(?:ARTEX_[A-Z0-9_]*|ANTHROPIC_API_KEY|OPENAI_API_KEY)=))"
    r"\S+"
)


def redact(text: str) -> str:
    def _sub(match: re.Match[str]) -> str:
        return match.group(1) + "<redacted>"

    return _SECRET.sub(_sub, text)
