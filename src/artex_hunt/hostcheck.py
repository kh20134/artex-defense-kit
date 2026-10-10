"""비인가 설치를 찾기 위한 디렉터리·프로세스·컨테이너 점검.

포트 번호만으로 판정하지 않는다. 프로세스 인자에서 토큰 값은 출력 전에 가린다.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

from artex_hunt.indicators import Indicator
from artex_hunt.models import Finding
from artex_hunt.redact import redact

_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    ".ruff_cache",
    ".pytest_cache",
}
_TEXT_SUFFIXES = {
    ".html",
    ".htm",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".go",
    ".py",
    ".yml",
    ".yaml",
    ".json",
    ".sh",
    ".service",
    ".conf",
    ".env",
    ".toml",
    ".txt",
}
_MAX_BYTES = 1_000_000
_EVIDENCE_LIMIT = 8


def scan_directory(root: Path, indicators: list[Indicator]) -> list[Finding]:
    if not root.is_dir():
        raise FileNotFoundError(f"디렉터리가 없습니다: {root}")
    hits: dict[str, list[dict[str, object]]] = defaultdict(list)
    chosen = {
        item.id: item
        for item in indicators
        if item.type in {"file_name", "file_path", "file_content", "container_image"}
    }
    for path in _walk(root):
        relative = path.relative_to(root).as_posix()
        for indicator in chosen.values():
            if indicator.type == "file_name" and _name_matches(path.name, indicator):
                hits[indicator.id].append({"path": relative, "note": "파일 이름"})
            elif indicator.type == "file_path" and relative.endswith(indicator.value):
                hits[indicator.id].append({"path": relative, "note": "상대 경로"})
        text = _read_text(path)
        if text is None:
            continue
        for indicator in chosen.values():
            if indicator.type not in {"file_content", "container_image"}:
                continue
            if indicator.value in text or indicator.value.casefold() in text.casefold():
                hits[indicator.id].append({"path": relative, "note": "파일 내용"})
    return _group(hits, chosen, "호스트 파일", "directory")


def scan_processes(path: Path, indicators: list[Indicator]) -> list[Finding]:
    if not path.is_file():
        raise FileNotFoundError(f"프로세스 목록이 없습니다: {path}")
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    hits: dict[str, list[dict[str, object]]] = defaultdict(list)
    chosen = {item.id: item for item in indicators if item.type in {"file_name", "process_env"}}
    for line_no, line in enumerate(lines, start=1):
        if not line.strip() or line.startswith("#"):
            continue
        for indicator in chosen.values():
            if indicator.type == "file_name" and _command_matches(line, indicator):
                hits[indicator.id].append(_line_evidence(path.name, line_no, line))
            elif indicator.type == "process_env" and _token_in(line, indicator.value):
                hits[indicator.id].append(_line_evidence(path.name, line_no, line))
    return _group(hits, chosen, "프로세스 목록", "process")


def scan_containers(path: Path, indicators: list[Indicator]) -> list[Finding]:
    if not path.is_file():
        raise FileNotFoundError(f"컨테이너 목록이 없습니다: {path}")
    text = path.read_text(encoding="utf-8", errors="replace")
    hits: dict[str, list[dict[str, object]]] = defaultdict(list)
    chosen = {item.id: item for item in indicators if item.type == "container_image"}
    records = _container_records(text)
    if records:
        for index, record in enumerate(records, start=1):
            image = str(record.get("Image") or record.get("image") or "")
            for indicator in chosen.values():
                if indicator.value.casefold() in image.casefold():
                    hits[indicator.id].append(
                        {
                            "source": path.name,
                            "line": index,
                            "detail": redact(image)[:300],
                        }
                    )
    else:
        for line_no, line in enumerate(text.splitlines(), start=1):
            for indicator in chosen.values():
                if indicator.value.casefold() in line.casefold():
                    hits[indicator.id].append(_line_evidence(path.name, line_no, line))
    return _group(hits, chosen, "컨테이너 목록", "container")


def _walk(root: Path) -> list[Path]:
    found: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        found.append(path)
    return found


def _read_text(path: Path) -> str | None:
    if path.suffix.lower() not in _TEXT_SUFFIXES and path.name.lower() not in {
        "dockerfile",
        "start.sh",
        "start.bat",
    }:
        return None
    try:
        if path.stat().st_size > _MAX_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:4096]:
        return None
    return data.decode("utf-8", errors="replace")


def _name_matches(name: str, indicator: Indicator) -> bool:
    folded = name.casefold()
    return folded in {value.casefold() for value in indicator.values}


def _command_matches(line: str, indicator: Indicator) -> bool:
    for value in indicator.values:
        pattern = rf"(?<![A-Za-z0-9._-]){re.escape(value)}(?![A-Za-z0-9._-])"
        if re.search(pattern, line, flags=re.IGNORECASE):
            return True
    return False


def _token_in(line: str, value: str) -> bool:
    pattern = rf"(?<![A-Za-z0-9_]){re.escape(value)}(?![A-Za-z0-9_])"
    return re.search(pattern, line) is not None


def _container_records(text: str) -> list[dict[str, object]]:
    stripped = text.strip()
    if not stripped:
        return []
    if stripped.startswith("["):
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            return []
        if isinstance(payload, list) and all(isinstance(item, dict) for item in payload):
            return payload
        return []
    records: list[dict[str, object]] = []
    json_lines = 0
    for line in stripped.splitlines():
        if not line.strip().startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            return []
        if not isinstance(payload, dict):
            return []
        records.append(payload)
        json_lines += 1
    if json_lines and json_lines == len([line for line in stripped.splitlines() if line.strip()]):
        return records
    return []


def _line_evidence(source: str, line_no: int, line: str) -> dict[str, object]:
    return {"source": source, "line": line_no, "detail": redact(line.strip())[:300]}


def _group(
    hits: dict[str, list[dict[str, object]]],
    chosen: dict[str, Indicator],
    where: str,
    slug: str,
) -> list[Finding]:
    findings: list[Finding] = []
    for indicator_id, evidence in hits.items():
        indicator = chosen[indicator_id]
        unique = _unique(evidence)
        findings.append(
            Finding(
                id=f"host:{slug}:{indicator.id}",
                confidence=indicator.confidence,
                category="host",
                title=f"{where}: {indicator.value}",
                summary=indicator.purpose,
                client=None,
                count=len(unique),
                indicator_id=indicator.id,
                false_positive_notes=indicator.false_positives,
                evidence=unique[:_EVIDENCE_LIMIT],
            )
        )
    return findings


def _unique(evidence: list[dict[str, object]]) -> list[dict[str, object]]:
    seen: set[str] = set()
    unique: list[dict[str, object]] = []
    for item in evidence:
        key = json.dumps(item, ensure_ascii=False, sort_keys=True, default=str)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique
