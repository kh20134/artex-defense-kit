"""웹 서버·프록시 접근 로그 파서.

지원 형식은 nginx/apache combined, IIS W3C, JSON Lines 이다.
시각의 월 이름은 로케일과 무관하게 영어 약자만 받는다.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from artex_hunt.models import Event

_MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

_COMBINED = re.compile(
    r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<request>[^\"]*)\" "
    r"(?P<status>\d{3}) \S+ \"[^\"]*\" \"(?P<ua>[^\"]*)\""
)
_COMBINED_VHOST = re.compile(
    r"^\S+ (?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<request>[^\"]*)\" "
    r"(?P<status>\d{3}) \S+ \"[^\"]*\" \"(?P<ua>[^\"]*)\""
)
_COMBINED_TIME = re.compile(
    r"(?P<day>\d{2})/(?P<mon>[A-Za-z]{3})/(?P<year>\d{4}):"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2}) (?P<zone>[+-]\d{4})"
)

_UA_KEYS = ("user_agent", "useragent", "ua", "http_user_agent", "cs-user-agent", "cs(user-agent)")
_IP_KEYS = ("client_ip", "remote_addr", "c_ip", "c-ip", "ip", "src_ip", "source_ip")
_PATH_KEYS = ("path", "uri", "url", "request_uri", "cs-uri-stem", "cs_uri_stem")
_QUERY_KEYS = ("query", "args", "cs-uri-query", "cs_uri_query")
_TIME_KEYS = ("timestamp", "time", "ts", "datetime", "@timestamp")
_METHOD_KEYS = ("method", "cs-method", "cs_method", "verb")
_STATUS_KEYS = ("status", "sc-status", "sc_status", "status_code")


def parse_file(path: Path, log_format: str = "auto") -> tuple[list[Event], int]:
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    chosen = log_format if log_format != "auto" else detect_format(lines)
    if chosen == "json":
        return _parse_json_lines(path.name, lines)
    if chosen == "iis":
        return _parse_iis(path.name, lines)
    return _parse_combined(path.name, lines)


def detect_format(lines: list[str]) -> str:
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("{") or stripped.startswith("["):
            return "json"
        if stripped.startswith("#Software") or stripped.startswith("#Fields"):
            return "iis"
        return "combined"
    return "combined"


def parse_combined_time(value: str) -> datetime | None:
    match = _COMBINED_TIME.search(value)
    if not match:
        return None
    month = _MONTHS.get(match.group("mon"))
    if month is None:
        return None
    zone = match.group("zone")
    tz = _zone(zone)
    return datetime(
        int(match.group("year")),
        month,
        int(match.group("day")),
        int(match.group("hour")),
        int(match.group("minute")),
        int(match.group("second")),
        tzinfo=tz,
    )


def split_target(target: str) -> tuple[str | None, str | None]:
    if not target or target == "-":
        return None, None
    path, _, query = target.partition("?")
    return path or None, query or None


def _parse_combined(source: str, lines: list[str]) -> tuple[list[Event], int]:
    events: list[Event] = []
    skipped = 0
    for line_no, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        match = _COMBINED.match(line) or _COMBINED_VHOST.match(line)
        if not match:
            skipped += 1
            continue
        method, path, query = _split_request(match.group("request"))
        status_text = match.group("status")
        events.append(
            Event(
                source=source,
                line_no=line_no,
                client_ip=match.group("ip"),
                timestamp=parse_combined_time(match.group("time")),
                method=method,
                path=path,
                query=query,
                status=int(status_text) if status_text.isdigit() else None,
                user_agent=_empty(match.group("ua")),
                raw=line,
            )
        )
    return events, skipped


def _parse_iis(source: str, lines: list[str]) -> tuple[list[Event], int]:
    fields: list[str] | None = None
    events: list[Event] = []
    skipped = 0
    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            if stripped.lower().startswith("#fields:"):
                fields = stripped.split(":", 1)[1].strip().split()
            continue
        if not fields:
            skipped += 1
            continue
        parts = stripped.split()
        if len(parts) != len(fields):
            skipped += 1
            continue
        row = dict(zip(fields, parts, strict=True))
        stem = _field(row, "cs-uri-stem")
        query = _field(row, "cs-uri-query")
        if query == "-":
            query = None
        ua = _field(row, "cs(User-Agent)")
        if ua:
            ua = ua.replace("+", " ")
        timestamp = _iis_time(row.get("date"), row.get("time"))
        status_text = _field(row, "sc-status") or ""
        events.append(
            Event(
                source=source,
                line_no=line_no,
                client_ip=_field(row, "c-ip"),
                timestamp=timestamp,
                method=_field(row, "cs-method"),
                path=stem,
                query=query,
                status=int(status_text) if status_text.isdigit() else None,
                user_agent=ua,
                raw=line,
            )
        )
    return events, skipped


def _parse_json_lines(source: str, lines: list[str]) -> tuple[list[Event], int]:
    events: list[Event] = []
    skipped = 0
    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            skipped += 1
            continue
        rows = payload if isinstance(payload, list) else [payload]
        for row in rows:
            if not isinstance(row, dict):
                skipped += 1
                continue
            lowered = {str(key).lower(): value for key, value in row.items()}
            path, query = _json_path(lowered)
            status_value = _first(lowered, _STATUS_KEYS)
            status: int | None = None
            if isinstance(status_value, int):
                status = status_value
            elif isinstance(status_value, str) and status_value.isdigit():
                status = int(status_value)
            ua = _first(lowered, _UA_KEYS)
            ip = _first(lowered, _IP_KEYS)
            method = _first(lowered, _METHOD_KEYS)
            events.append(
                Event(
                    source=source,
                    line_no=line_no,
                    client_ip=str(ip) if ip else None,
                    timestamp=_json_time(_first(lowered, _TIME_KEYS)),
                    method=str(method) if method else None,
                    path=path,
                    query=query,
                    status=status,
                    user_agent=str(ua) if ua else None,
                    raw=line,
                )
            )
    return events, skipped


def _json_path(row: dict[str, object]) -> tuple[str | None, str | None]:
    raw_path = _first(row, _PATH_KEYS)
    raw_query = _first(row, _QUERY_KEYS)
    path = str(raw_path) if raw_path else None
    query = str(raw_query) if raw_query else None
    if path and "://" in path:
        split = urlsplit(path)
        path = split.path or "/"
        query = query or (split.query or None)
    elif path and "?" in path:
        path, _, embedded = path.partition("?")
        query = query or embedded or None
    if query == "-":
        query = None
    return path, query


def _json_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    text = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        parsed = parse_combined_time(text)
        if parsed is None:
            return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def _iis_time(date_text: str | None, time_text: str | None) -> datetime | None:
    if not date_text or not time_text:
        return None
    try:
        parsed = datetime.strptime(f"{date_text} {time_text}", "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC)


def _split_request(request: str) -> tuple[str | None, str | None, str | None]:
    parts = request.split()
    if len(parts) >= 2 and parts[0].isalpha() and parts[0].isupper():
        method = parts[0]
        target = parts[1]
    elif parts:
        method = None
        target = parts[0]
    else:
        return None, None, None
    path, query = split_target(target)
    return method, path, query


def _field(row: dict[str, str], name: str) -> str | None:
    value = row.get(name)
    if value is None or value == "-":
        return None
    return value


def _first(row: dict[str, object], keys: tuple[str, ...]) -> object | None:
    for key in keys:
        if key in row and row[key] not in (None, "", "-"):
            return row[key]
    return None


def _empty(value: str) -> str | None:
    if not value or value == "-":
        return None
    return value


def _zone(text: str) -> datetime.tzinfo:
    sign = 1 if text[0] == "+" else -1
    hours = int(text[1:3])
    minutes = int(text[3:5])
    return timezone(sign * timedelta(hours=hours, minutes=minutes))
