"""행위 휴리스틱.

이 모듈의 적중은 ARTEX 확정이 아니다. 공개 소스의 기본 수집 스크립트가
남길 수 있는 요청 형태와, PLURA가 권고한 '반복 조회' 조사를 임계값으로 옮긴 것이다.
임계값은 기본값일 뿐이며 사건에서 측정된 공격 속도가 아니다.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from urllib.parse import parse_qsl

from artex_hunt.indicators import Heuristic
from artex_hunt.models import Event, Finding
from artex_hunt.redact import redact

_STATIC = (
    ".js",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".map",
    ".mp4",
    ".webp",
    ".pdf",
    ".zip",
)
_API = (
    "/api/",
    "/rest/",
    "/service/",
    "/services/",
    "/gateway/",
    "/graphql",
    "/ajax/",
    "/rpc/",
    "/admin/",
    "/backend/",
)
_LOOKUP_PARAMS = ("id", "q", "query", "keyword", "search", "account", "user", "userid", "no", "seq")
_EVIDENCE_LIMIT = 5


def evaluate(
    events: list[Event],
    heuristics: list[Heuristic],
    overrides: dict[str, float] | None = None,
    enabled: bool = True,
) -> list[Finding]:
    if not enabled:
        return []
    by_id = {item.id: item for item in heuristics}
    thresholds = _merged_thresholds(heuristics, overrides or {})
    grouped = _by_ip(events)
    findings: list[Finding] = []
    for ip, rows in grouped.items():
        findings.extend(_js_burst(ip, rows, by_id["js-asset-burst"], thresholds))
        findings.extend(_api_enum(ip, rows, by_id["api-path-diversity"], thresholds))
        findings.extend(_lookup(ip, rows, by_id["lookup-variation"], thresholds))
        findings.extend(_crawl(ip, rows, by_id["html-crawl-pace"], thresholds))
    return findings


def _merged_thresholds(heuristics: list[Heuristic], overrides: dict[str, float]) -> dict[str, float]:
    merged: dict[str, float] = {}
    for item in heuristics:
        merged.update(item.thresholds)
    merged.update(overrides)
    return merged


def _by_ip(events: list[Event]) -> dict[str, list[Event]]:
    grouped: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        if event.client_ip and event.timestamp is not None and event.path:
            grouped[event.client_ip].append(event)
    for rows in grouped.values():
        rows.sort(key=lambda item: item.timestamp or datetime.min)
    return grouped


def _windows(rows: list[Event], window: timedelta) -> list[list[Event]]:
    """같은 시각의 요청은 한 창으로 묶고, 그 창의 오른쪽 끝에서만 평가한다."""
    chosen: list[list[Event]] = []
    left = 0
    for right, event in enumerate(rows):
        assert event.timestamp is not None
        while rows[left].timestamp is not None and event.timestamp - rows[left].timestamp > window:
            left += 1
        next_row = rows[right + 1] if right + 1 < len(rows) else None
        if next_row is not None and next_row.timestamp == event.timestamp:
            continue
        chosen.append(rows[left : right + 1])
    return chosen


def _js_burst(ip: str, rows: list[Event], spec: Heuristic, thresholds: dict[str, float]) -> list[Finding]:
    need = int(thresholds["distinct_js"])
    window = timedelta(seconds=thresholds["window_seconds"])
    best: list[Event] | None = None
    best_count = 0
    for chunk in _windows(rows, window):
        js = [item for item in chunk if _is_js(item.path)]
        count = len({item.path for item in js})
        if count >= need and count > best_count:
            best = js
            best_count = count
    if not best:
        return []
    return [
        _finding(
            spec,
            ip,
            best_count,
            best,
            f"{ip}에서 {int(thresholds['window_seconds'])}초 안에 서로 다른 JS {best_count}건.",
        )
    ]


def _api_enum(ip: str, rows: list[Event], spec: Heuristic, thresholds: dict[str, float]) -> list[Finding]:
    need = int(thresholds["distinct_api"])
    window = timedelta(seconds=thresholds["window_seconds"])
    best: list[Event] | None = None
    best_count = 0
    for chunk in _windows(rows, window):
        api = [item for item in chunk if _is_api(item.path)]
        count = len({item.path for item in api})
        if count >= need and count > best_count:
            best = api
            best_count = count
    if not best:
        return []
    return [
        _finding(
            spec,
            ip,
            best_count,
            best,
            f"{ip}에서 {int(thresholds['window_seconds'])}초 안에 API형 경로 {best_count}종.",
        )
    ]


def _lookup(ip: str, rows: list[Event], spec: Heuristic, thresholds: dict[str, float]) -> list[Finding]:
    need = int(thresholds["lookup_variants"])
    window = timedelta(seconds=thresholds["window_seconds"])
    best_key: tuple[str, str] | None = None
    best_events: list[Event] = []
    best_count = 0
    for chunk in _windows(rows, window):
        grouped: dict[tuple[str, str], dict[str, Event]] = defaultdict(dict)
        for event in chunk:
            if not event.query or not event.path:
                continue
            for name, value in parse_qsl(event.query, keep_blank_values=False):
                if name.lower() not in _LOOKUP_PARAMS:
                    continue
                grouped[(event.path, name.lower())][value] = event
        for key, variants in grouped.items():
            if len(variants) >= need and len(variants) > best_count:
                best_key = key
                best_events = list(variants.values())
                best_count = len(variants)
    if best_key is None:
        return []
    path, param = best_key
    return [
        _finding(
            spec,
            ip,
            best_count,
            best_events,
            f"{ip}가 {path} 의 {param} 값을 {best_count}종 바꿨다.",
        )
    ]


def _crawl(ip: str, rows: list[Event], spec: Heuristic, thresholds: dict[str, float]) -> list[Finding]:
    need = int(thresholds["crawl_requests"])
    unique_need = int(thresholds["crawl_unique_paths"])
    gap_min = thresholds["crawl_gap_min"]
    gap_max = thresholds["crawl_gap_max"]
    window = timedelta(seconds=thresholds["window_seconds"])
    best: list[Event] | None = None
    best_count = 0
    best_span = 0.0
    for chunk in _windows(rows, window):
        pages = [item for item in chunk if item.path and not _is_static(item.path) and not _is_api(item.path)]
        if len(pages) < need or len({item.path for item in pages}) < unique_need:
            continue
        span = _span_seconds(pages)
        per_request = max(len(pages) - 1, 1)
        if span > gap_max * per_request:
            continue
        if span != 0 and span < gap_min * per_request:
            continue
        if len(pages) > best_count:
            best = pages
            best_count = len(pages)
            best_span = span
    if not best:
        return []
    return [
        _finding(
            spec,
            ip,
            best_count,
            best,
            f"{ip}의 HTML성 요청 {best_count}건이 {best_span:.0f}초 안에 몰려 있다.",
        )
    ]


def _finding(spec: Heuristic, ip: str, count: int, events: list[Event], detail: str) -> Finding:
    return Finding(
        id=f"heuristic:{spec.id}:{ip}",
        confidence=spec.confidence,
        category="heuristic",
        title=spec.title,
        summary=spec.summary + " " + detail,
        client=ip,
        count=count,
        indicator_id=spec.id,
        false_positive_notes=spec.false_positives,
        evidence=[_evidence(event) for event in events[:_EVIDENCE_LIMIT]],
    )


def _evidence(event: Event) -> dict[str, object]:
    target = event.path or ""
    if event.query:
        target = f"{target}?{event.query}"
    return {
        "source": event.source,
        "line": event.line_no,
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "client_ip": event.client_ip,
        "method": event.method,
        "target": redact(target)[:300],
        "status": event.status,
        "user_agent": redact(event.user_agent or "")[:300],
    }


def _span_seconds(events: list[Event]) -> float:
    stamps = [event.timestamp for event in events if event.timestamp is not None]
    if len(stamps) < 2:
        return 0.0
    return (stamps[-1] - stamps[0]).total_seconds()


def _is_js(path: str | None) -> bool:
    return bool(path) and path.lower().split("?", 1)[0].endswith(".js")


def _is_static(path: str) -> bool:
    lowered = path.lower().split("?", 1)[0]
    return lowered.endswith(_STATIC)


def _is_api(path: str | None) -> bool:
    if not path:
        return False
    lowered = path.lower()
    if any(token in lowered for token in _API):
        return True
    parts = [part for part in lowered.split("/") if part]
    return any(part.startswith("v") and part[1:].isdigit() for part in parts)
