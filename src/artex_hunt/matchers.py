"""검증된 User-Agent 지표 대조."""

from __future__ import annotations

from collections import defaultdict

from artex_hunt.indicators import Indicator
from artex_hunt.models import Event, Finding
from artex_hunt.redact import redact

_EVIDENCE_LIMIT = 5
_PARTIAL_MIN = 12


def match_user_agents(events: list[Event], indicators: list[Indicator]) -> list[Finding]:
    ordered = sorted(indicators, key=lambda item: len(item.value), reverse=True)
    buckets: dict[tuple[str, str, str], list[Event]] = defaultdict(list)
    kinds: dict[tuple[str, str, str], Indicator] = {}
    for event in events:
        ua = event.user_agent or ""
        if not ua:
            continue
        found = _exact(ua, ordered)
        kind = "exact"
        if found is None:
            found = _partial(ua, ordered)
            kind = "partial"
        if found is None:
            continue
        client = event.client_ip or "-"
        key = (found.id, client, kind)
        buckets[key].append(event)
        kinds[key] = found

    findings: list[Finding] = []
    for key, rows in buckets.items():
        indicator = kinds[key]
        kind = key[2]
        confidence = indicator.confidence if kind == "exact" else _partial_confidence(indicator)
        title = _title(indicator, kind)
        summary = indicator.purpose
        if kind == "partial":
            summary += " User-Agent 전체가 지표와 같지는 않고, 지표 문자열이 포함되어 있다."
        if indicator.direction == "outbound":
            summary += " 이 값은 대상 웹사이트로 들어오는 공격 요청의 지표가 아니다."
        findings.append(
            Finding(
                id=f"ua:{indicator.id}:{key[1]}:{kind}",
                confidence=confidence,
                category="user_agent",
                title=title,
                summary=summary,
                client=None if key[1] == "-" else key[1],
                count=len(rows),
                indicator_id=indicator.id,
                false_positive_notes=indicator.false_positives,
                evidence=[_evidence(event) for event in rows[:_EVIDENCE_LIMIT]],
            )
        )
    return findings


def _exact(ua: str, indicators: list[Indicator]) -> Indicator | None:
    folded = ua.casefold()
    for indicator in indicators:
        if folded == indicator.value.casefold():
            return indicator
    return None


def _partial(ua: str, indicators: list[Indicator]) -> Indicator | None:
    folded = ua.casefold()
    for indicator in indicators:
        if len(indicator.value) < _PARTIAL_MIN:
            continue
        if indicator.value.casefold() in folded:
            return indicator
    return None


def _partial_confidence(indicator: Indicator) -> str:
    if indicator.confidence == "high":
        return "medium"
    return "low"


def _title(indicator: Indicator, kind: str) -> str:
    if indicator.direction == "outbound":
        prefix = "업데이트 통신 User-Agent"
    else:
        prefix = "User-Agent 일치" if kind == "exact" else "User-Agent 부분 포함"
    return f"{prefix}: {indicator.value}"


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
