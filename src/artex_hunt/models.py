"""공유 데이터 모델."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

CONFIDENCE_RANK = {"low": 1, "medium": 2, "high": 3}


def confidence_at_least(level: str, minimum: str) -> bool:
    return CONFIDENCE_RANK[level] >= CONFIDENCE_RANK[minimum]


@dataclass
class Event:
    source: str
    line_no: int
    client_ip: str | None
    timestamp: datetime | None
    method: str | None
    path: str | None
    query: str | None
    status: int | None
    user_agent: str | None
    raw: str


@dataclass
class Finding:
    id: str
    confidence: str
    category: str
    title: str
    summary: str
    client: str | None
    count: int
    indicator_id: str | None
    false_positive_notes: str
    evidence: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "confidence": self.confidence,
            "category": self.category,
            "title": self.title,
            "summary": self.summary,
            "client": self.client,
            "count": self.count,
            "indicator_id": self.indicator_id,
            "false_positive_notes": self.false_positive_notes,
            "evidence": self.evidence,
        }
