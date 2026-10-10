"""지표 YAML을 읽고, 로그 헌트와 호스트 헌트에 쓸 항목만 고른다."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from artex_hunt.models import CONFIDENCE_RANK


@dataclass
class Indicator:
    id: str
    status: str
    type: str
    value: str
    match: str
    direction: str
    confidence: str
    purpose: str
    false_positives: str
    sources: list[dict[str, Any]] = field(default_factory=list)
    hunt_log: bool = False
    hunt_host: bool = False
    also_values: list[str] = field(default_factory=list)

    @property
    def values(self) -> list[str]:
        return [self.value, *self.also_values]


@dataclass
class Heuristic:
    id: str
    confidence: str
    title: str
    summary: str
    false_positives: str
    thresholds: dict[str, float]
    sources: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class IndicatorCatalog:
    meta: dict[str, Any]
    indicators: list[Indicator]
    heuristics: list[Heuristic]
    coverage_gaps: list[str]

    def log_indicators(self) -> list[Indicator]:
        return [item for item in self.indicators if item.hunt_log and item.status == "active"]

    def host_indicators(self) -> list[Indicator]:
        return [item for item in self.indicators if item.hunt_host and item.status == "active"]

    def heuristic(self, heuristic_id: str) -> Heuristic:
        for item in self.heuristics:
            if item.id == heuristic_id:
                return item
        raise KeyError(heuristic_id)


def default_indicator_path() -> Path:
    return Path(__file__).resolve().parent / "data" / "indicators.yaml"


def load_catalog(path: Path | None = None) -> IndicatorCatalog:
    indicator_path = path or default_indicator_path()
    raw = yaml.safe_load(indicator_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"지표 파일 형식이 올바르지 않습니다: {indicator_path}")

    indicators: list[Indicator] = []
    for entry in raw.get("indicators", []):
        confidence = str(entry["confidence"])
        if entry["status"] == "active" and confidence not in CONFIDENCE_RANK:
            raise ValueError(f"{entry['id']}: confidence 값이 올바르지 않습니다")
        indicators.append(
            Indicator(
                id=str(entry["id"]),
                status=str(entry["status"]),
                type=str(entry["type"]),
                value=str(entry["value"]),
                match=str(entry.get("match", "exact")),
                direction=str(entry.get("direction", "")),
                confidence=confidence,
                purpose=str(entry.get("purpose", "")),
                false_positives=str(entry.get("false_positives", "")),
                sources=list(entry.get("sources", [])),
                hunt_log=bool(entry.get("hunt_log", False)),
                hunt_host=bool(entry.get("hunt_host", False)),
                also_values=[str(value) for value in entry.get("also_values", [])],
            )
        )

    heuristics: list[Heuristic] = []
    for entry in raw.get("heuristics", []):
        heuristics.append(
            Heuristic(
                id=str(entry["id"]),
                confidence=str(entry["confidence"]),
                title=str(entry["title"]),
                summary=str(entry["summary"]),
                false_positives=str(entry.get("false_positives", "")),
                thresholds={key: float(value) for key, value in entry.get("thresholds", {}).items()},
                sources=list(entry.get("sources", [])),
            )
        )

    gaps = [str(item) for item in raw.get("coverage_gaps", [])]
    return IndicatorCatalog(
        meta=dict(raw.get("meta", {})),
        indicators=indicators,
        heuristics=heuristics,
        coverage_gaps=gaps,
    )
