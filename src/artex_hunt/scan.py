"""로그 스캔과 호스트 점검을 하나의 결과로 모은다."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from artex_hunt.heuristics import evaluate
from artex_hunt.hostcheck import scan_containers, scan_directory, scan_processes
from artex_hunt.indicators import IndicatorCatalog, load_catalog
from artex_hunt.matchers import match_user_agents
from artex_hunt.models import Finding, confidence_at_least
from artex_hunt.parsers import parse_file

_THRESHOLD_FLAGS = {
    "window": "window_seconds",
    "distinct_js": "distinct_js",
    "distinct_api": "distinct_api",
    "lookup_variants": "lookup_variants",
    "crawl_requests": "crawl_requests",
}


@dataclass
class HuntReport:
    mode: str
    inputs: list[str]
    findings: list[Finding]
    coverage_gaps: list[str]
    thresholds: dict[str, float] = field(default_factory=dict)
    stats: dict[str, int] = field(default_factory=dict)
    meta: dict[str, Any] = field(default_factory=dict)

    def counts(self) -> dict[str, int]:
        counts = {"high": 0, "medium": 0, "low": 0}
        for finding in self.findings:
            counts[finding.confidence] = counts.get(finding.confidence, 0) + 1
        return counts


def scan_logs(
    paths: list[Path],
    *,
    log_format: str = "auto",
    indicator_path: Path | None = None,
    overrides: dict[str, float] | None = None,
    heuristics_enabled: bool = True,
    min_confidence: str = "low",
) -> HuntReport:
    catalog = load_catalog(indicator_path)
    events = []
    skipped = 0
    for path in paths:
        parsed, skipped_in_file = parse_file(path, log_format)
        events.extend(parsed)
        skipped += skipped_in_file
    user_agent_findings = match_user_agents(events, catalog.log_indicators())
    heuristic_findings = evaluate(
        events,
        catalog.heuristics,
        overrides=overrides,
        enabled=heuristics_enabled,
    )
    _corroborate(user_agent_findings, heuristic_findings)
    findings = [
        item
        for item in [*user_agent_findings, *heuristic_findings]
        if confidence_at_least(item.confidence, min_confidence)
    ]
    findings.sort(key=lambda item: ({"high": 0, "medium": 1, "low": 2}[item.confidence], item.id))
    return HuntReport(
        mode="scan",
        inputs=[str(path) for path in paths],
        findings=findings,
        coverage_gaps=list(catalog.coverage_gaps),
        thresholds=_effective_thresholds(catalog, overrides or {}),
        stats={"events": len(events), "skipped_lines": skipped, "files": len(paths)},
        meta=catalog.meta,
    )


def scan_host(
    *,
    directory: Path | None = None,
    processes: Path | None = None,
    containers: Path | None = None,
    indicator_path: Path | None = None,
    min_confidence: str = "low",
) -> HuntReport:
    if directory is None and processes is None and containers is None:
        raise ValueError("디렉터리, 프로세스 목록, 컨테이너 목록 중 하나 이상이 필요합니다")
    catalog = load_catalog(indicator_path)
    indicators = catalog.host_indicators()
    findings: list[Finding] = []
    inputs: list[str] = []
    if directory is not None:
        findings.extend(scan_directory(directory, indicators))
        inputs.append(str(directory))
    if processes is not None:
        findings.extend(scan_processes(processes, indicators))
        inputs.append(str(processes))
    if containers is not None:
        findings.extend(scan_containers(containers, indicators))
        inputs.append(str(containers))
    kept = [item for item in findings if confidence_at_least(item.confidence, min_confidence)]
    kept.sort(key=lambda item: ({"high": 0, "medium": 1, "low": 2}[item.confidence], item.id))
    return HuntReport(
        mode="host",
        inputs=inputs,
        findings=kept,
        coverage_gaps=list(catalog.coverage_gaps),
        stats={"sources": len(inputs)},
        meta=catalog.meta,
    )


def _corroborate(user_agents: list[Finding], heuristics: list[Finding]) -> None:
    confirmed = {
        finding.client for finding in user_agents if finding.confidence == "high" and finding.id.endswith(":exact")
    }
    for finding in heuristics:
        if finding.client in confirmed and finding.confidence == "low":
            finding.confidence = "medium"
            finding.summary += " 같은 출발지에서 검증된 User-Agent도 함께 보였다."


def _effective_thresholds(catalog: IndicatorCatalog, overrides: dict[str, float]) -> dict[str, float]:
    merged: dict[str, float] = {}
    for item in catalog.heuristics:
        merged.update(item.thresholds)
    merged.update({key: value for key, value in overrides.items() if value is not None})
    return merged


def overrides_from_flags(
    window: float | None,
    distinct_js: int | None,
    distinct_api: int | None,
    lookup_variants: int | None,
    crawl_requests: int | None,
) -> dict[str, float]:
    raw = {
        "window": window,
        "distinct_js": distinct_js,
        "distinct_api": distinct_api,
        "lookup_variants": lookup_variants,
        "crawl_requests": crawl_requests,
    }
    return {_THRESHOLD_FLAGS[name]: float(value) for name, value in raw.items() if value is not None}
