"""한국어 터미널 요약, JSON, HTML 보고서."""

from __future__ import annotations

import html
import json
from datetime import UTC, datetime
from typing import Any

from artex_hunt import __version__
from artex_hunt.scan import HuntReport

_LABEL = {"high": "높음", "medium": "중간", "low": "낮음"}
_MODE = {"scan": "로그 스캔", "host": "호스트 점검"}


def dumps_json(report: HuntReport) -> str:
    payload = {
        "tool": "artex-hunt",
        "version": __version__,
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "mode": report.mode,
        "inputs": report.inputs,
        "thresholds": report.thresholds,
        "stats": report.stats,
        "summary": report.counts(),
        "coverage_gaps": report.coverage_gaps,
        "analysis": {
            "repo": report.meta.get("repo"),
            "commit": report.meta.get("commit"),
            "verified_on": report.meta.get("verified_on"),
        },
        "findings": [finding.to_dict() for finding in report.findings],
        "disclaimer": (
            "지표 일치는 도구 식별 후보이다. 침해 성공이나 특정 사건과의 연관을 뜻하지 않는다. "
            "지표가 없어도 ARTEX 사용 가능성을 배제하지 않는다."
        ),
    }
    return json.dumps(payload, ensure_ascii=False, indent=2, default=str) + "\n"


def render_text(report: HuntReport) -> str:
    counts = report.counts()
    lines = [
        "ARTEX 헌트 결과",
        f"모드: {_MODE.get(report.mode, report.mode)}",
        f"입력: {', '.join(report.inputs) if report.inputs else '-'}",
        (f"신뢰도  높음 {counts['high']}  ·  중간 {counts['medium']}  ·  낮음 {counts['low']}"),
        f"파싱 통계: {json.dumps(report.stats, ensure_ascii=False)}",
        "",
    ]
    if not report.findings:
        lines.append("검증된 지표와 현재 임계값에 해당하는 항목이 없습니다.")
        lines.append("이 결과만으로 ARTEX 사용 가능성을 배제하지 않습니다.")
    for finding in report.findings:
        lines.append(f"[{_LABEL[finding.confidence]}] {finding.title}")
        client = finding.client or "-"
        lines.append(f"  대상: {client}  ·  건수: {finding.count}  ·  지표: {finding.indicator_id}")
        lines.append(f"  설명: {finding.summary}")
        lines.append(f"  오탐 참고: {finding.false_positive_notes}")
        for evidence in finding.evidence[:3]:
            lines.append(f"  증거: {_evidence_line(evidence)}")
        lines.append("")
    lines.append("다루는 범위 밖")
    for gap in report.coverage_gaps:
        lines.append(f"- {gap}")
    lines.append("")
    lines.append("판정 주의: User-Agent 일치만으로 침해를 확정하지 말고, 인가된 보안 점검인지부터 확인합니다.")
    return "\n".join(lines).rstrip() + "\n"


def render_html(report: HuntReport) -> str:
    counts = report.counts()
    rows = "\n".join(_finding_html(finding) for finding in report.findings)
    if not rows:
        rows = "<p class='empty'>검증된 지표와 현재 임계값에 해당하는 항목이 없습니다.</p>"
    gaps = "".join(f"<li>{html.escape(gap)}</li>" for gap in report.coverage_gaps)
    inputs = html.escape(", ".join(report.inputs))
    mode = html.escape(_MODE.get(report.mode, report.mode))
    version = html.escape(__version__)
    note = (
        "지표 일치는 도구 식별 후보입니다. 침해 성공이나 특정 금융권 사건과의 연관을 뜻하지 않습니다. "
        "지표가 없어도 사용 가능성을 배제하지 않습니다."
    )
    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ARTEX 헌트 결과</title>
<style>
  :root {{ color-scheme: light; }}
  body {{
    margin: 0; padding: 32px 20px 64px;
    font-family: "Noto Sans CJK KR", "Noto Sans KR", "Noto Sans CJK", "NanumGothic",
      "Malgun Gothic", sans-serif;
    background: #f6f4ef; color: #1c1917; line-height: 1.55;
  }}
  main {{ max-width: 920px; margin: 0 auto; }}
  h1 {{ font-size: 1.7rem; margin-bottom: 0.2rem; }}
  h2 {{ font-size: 1.15rem; margin-top: 2rem; }}
  .meta {{ color: #44403c; }}
  .counts {{ display: flex; gap: 12px; margin: 16px 0; }}
  .count {{ background: white; border: 1px solid #e7e5e4; border-radius: 10px; padding: 10px 14px; }}
  .finding {{ background: white; border: 1px solid #e7e5e4; border-radius: 12px; padding: 14px 16px; margin: 12px 0; }}
  .badge {{ display: inline-block; border-radius: 999px; padding: 2px 10px; font-size: 0.85rem; }}
  .high {{ background: #ffe4e6; color: #9f1239; }}
  .medium {{ background: #ffedd5; color: #9a3412; }}
  .low {{ background: #dbeafe; color: #1e3a8a; }}
  .note {{ background: #fffbeb; border: 1px solid #fde68a; border-radius: 10px; padding: 12px 14px; }}
  code {{ font-family: ui-monospace, "D2Coding", "Noto Sans Mono CJK KR", monospace; }}
  ul {{ padding-left: 1.2rem; }}
  .empty {{ background: white; border-radius: 12px; padding: 16px; }}
</style>
</head>
<body>
<main>
  <h1>ARTEX 헌트 결과</h1>
  <p class="meta">모드 {mode} · artex-hunt {version} · 입력 {inputs}</p>
  <div class="counts">
    <div class="count">높음 <strong>{counts["high"]}</strong></div>
    <div class="count">중간 <strong>{counts["medium"]}</strong></div>
    <div class="count">낮음 <strong>{counts["low"]}</strong></div>
  </div>
  <p class="note">{note}</p>
  <h2>항목</h2>
  {rows}
  <h2>다루는 범위 밖</h2>
  <ul>{gaps}</ul>
</main>
</body>
</html>
"""


def _finding_html(finding: Any) -> str:
    evidence = "".join(f"<li><code>{html.escape(_evidence_line(item))}</code></li>" for item in finding.evidence)
    client = html.escape(finding.client or "-")
    return (
        "<article class='finding'>"
        f"<p><span class='badge {html.escape(finding.confidence)}'>{_LABEL[finding.confidence]}</span> "
        f"<strong>{html.escape(finding.title)}</strong></p>"
        f"<p>대상 {client} · 건수 {finding.count} · 지표 <code>{html.escape(finding.indicator_id or '')}</code></p>"
        f"<p>{html.escape(finding.summary)}</p>"
        f"<p>오탐 참고: {html.escape(finding.false_positive_notes)}</p>"
        f"<ul>{evidence}</ul>"
        "</article>"
    )


def _evidence_line(evidence: dict[str, Any]) -> str:
    if "target" in evidence or "user_agent" in evidence:
        return (
            f"{evidence.get('source')}:{evidence.get('line')} "
            f"{evidence.get('client_ip') or '-'} {evidence.get('method') or ''} "
            f"{evidence.get('target') or ''} ua={evidence.get('user_agent') or '-'}"
        )
    if "path" in evidence:
        return f"{evidence.get('path')} ({evidence.get('note')})"
    return f"{evidence.get('source')}:{evidence.get('line')} {evidence.get('detail') or ''}"
