"""artex-hunt 명령행."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from artex_hunt import __version__
from artex_hunt.models import CONFIDENCE_RANK
from artex_hunt.report import dumps_json, render_html, render_text
from artex_hunt.scan import overrides_from_flags, scan_host, scan_logs


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            report = scan_logs(
                [Path(path) for path in args.logs],
                log_format=args.format,
                indicator_path=args.indicators,
                overrides=overrides_from_flags(
                    args.window,
                    args.distinct_js,
                    args.distinct_api,
                    args.lookup_variants,
                    args.crawl_requests,
                ),
                heuristics_enabled=not args.no_heuristics,
                min_confidence=args.min_confidence,
            )
        else:
            report = scan_host(
                directory=args.directory,
                processes=args.processes,
                containers=args.containers,
                indicator_path=args.indicators,
                min_confidence=args.min_confidence,
            )
    except (OSError, ValueError, KeyError) as exc:
        print(f"오류: {exc}", file=sys.stderr)
        return 1

    text = render_text(report)
    sys.stdout.write(text)
    if args.json:
        args.json.write_text(dumps_json(report), encoding="utf-8")
    if args.html:
        args.html.write_text(render_html(report), encoding="utf-8")
    if args.fail_on:
        rank = CONFIDENCE_RANK[args.fail_on]
        if any(CONFIDENCE_RANK[item.confidence] >= rank for item in report.findings):
            return 2
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="artex-hunt",
        description="ARTEX 공개 지표와 행위 휴리스틱으로 로그·호스트를 점검합니다.",
    )
    parser.add_argument("--version", action="version", version=f"artex-hunt {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="웹 서버·WAF·프록시 로그를 스캔")
    scan.add_argument("logs", nargs="+", type=Path, help="로그 파일 경로")
    scan.add_argument(
        "--format",
        choices=("auto", "combined", "iis", "json"),
        default="auto",
        help="auto는 파일마다 combined, IIS W3C, JSON Lines를 구분",
    )
    _common(scan)
    scan.add_argument("--window", type=float, help="휴리스틱 시간 창(초)")
    scan.add_argument("--distinct-js", type=int, help="JS 자산 다양성 임계값")
    scan.add_argument("--distinct-api", type=int, help="API형 경로 다양성 임계값")
    scan.add_argument("--lookup-variants", type=int, help="조회 파라미터 값 종류 임계값")
    scan.add_argument("--crawl-requests", type=int, help="HTML 순회 요청 수 임계값")
    scan.add_argument(
        "--no-heuristics",
        action="store_true",
        help="검증된 User-Agent만 보고, 행위 휴리스틱은 끄기",
    )

    host = sub.add_parser("host", help="디렉터리·프로세스·컨테이너 목록에서 설치 흔적 점검")
    host.add_argument("--directory", type=Path, help="점검할 디렉터리")
    host.add_argument("--processes", type=Path, help="ps 출력 등 프로세스 목록 파일")
    host.add_argument("--containers", type=Path, help="docker ps JSON 또는 텍스트")
    _common(host)
    return parser


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--indicators", type=Path, help="지표 YAML 경로. 기본값은 패키지 내 파일")
    parser.add_argument(
        "--min-confidence",
        choices=tuple(CONFIDENCE_RANK),
        default="low",
        help="이 신뢰도보다 낮은 항목은 보고서에서 뺀다",
    )
    parser.add_argument("--json", type=Path, help="JSON 보고서 경로")
    parser.add_argument("--html", type=Path, help="HTML 보고서 경로")
    parser.add_argument(
        "--fail-on",
        choices=tuple(CONFIDENCE_RANK),
        help="해당 신뢰도 이상 항목이 있으면 종료 코드 2",
    )
