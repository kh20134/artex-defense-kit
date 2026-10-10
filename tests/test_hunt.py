"""합성 로그만 사용한다. 실제 사고 로그나 ARTEX 실행이 아니다."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from artex_hunt.cli import main
from artex_hunt.indicators import load_catalog
from artex_hunt.redact import redact
from artex_hunt.report import render_html, render_text
from artex_hunt.scan import scan_host, scan_logs

FIXTURES = Path(__file__).parent / "fixtures"
ACCESS = FIXTURES / "synthetic_access.log"


def test_catalog_keeps_verified_user_agents_and_drops_rejected() -> None:
    catalog = load_catalog()
    active = {item.value for item in catalog.log_indicators()}
    assert "artex-enrich/1.0" in active
    assert "Mozilla/5.0 (spa-api-recon)" in active
    assert "Mozilla/5.0 (spa-api-recon spider)" in active
    assert "artex-selfupdate" in active
    rejected = {item.id: item for item in catalog.indicators if item.status == "rejected"}
    assert rejected["rejected-ua-worker-mock"].hunt_log is False
    assert rejected["rejected-api-path-list"].value == "/api/"
    contextual = [item for item in catalog.indicators if item.status == "contextual"]
    assert {item.value for item in contextual} == {"8787/tcp", "8788/tcp"}
    assert all(not item.hunt_host and not item.hunt_log for item in contextual)
    for item in catalog.indicators:
        if item.status == "active":
            assert item.sources
            assert item.false_positives
            assert item.purpose


def test_synthetic_access_log_confidence_levels() -> None:
    report = scan_logs([ACCESS])
    by_client = {}
    for finding in report.findings:
        by_client.setdefault(finding.client, []).append(finding)

    enrich = by_client["198.51.100.12"]
    assert any(item.confidence == "high" and item.indicator_id == "ua-artex-enrich" for item in enrich)

    spider = by_client["198.51.100.13"]
    assert len(spider) == 1
    assert spider[0].indicator_id == "ua-spa-api-recon-spider"
    assert spider[0].confidence == "high"

    harvest = by_client["198.51.100.14"]
    assert any(item.confidence == "high" and item.indicator_id == "ua-spa-api-recon" for item in harvest)
    js = next(item for item in harvest if item.indicator_id == "js-asset-burst")
    assert js.confidence == "medium"

    lookup = by_client["198.51.100.15"]
    assert lookup[0].indicator_id == "lookup-variation"
    assert lookup[0].confidence == "low"

    crawl = by_client["198.51.100.16"]
    assert crawl[0].indicator_id == "html-crawl-pace"
    assert crawl[0].confidence == "low"

    api = by_client["198.51.100.18"]
    assert api[0].indicator_id == "api-path-diversity"
    assert api[0].confidence == "low"

    partial = by_client["198.51.100.19"]
    assert partial[0].confidence == "medium"
    assert partial[0].indicator_id == "ua-spa-api-recon"

    update = by_client["198.51.100.20"]
    assert update[0].indicator_id == "ua-artex-selfupdate"
    assert update[0].confidence == "medium"
    assert "공격 요청의 지표가 아니다" in update[0].summary

    assert "198.51.100.10" not in by_client
    assert "198.51.100.11" not in by_client
    assert "198.51.100.17" not in by_client
    assert report.stats["skipped_lines"] >= 1


def test_worker_mock_user_agent_is_not_a_finding() -> None:
    report = scan_logs([ACCESS])
    blob = json.dumps([item.to_dict() for item in report.findings], ensure_ascii=False)
    assert "ARTEX-worker/1.0" not in blob


def test_thresholds_and_indicator_only_mode() -> None:
    strict = scan_logs(
        [ACCESS],
        overrides={
            "distinct_js": 100,
            "distinct_api": 100,
            "lookup_variants": 100,
            "crawl_requests": 100,
        },
    )
    assert all(item.category != "heuristic" for item in strict.findings)
    indicators_only = scan_logs([ACCESS], heuristics_enabled=False)
    assert indicators_only.findings
    assert all(item.category == "user_agent" for item in indicators_only.findings)
    highs = scan_logs([ACCESS], min_confidence="high")
    assert highs.findings
    assert all(item.confidence == "high" for item in highs.findings)


def test_iis_json_and_vhost_formats() -> None:
    iis = scan_logs([FIXTURES / "synthetic_iis.log"], heuristics_enabled=False)
    ids = {item.indicator_id for item in iis.findings}
    assert "ua-artex-enrich" in ids
    assert "ua-spa-api-recon-spider" in ids
    assert all(item.confidence == "high" for item in iis.findings)

    payload = scan_logs([FIXTURES / "synthetic_json.log"], heuristics_enabled=False)
    json_ids = {item.indicator_id for item in payload.findings}
    assert json_ids == {"ua-artex-enrich", "ua-spa-api-recon"}
    partial = next(item for item in payload.findings if item.client == "198.51.100.19")
    assert partial.confidence == "medium"

    vhost = scan_logs([FIXTURES / "synthetic_vhost.log"], heuristics_enabled=False)
    assert vhost.findings[0].client == "198.51.100.12"
    assert vhost.findings[0].confidence == "high"


def test_reports_are_korean_and_escape_html() -> None:
    report = scan_logs([ACCESS], min_confidence="high")
    text = render_text(report)
    assert "ARTEX 헌트 결과" in text
    assert "높음" in text
    assert "배제하지" in text
    page = render_html(report)
    assert 'lang="ko"' in page
    assert "<script>" not in page
    nasty = report.findings[0]
    nasty.evidence.append({"source": "x", "line": 1, "user_agent": "<script>alert(1)</script>", "target": "<b>"})
    escaped = render_html(report)
    assert "<script>alert" not in escaped
    assert "&lt;script&gt;" in escaped


def test_host_install_and_benign_directory() -> None:
    install = scan_host(directory=FIXTURES / "synthetic_host" / "install")
    ids = {item.indicator_id for item in install.findings}
    assert "host-image-autumn27-artex" in ids
    assert "host-console-title" in ids
    assert "host-console-description" in ids
    assert "host-artex-token-key" in ids
    assert "host-binary-name" in ids
    assert "host-path-harvest-static" in ids
    assert "host-path-spider" in ids
    assert "host-package-spa-api-recon-runtime" in ids
    assert "ctx-listen-8787" not in ids
    benign = scan_host(directory=FIXTURES / "synthetic_host" / "benign")
    assert benign.findings == []


def test_process_and_container_exports_redact_secrets() -> None:
    report = scan_host(
        processes=FIXTURES / "synthetic_processes.txt",
        containers=FIXTURES / "synthetic_containers.json",
    )
    ids = {item.indicator_id for item in report.findings}
    assert "host-binary-name" in ids
    assert "host-env-pg-dsn" in ids
    assert "host-env-update-token" in ids
    assert "host-image-autumn27-artex" in ids
    blob = json.dumps([item.to_dict() for item in report.findings], ensure_ascii=False)
    evidence = " ".join(str(item.get("detail", "")) for finding in report.findings for item in finding.evidence)
    assert "supersecret" not in blob
    assert "ghp_example" not in blob
    assert "<redacted>" in blob
    assert "artex-hunt" not in evidence
    text_containers = scan_host(containers=FIXTURES / "synthetic_containers.txt")
    assert any(item.indicator_id == "host-image-autumn27-artex" for item in text_containers.findings)
    assert text_containers.counts()["high"] == 1


def test_redact_helper() -> None:
    raw = "Authorization: Bearer sek.ret ARTEX_PG_DSN=postgres://artex:pw@db/artex"
    cleaned = redact(raw)
    assert "sek.ret" not in cleaned
    assert "pw@db" not in cleaned
    assert cleaned.count("<redacted>") == 2


def test_cli_writes_reports_and_exit_code(tmp_path: Path) -> None:
    json_path = tmp_path / "out.json"
    html_path = tmp_path / "out.html"
    code = main(
        [
            "scan",
            str(ACCESS),
            "--min-confidence",
            "high",
            "--json",
            str(json_path),
            "--html",
            str(html_path),
            "--fail-on",
            "high",
        ]
    )
    assert code == 2
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["summary"]["high"] >= 1
    assert payload["disclaimer"]
    assert "높음" in html_path.read_text(encoding="utf-8")
    clean = main(["host", "--directory", str(FIXTURES / "synthetic_host" / "benign"), "--fail-on", "low"])
    assert clean == 0
    missing = main(["host", "--directory", str(tmp_path / "missing")])
    assert missing == 1


def _run_cli(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "artex_hunt", *args],
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
    )


def test_json_and_html_follow_the_subcommand(tmp_path: Path) -> None:
    """README puts --json and --html after scan/host. The top-level parser does not accept them."""
    repo = Path(__file__).resolve().parents[1]
    scan_json = tmp_path / "scan.json"
    scan_html = tmp_path / "scan.html"
    host_json = tmp_path / "host.json"
    host_html = tmp_path / "host.html"

    scan = _run_cli(
        "scan",
        str(ACCESS),
        "--json",
        str(scan_json),
        "--html",
        str(scan_html),
        cwd=repo,
    )
    assert scan.returncode == 0, scan.stderr
    assert scan.stdout.startswith("ARTEX 헌트 결과")
    scan_payload = json.loads(scan_json.read_text(encoding="utf-8"))
    assert scan_payload["mode"] == "scan"
    assert scan_payload["schema_version"] == 1
    assert "로그 스캔" in scan_html.read_text(encoding="utf-8")

    host = _run_cli(
        "host",
        "--directory",
        str(FIXTURES / "synthetic_host" / "install"),
        "--processes",
        str(FIXTURES / "synthetic_processes.txt"),
        "--containers",
        str(FIXTURES / "synthetic_containers.json"),
        "--json",
        str(host_json),
        "--html",
        str(host_html),
        cwd=repo,
    )
    assert host.returncode == 0, host.stderr
    assert host.stdout.startswith("ARTEX 헌트 결과")
    host_payload = json.loads(host_json.read_text(encoding="utf-8"))
    assert host_payload["mode"] == "host"
    assert host_payload["findings"]
    assert "호스트 점검" in host_html.read_text(encoding="utf-8")

    for command in ("scan", "host"):
        misplaced_json = tmp_path / f"misplaced-{command}.json"
        misplaced_html = tmp_path / f"misplaced-{command}.html"
        misplaced = _run_cli(
            "--json",
            str(misplaced_json),
            "--html",
            str(misplaced_html),
            command,
            cwd=repo,
        )
        assert misplaced.returncode != 0
        assert "invalid choice" in misplaced.stderr
        assert not misplaced_json.exists()
        assert not misplaced_html.exists()
