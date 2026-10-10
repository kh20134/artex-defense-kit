"""룰 파일은 검증된 문자열만 담고, 버린 지표는 탐지 조건에 넣지 않는다."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules"


def _text(relative: str) -> str:
    return (RULES / relative).read_text(encoding="utf-8")


def test_rules_include_verified_inbound_user_agents() -> None:
    combined = "\n".join(
        _text(name)
        for name in (
            "sigma/artex_recon_user_agent.yml",
            "suricata/artex_user_agents.rules",
            "modsecurity/artex-user-agents.conf",
        )
    )
    assert "artex-enrich/1.0" in combined
    assert "spa-api-recon" in combined
    assert "spider" in combined


def _active_lines(path: Path) -> str:
    kept = [line for line in path.read_text(encoding="utf-8").splitlines() if not line.strip().startswith("#")]
    return "\n".join(kept)


def test_rules_omit_rejected_indicators() -> None:
    rule_files = [path for path in RULES.rglob("*") if path.suffix in {".yml", ".rules", ".conf"}]
    combined = "\n".join(_active_lines(path) for path in rule_files)
    assert "ARTEX-worker/1.0" not in combined
    for path in rule_files:
        body = _active_lines(path)
        lowered = body.lower()
        assert ",deny" not in lowered
        assert " deny," not in lowered
        assert "/graphql/" not in body
        assert 'content:"/api/' not in body


def test_selfupdate_rule_is_not_an_inbound_waf_rule() -> None:
    sigma = _text("sigma/artex_selfupdate_user_agent.yml")
    assert "proxy" in sigma
    assert "inbound WAF" in sigma or "인바운드" in sigma or "Do not deploy this rule on an inbound WAF" in sigma
    modsec = _text("modsecurity/artex-user-agents.conf")
    rule = modsec.split("SecRule", 1)[1].split("#", 1)[0]
    assert "artex-selfupdate" not in rule
    assert "pass" in rule
    assert "log" in rule
