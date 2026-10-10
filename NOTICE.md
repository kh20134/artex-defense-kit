# 고지

artex-defense-kit 은 ARTEX 를 분석해 탐지와 방어에 쓰려고 새로 쓴 글과 코드이다. ARTEX 소스, 바이너리, 스킬 스크립트, 프롬프트, 페이로드는 포함하지 않는다.

ARTEX 는 Autumn-27 이 공개한 LLM 다중 에이전트 침투 테스트 시스템이고, 라이선스는 GNU Affero General Public License v3.0 이다. 2026-10-10 에 직접 읽은 공개 트리는 Hinln/ARTEX 커밋 `f3e3f54b6c93916388a0a3dc6a439893a9abe37a` 이다. 이 트리는 자신을 Autumn-27/ARTEX v0.3.15 백업으로 소개한다. 같은 날 Autumn-27/ARTEX 저장소는 공개 HTTPS 에서 404 였다.

지표로 남긴 문자열은 그 소스의 짧은 리터럴이다. 파일 경로와 줄 번호는 `src/artex_hunt/data/indicators.yaml` 과 `docs/analysis/` 에 적었다. 프로그램 표현을 옮기거나 개작한 것이 아니므로 이 저장소는 MIT 로 둔다. ARTEX 자체를 수정해 서비스로 제공하면 AGPL-3.0 의무는 그 수정본에 남는다.

공개 보고서:

- PLURA, 「[1보] 금융권 해킹 공격 IOC: ARTEX AI 관련 공개 지표와 즉시 점검 항목」, 2026-10-03. https://blog.plura.io/ko/respond/financial-sector-hacking-ioc-artex-1st-report/
- PLURA, 「ARTEX·LLM 모의시험: AI가 만든 웹 요청, WAF에는 무엇이 남았나?」, 2026-10-09. https://blog.plura.io/ko/column/howto-artex-llm/
- AhnLab ASEC, 「AI가 공격의 진입장벽을 낮춘다: 안랩이 추적한 ARTEX 인프라」, https://www.ahnlab.com/ko/contents/content-center/36299
- AhnLab ASEC, 「ARTEX의 진화: 안랩이 추적한 AI 기반 침투 테스트 인프라」, https://www.ahnlab.com/ko/contents/content-center/36300

PLURA 는 세 User-Agent 가 금융권 공격 로그로 검증된 값이 아니라고 밝혔다. 안랩은 노출된 콘솔을 추적했고, 그 시스템이 모두 악성 목적임을 뜻하지 않는다고 밝혔다. 이 저장소도 특정 사건과의 연관을 확정하지 않는다.

작성: 최규선 (정보관리기술사). 관련 글: https://최규선.com/posts/4
