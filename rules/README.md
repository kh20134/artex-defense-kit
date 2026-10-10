# 탐지 룰 예시

이 디렉터리의 Sigma, Suricata, ModSecurity 예시는 공개 소스에서 확인한 User-Agent 만 담는다. 운영에 넣기 전에 로그 표본으로 오탐을 보고, 인가된 점검 대역을 예외로 둔다.

룰은 도구 식별용이다. 일치해도 침해가 확정되지 않고, 없어도 ARTEX 요청이 없다고 볼 수 없다. LLM 이 만든 클라이언트는 User-Agent 가 없을 수 있고, 브라우저를 띄우는 런타임 스크립트는 이 문자열을 쓰지 않는다.

`ARTEX-worker/1.0` 과 `/api/` 같은 경로 접두사는 일부러 넣지 않았다. `artex-selfupdate` 는 아웃바운드 프록시용이며 인바운드 WAF 룰에 넣지 않는다.

기본 ModSecurity 예시는 `pass,log` 이다. `deny` 로 바꾸기 전에 탐지 전용으로 먼저 돌린다.
