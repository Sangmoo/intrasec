# intrasec

> 사내 웹 시스템(ERP, 그룹웨어, 업무 시스템)을 대상으로 하는 로컬 실행형 웹 보안 점검 도구

단일 실행 파일로 로컬 PC 에서 CLI(또는 웹 UI, M3 예정)로 **승인된 사내 시스템**의 보안 상태를 점검하고 리포트를 생성합니다.

## ⚠️ 사용 원칙

- **본인이 관리 권한을 가졌거나 서면 승인을 받은 시스템**에만 사용하십시오. 승인되지 않은 점검은 「정보통신망법」 등에 따라 처벌 대상이 될 수 있습니다.
- 운영 환경 능동 점검은 업무 장애를 유발할 수 있으므로 **스테이징 우선, 업무 외 시간 실행**을 원칙으로 합니다.
- 모든 점검은 `scope.yaml` 에 명시된 대상·시간대 안에서만 실행되며, 실행 기록은 감사 로그(`results/audit.log`)로 남습니다.

## 안전장치

| 항목 | 동작 |
|---|---|
| 스코프 강제 | 모든 요청은 `transport` 에서 호스트·포트·경로 검사, **DNS 해석 후 실제 연결 IP** 가 `allow.cidrs` 안인지 검사. 리다이렉트도 매 홉 재검사 |
| 시간대 | `engagement.window` 밖이면 엔진 시작 거부 |
| 점검 레벨 | `active` 점검은 `options.active_checks: true` 일 때만 엔진이 실행 |
| 메서드 | `DELETE` / `PUT` / `PATCH` 기본 차단 |
| 제외 경로 | logout, delete, approval/submit 등 위험 패턴 기본 제외 |
| 부하 | 기본 초당 5 요청, 연속 5xx 10회 시 자동 일시정지 |
| 민감정보 | 평문 `password:` 필드 거부(환경변수만), 근거의 쿠키·인증 헤더 마스킹 |
| 웹 UI | `127.0.0.1` 전용, 실행별 랜덤 토큰, Host/Origin 검증 |
| 운영 안전 모드 | `--safe` 또는 `options.safe_mode: true`: 초당 2요청·동시 1·호스트당 60요청 상한·연속 5xx 3회 일시정지·passive 전용, 경로 탐색은 `.git`/`.env`/디렉터리 리스팅만 |
| 사전 확인 | `--dry-run`: 요청 없이 시간대·적용 옵션·대상별 점검 목록 출력 |

### 운영 중인 시스템 점검

부하 테스트성 요청은 하지 않으며, 운영 시스템에는 다음 순서를 권장합니다.

```bash
./bin/intrasec scan -c scope.yaml --safe --dry-run     # 1. 계획 확인 (요청 없음)
./bin/intrasec scan -c scope.yaml --safe -o report.html  # 2. 저부하 점검
```

운영 안전 모드에서 생략되는 항목: PHP 경로 탐색(phpinfo, 관리 도구 등 — 헤더 기반 버전 판단은 수행), 백업 파일 탐색, 로그인 경로 탐색. 전체 점검은 스테이징에서 수행하십시오.

## 개발 환경 준비

| 도구 | 설치 |
|---|---|
| Go 1.27 이상 | https://go.dev/dl/ 에서 OS 별 설치 파일, 또는 Windows `winget install GoLang.Go` / macOS `brew install go` |
| make (Windows) | `winget install ezwinports.make` 또는 Git Bash 에서 실행. make 없이도 `go build -o bin/intrasec.exe ./cmd/intrasec` 로 빌드 가능 |
| golangci-lint (선택) | https://golangci-lint.run/welcome/install/ |
| Docker (실습 환경, 선택) | https://docs.docker.com/get-docker/ |

## 빠른 시작

```bash
make build                         # bin/intrasec
cp configs/scope.example.yaml scope.yaml   # 대상·승인 정보 작성
./bin/intrasec scope validate -c scope.yaml
./bin/intrasec checks list
./bin/intrasec scan -c scope.yaml -o report.html
./bin/intrasec report --scan-id <id> --format md -o report.md
```

로컬 실습 환경(Juice Shop, DVWA):

```bash
make run-lab
./bin/intrasec scan -c configs/scope.lab.yaml -o report.html
make test-integration     # Juice Shop 대상 통합 테스트
```

## 구조

```
cmd/intrasec/          CLI (serve, scan, report, checks, scope, version)
internal/scope/        scope.yaml 파싱·검증, IP 기준 허용 판단, 시간대 검사
internal/transport/    공통 HTTP 클라이언트 (스코프·레이트리밋·리다이렉트 재검사·마스킹)
internal/engine/       점검 오케스트레이션, 워커 풀, 레벨 강제
internal/checks/       점검 플러그인 (common / php / weblogic / xplatform / groupware)
internal/auth/         폼 로그인, 세션 유지, 만료 감지 후 재로그인
internal/report/       HTML / JSON / Markdown / SARIF 리포트
internal/audit/        감사 로그 (JSON Lines)
internal/server/       로컬 웹 UI API (토큰, Host 검증)
pkg/finding/           Finding 모델
```

점검 항목은 [docs/checks.md](docs/checks.md), 플러그인 작성법은 [docs/writing-checks.md](docs/writing-checks.md) 를 참고하십시오.

## 로드맵

- **M1** 엔진 기반 (CLI): scope, transport, engine, common 점검(헤더·TLS·쿠키·노출 파일·에러), PHP 점검, 리포트, Juice Shop 통합 테스트 — [v0.1.0](https://github.com/Sangmoo/intrasec/releases/tag/v0.1.0)
- **M2** 사내 시스템 특화 + 인증: auth(폼 로그인·재로그인), weblogic(WLS-001~004), xplatform(XP-001~002), HTML 리포트 — 구현 완료, 사내 스테이징 실전 점검 대기
- **M3** 웹 UI: server, store(SQLite), Svelte UI, GoReleaser
- **M4** 확장: Nuclei, groupware, SARIF, KISA 매핑, diff 리포트

## 라이선스

Apache License 2.0
