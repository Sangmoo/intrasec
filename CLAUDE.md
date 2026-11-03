# intrasec

> 사내 웹 시스템(ERP, 그룹웨어, 업무 시스템)을 대상으로 하는 로컬 실행형 웹 보안 점검 도구

`intrasec`은 단일 실행 파일로 배포되며, 로컬 PC에서 웹 UI 또는 CLI로 **승인된 사내 시스템**의 보안 상태를 점검하고 리포트를 생성합니다.

---

## ⚠️ 사용 원칙

- 이 도구는 **본인이 관리 권한을 가졌거나 서면 승인을 받은 시스템**에만 사용해야 합니다.
- 승인되지 않은 시스템에 대한 점검은 「정보통신망 이용촉진 및 정보보호 등에 관한 법률」 등에 따라 처벌 대상이 될 수 있습니다.
- 운영 환경 능동 점검은 업무 장애를 유발할 수 있으므로 **스테이징 환경 우선, 업무 외 시간 실행**을 원칙으로 합니다.
- 모든 점검은 `scope.yaml`에 명시된 대상·시간대 안에서만 실행되며, 실행 기록은 감사 로그로 남습니다.

---

## 1. 프로젝트 목표

### 목표
- 바이너리 하나로 설치 없이 실행 (Windows / macOS / Linux)
- 로컬 웹 UI에서 점검 설정 → 실행 → 결과 확인 → 리포트 다운로드
- 자동화를 위한 CLI 모드 동시 지원 (동일 엔진 공유)
- 사내 시스템 특화 점검: WebLogic, XPlatform/MiPlatform 서비스 URL, 그룹웨어
- 실무 보고용 HTML 리포트 (인쇄 시 PDF 변환 가능)
- OWASP Top 10, CWE, KISA 웹 취약점 점검 항목 매핑

### 비목표 (하지 않는 것)
- 익스플로잇 코드 작성 및 실제 침투 (취약점 **존재 근거 확인**까지만)
- 인터넷상 임의의 외부 사이트 스캔
- 데이터 변경·삭제를 유발하는 요청 (기본 비활성)
- 서비스 거부(DoS) 성격의 부하 테스트

---

## 2. 기술 스택

| 영역 | 선택 | 비고 |
|---|---|---|
| 언어 | Go (최신 안정 버전) | `CGO_ENABLED=0` 정적 빌드 |
| CLI | `spf13/cobra` | `serve`, `scan`, `report`, `version` |
| HTTP 서버 | 표준 `net/http` (Go 1.22+ 라우팅) | 외부 프레임워크 최소화 |
| 레이트 리밋 | `golang.org/x/time/rate` | |
| DB | `modernc.org/sqlite` | 순수 Go, CGO 불필요 |
| 점검 규칙 확장 | Nuclei v3 (라이브러리 임베드) | 3단계에서 도입 |
| 프론트엔드 | Svelte + Vite | 빌드 결과를 `go:embed`로 내장 |
| 리포트 | `html/template` | 단일 HTML (CSS 인라인) |
| 릴리스 | GoReleaser + GitHub Actions | |
| 린트/보안 | golangci-lint, gitleaks, govulncheck | |

> 참고: 최신 Go 바이너리는 Linux 커널 3.2 이상이 필요합니다. CentOS 6 서버가 아닌 **별도 점검용 PC**에서 실행하는 것을 전제로 합니다.

---

## 3. 디렉터리 구조

```
intrasec/
├── cmd/intrasec/
│   ├── main.go
│   ├── serve.go              # 웹 UI 모드
│   ├── scan.go               # CLI 점검 모드
│   └── report.go             # 저장된 점검 결과로 리포트 재생성
├── internal/
│   ├── engine/               # 점검 오케스트레이션, 워커 풀, 타임아웃, 취소
│   ├── scope/                # 허용 목록 검증 (모든 요청 필수 통과)
│   ├── transport/            # 공통 HTTP 클라이언트 (레이트리밋, 재시도, 프록시, 요청 기록)
│   ├── auth/                 # 폼 로그인, 세션 쿠키 유지, 로그아웃 URL 회피
│   ├── checks/
│   │   ├── registry.go       # 점검 플러그인 등록
│   │   ├── common/           # 헤더, TLS, 쿠키, 노출 파일, 디렉터리 리스팅
│   │   ├── weblogic/         # 콘솔 노출, 버전 노출, T3/IIOP 노출
│   │   ├── xplatform/        # 서비스 URL 인증 누락, IDOR, 평문 전송
│   │   └── groupware/        # 업로드 검증, XSS 반영 지점, 권한 우회
│   ├── nuclei/               # Nuclei 엔진 어댑터 (3단계)
│   ├── server/               # REST API, SSE, 토큰 인증, Host 헤더 검증
│   ├── store/                # SQLite 저장소
│   ├── report/
│   │   ├── html.go
│   │   ├── json.go
│   │   ├── markdown.go
│   │   ├── sarif.go
│   │   └── templates/
│   └── audit/                # 실행자, 시각, 대상, 점검 항목 기록
├── pkg/finding/              # Finding 모델 (외부 공개 API)
├── rules/                    # 자체 점검 규칙 YAML
├── web/                      # Svelte 프론트엔드 소스
│   └── dist/                 # 빌드 결과 (go:embed 대상, git 제외)
├── configs/
│   └── scope.example.yaml
├── testdata/                 # 녹화된 HTTP 응답 (사내 정보 제거본)
├── deploy/
│   └── docker-compose.yml    # 테스트용 취약 앱 (OWASP Juice Shop, DVWA)
├── docs/
│   ├── checks.md             # 점검 항목 목록
│   └── writing-checks.md     # 점검 플러그인 작성 가이드
├── .github/workflows/
│   ├── ci.yml
│   └── release.yml
├── .goreleaser.yaml
├── .gitignore
├── Makefile
└── LICENSE
```

---

## 4. 핵심 설계 규칙

### 4.1 스코프 강제 (가장 중요)
- 모든 HTTP 요청은 `transport` 계층에서 `scope.Allow(url)` 검사를 통과해야 한다.
- 검사는 **DNS 해석 이후의 실제 IP** 기준으로 수행한다 (호스트명 우회 방지).
- 리다이렉트 대상도 매 홉마다 재검사한다.
- 점검 시간대(`window`) 밖이면 엔진 시작 자체를 거부한다.
- 플러그인은 스코프를 우회하는 자체 HTTP 클라이언트를 만들 수 없다 (`transport`만 사용).

### 4.2 점검 레벨
- `passive`: 일반 브라우징 수준의 요청만 (GET, 헤더·응답 분석)
- `active`: 파라미터 변조, 인증 우회 시도 등. `scope.yaml`의 `active_checks: true`일 때만 실행
- 레벨 판단은 플러그인이 아닌 **엔진**에서 강제한다.

### 4.3 안전장치
- 기본 레이트 리밋: 초당 5 요청
- `DELETE`, `PUT` 및 데이터 변경 의심 요청 기본 차단
- 로그아웃·삭제·결재 등 위험 URL 패턴은 크롤링 제외 목록에 기본 포함
- 연속 5xx 응답이 일정 횟수 이상이면 자동 일시정지

### 4.4 로컬 웹 UI 보안
- `127.0.0.1`에만 바인딩 (`0.0.0.0` 금지)
- 실행 시마다 랜덤 토큰 발급, 모든 API 요청에서 검증
- `Host` 헤더가 `127.0.0.1` / `localhost`가 아니면 거부 (DNS 리바인딩 방지)
- 상태 변경 API는 `POST` + 토큰 + `Origin` 검사

### 4.5 민감정보 관리
- 테스트 계정 비밀번호는 DB에 평문 저장 금지 (OS 키체인 또는 실행 시 입력)
- 리포트의 요청/응답 근거에서 쿠키·세션·비밀번호 값은 마스킹
- 공개 저장소에 사내 호스트, IP, 계정, 결과물 커밋 금지 (gitleaks로 검사)

---

## 5. 데이터 모델

```go
type Severity string

const (
    SevInfo     Severity = "info"
    SevLow      Severity = "low"
    SevMedium   Severity = "medium"
    SevHigh     Severity = "high"
    SevCritical Severity = "critical"
)

type Finding struct {
    ID          string    // 고유 ID
    CheckID     string    // 예: "COMMON-HDR-001"
    Title       string
    Severity    Severity
    Target      string    // URL
    Evidence    Evidence  // 근거 요청/응답 (마스킹 적용)
    CWE         []string
    OWASP       []string  // 예: "A05:2021"
    KISA        []string  // KISA 점검 항목 코드
    Description string
    Remediation string    // 조치 방법 (한국어)
    FoundAt     time.Time
}

type Evidence struct {
    Request  string
    Response string
    Note     string
}
```

### 점검 플러그인 인터페이스

```go
type Level int

const (
    Passive Level = iota
    Active
)

type Check interface {
    ID() string
    Name() string
    Level() Level
    Tags() []string                // "weblogic", "xplatform", "headers" 등
    Run(ctx context.Context, t Target, s *Session) ([]finding.Finding, error)
}
```

---

## 6. scope.yaml 명세

```yaml
engagement:
  name: "2026 사내시스템 정기점검"
  approved_by: "정보보안 담당자"
  approval_ref: "결재문서번호 또는 메일 제목"
  window:
    start: "2026-11-10T19:00:00+09:00"
    end:   "2026-11-10T23:00:00+09:00"

targets:
  - name: ERP
    base_url: https://erp.example.local
    ports: [443, 7001]
    tags: [weblogic, xplatform]
  - name: 그룹웨어
    base_url: https://gw.example.local
    tags: [groupware]

allow:
  cidrs: [10.0.10.0/28]

exclude_paths:
  - /logout
  - /*/delete*
  - /approval/submit*

auth:
  - target: ERP
    type: form
    login_url: https://erp.example.local/login.do
    username_field: userId
    password_field: userPw
    username: scan_test01
    password_env: INTRASEC_ERP_PW     # 비밀번호는 환경변수로

options:
  rate_limit: 5
  concurrency: 4
  active_checks: false
  timeout_sec: 15
```

---

## 7. CLI

```bash
intrasec serve [--port 7777] [--no-browser]
intrasec scan -c scope.yaml [--only weblogic,headers] [-o report.html]
intrasec report --scan-id <id> --format html|json|md|sarif -o out.html
intrasec checks list
intrasec scope validate -c scope.yaml
intrasec version
```

---

## 8. 로컬 API (serve 모드)

| Method | Path | 설명 |
|---|---|---|
| GET | `/api/projects` | 점검 프로젝트 목록 |
| POST | `/api/projects` | 프로젝트 생성 (scope 등록) |
| POST | `/api/scope/validate` | scope 검증 |
| POST | `/api/scans` | 점검 시작 |
| POST | `/api/scans/{id}/cancel` | 점검 중단 |
| GET | `/api/scans/{id}/events` | 진행 상황 (SSE) |
| GET | `/api/scans/{id}/findings` | 발견 항목 |
| GET | `/api/scans/{id}/report?format=html` | 리포트 다운로드 |
| GET | `/api/scans/{a}/diff/{b}` | 점검 간 비교 |

---

## 9. 1차 점검 항목 (passive)

| ID | 항목 | 심각도 |
|---|---|---|
| COMMON-HDR-001 | Content-Security-Policy 누락 | Medium |
| COMMON-HDR-002 | Strict-Transport-Security 누락 | Medium |
| COMMON-HDR-003 | X-Frame-Options / frame-ancestors 누락 | Medium |
| COMMON-HDR-004 | X-Content-Type-Options 누락 | Low |
| COMMON-HDR-005 | Server / X-Powered-By 버전 노출 | Low |
| COMMON-TLS-001 | TLS 1.0/1.1 허용 | High |
| COMMON-TLS-002 | 취약 암호화 스위트 허용 | Medium |
| COMMON-TLS-003 | 인증서 만료 / 만료 임박 / 자체 서명 | Medium |
| COMMON-HTTP-001 | 로그인 페이지 HTTP 평문 제공 | High |
| COMMON-CKE-001 | 세션 쿠키 Secure 누락 | Medium |
| COMMON-CKE-002 | 세션 쿠키 HttpOnly 누락 | Medium |
| COMMON-CKE-003 | 세션 쿠키 SameSite 미설정 | Low |
| COMMON-EXP-001 | `.git/`, `.svn/` 노출 | High |
| COMMON-EXP-002 | 백업·설정 파일 노출 (`.bak`, `.old`, `web.xml` 등) | High |
| COMMON-EXP-003 | 디렉터리 리스팅 활성화 | Medium |
| COMMON-ERR-001 | 상세 에러/스택트레이스 노출 | Medium |
| WLS-001 | WebLogic 관리 콘솔 접근 가능 | High |
| WLS-002 | WebLogic 버전 노출 | Low |
| WLS-003 | T3/IIOP 프로토콜 노출 | High |
| XP-001 | 서비스 URL 세션 없이 응답 | Critical |
| XP-002 | 서비스 통신 평문 전송 | High |

---

## 10. 로드맵

### M1. 엔진 기반 (CLI)
- [ ] 저장소 초기화, Makefile, CI (test, lint, gitleaks, govulncheck)
- [ ] `scope` 패키지: 파싱, 검증, IP 기준 허용 판단, 시간대 검사
- [ ] `transport` 패키지: 레이트리밋, 리다이렉트 재검사, 요청 기록
- [ ] `engine` + `Check` 인터페이스 + registry
- [ ] `common` 점검 항목 구현 (헤더, TLS, 쿠키, 노출 파일)
- [ ] JSON / Markdown 리포트
- [ ] Juice Shop 대상 통합 테스트
- [ ] v0.1.0 릴리스

### M2. 사내 시스템 특화 + 인증
- [ ] `auth` 모듈 (폼 로그인, 세션 유지, 세션 만료 감지 후 재로그인)
- [ ] `weblogic` 점검
- [ ] `xplatform` 점검
- [ ] 사내 스테이징 환경 첫 실전 점검
- [ ] HTML 리포트 (인쇄용 CSS 포함)

### M3. 웹 UI
- [ ] `server` 패키지 (토큰, Host 검증, SSE)
- [ ] `store` (SQLite)
- [ ] Svelte UI: 프로젝트 / 점검 실행 / 결과 / 리포트
- [ ] `go:embed` 내장, GoReleaser 멀티 OS 빌드
- [ ] v0.3.0 릴리스

### M4. 확장
- [ ] Nuclei 엔진 임베드, 자체 규칙 YAML
- [ ] `groupware` 점검
- [ ] SARIF 출력
- [ ] KISA 점검 항목 매핑, 한국어 조치 가이드
- [ ] 점검 간 비교(diff) 리포트

---

## 11. 개발 규칙

- 커밋 메시지: Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`)
- 모든 점검 항목은 `testdata/`의 녹화 응답 기반 단위 테스트 필수
- 실제 사내 시스템 응답을 `testdata/`에 넣을 때는 호스트·IP·계정·개인정보 제거
- 새 점검 항목 추가 시 `docs/checks.md` 갱신

### .gitignore 필수 항목

```
scope.yaml
*.local.yaml
.env
results/
*.db
web/dist/
web/node_modules/
dist/
```

---

## 12. 빠른 시작 (개발)

```bash
git clone https://github.com/<user>/intrasec.git
cd intrasec
make deps          # Go 모듈, 프론트엔드 의존성
make test
make run-lab       # docker-compose로 Juice Shop 실행
make build         # web 빌드 → go build
./bin/intrasec scan -c configs/scope.lab.yaml -o report.html
```

---

## 라이선스

Apache License 2.0
