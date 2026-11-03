# 점검 플러그인 작성 가이드

## 1. 원칙

- **HTTP 요청은 `Session.HTTP`(transport.Client)로만** 보낸다. `http.Client` 를 직접 만들면 스코프·레이트리밋·감사 기록을 우회하게 되므로 리뷰에서 반려한다.
- 취약점 **존재 근거 확인**까지만 한다. 익스플로잇, 데이터 변경·삭제, 부하 유발 요청은 작성하지 않는다.
- 파라미터 변조·인증 우회 시도 등은 `Level()` 을 `checks.Active` 로 선언한다. 실행 여부는 엔진이 `scope.yaml` 의 `active_checks` 로 판단하므로 플러그인에서 따로 검사하지 않는다.
- 근거(Evidence)는 `transport.DumpRequest` / `transport.DumpResponse` 로 만든다. 쿠키·인증 헤더가 자동 마스킹된다.

## 2. 구조

```go
package mycheck

func init() { checks.Register(myCheck{}) }

type myCheck struct{}

func (myCheck) ID() string          { return "WLS-001" }
func (myCheck) Name() string        { return "WebLogic 관리 콘솔 노출" }
func (myCheck) Level() checks.Level { return checks.Passive }
func (myCheck) Tags() []string      { return []string{"weblogic"} } // checks.TagCommon 이면 모든 대상

func (myCheck) Run(ctx context.Context, t checks.Target, s *checks.Session) ([]finding.Finding, error) {
	u := t.BaseURL.JoinPath("/console/login/LoginForm.jsp")
	resp, err := s.HTTP.Get(ctx, u.String())
	if err != nil {
		return nil, err
	}
	body, _ := transport.ReadBody(resp, 64<<10)
	return analyze(u.String(), resp, body), nil // 판단 로직은 순수 함수로 분리
}
```

- 대상 태그와 점검 태그가 하나라도 겹치면 실행된다 (`checks.AppliesTo`).
- 새 패키지를 만들면 `cmd/intrasec/main.go` 에 blank import 를 추가한다.
- `Finding.ID`, `FoundAt` 은 엔진이 채운다.

## 3. 테스트

- 판단 로직(`analyze...`)은 네트워크 없이 테스트할 수 있게 순수 함수로 분리한다.
- `testdata/<패키지>/` 에 녹화된 HTTP 응답(원문 형식)을 두고 `http.ReadResponse` 로 읽어 검증한다.
- 실제 사내 응답을 녹화할 때는 **호스트·IP·계정·세션 값·개인정보를 제거**한다 (gitleaks 가 CI 에서 검사).
- 오탐 방지를 위해 "취약" 응답과 "안전" 응답 양쪽 케이스를 모두 둔다.

## 4. 체크리스트

- [ ] `Session.HTTP` 만 사용
- [ ] 레벨 올바르게 선언
- [ ] CWE / OWASP (가능하면 KISA) 매핑
- [ ] 한국어 설명·조치 방법
- [ ] `testdata` 기반 단위 테스트 (취약/안전)
- [ ] `docs/checks.md` 갱신
