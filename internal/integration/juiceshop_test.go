//go:build integration

// Package integration 은 실제 취약 앱(OWASP Juice Shop)을 대상으로 전체 점검 흐름을 검증한다.
//
//	make run-lab
//	go test -tags integration ./internal/integration/
//
// 대상 주소는 INTRASEC_LAB_URL (기본 http://localhost:3000) 로 바꿀 수 있다. 루프백 주소만 허용한다.
package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sangmoo/intrasec/internal/checks"
	_ "github.com/Sangmoo/intrasec/internal/checks/common"
	_ "github.com/Sangmoo/intrasec/internal/checks/php"
	_ "github.com/Sangmoo/intrasec/internal/checks/weblogic"
	_ "github.com/Sangmoo/intrasec/internal/checks/xplatform"
	"github.com/Sangmoo/intrasec/internal/engine"
	"github.com/Sangmoo/intrasec/internal/scope"
	"github.com/Sangmoo/intrasec/internal/transport"
	"github.com/Sangmoo/intrasec/pkg/finding"
)

func labURL(t *testing.T) string {
	u := os.Getenv("INTRASEC_LAB_URL")
	if u == "" {
		u = "http://localhost:3000"
	}
	pu, err := url.Parse(u)
	if err != nil || (pu.Hostname() != "localhost" && pu.Hostname() != "127.0.0.1") {
		t.Fatalf("INTRASEC_LAB_URL 은 루프백 주소만 허용: %q", u)
	}
	return u
}

// waitReady 는 컨테이너 기동을 최대 2분 기다린다. 응답이 없으면 테스트를 건너뛴다.
func waitReady(t *testing.T, u string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for {
		resp, err := http.Get(u) //nolint:gosec,noctx // 루프백 실습 대상 기동 확인
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Skipf("실습 대상(%s)이 응답하지 않음: make run-lab 으로 먼저 실행하십시오 (%v)", u, err)
		}
		time.Sleep(2 * time.Second)
	}
}

func TestJuiceShopScan(t *testing.T) {
	base := labURL(t)
	waitReady(t, base)

	now := time.Now()
	y := fmt.Sprintf(`
engagement:
  name: "Juice Shop 통합 테스트"
  approved_by: "CI"
  approval_ref: "deploy/docker-compose.yml"
  window: {start: %q, end: %q}
targets: [{name: juice-shop, base_url: %q}]
allow: {cidrs: [127.0.0.1/32, "::1/128"]}
options: {rate_limit: 20, concurrency: 4, timeout_sec: 10}
`, now.Add(-time.Hour).Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339), base)
	cfg, err := scope.Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	sc, err := scope.New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	var requests atomic.Int64
	res, err := engine.Run(context.Background(), engine.Options{
		Scope:  sc,
		HTTP:   transport.New(sc, transport.Options{RateLimit: 20, Record: func(transport.Entry) { requests.Add(1) }}),
		Checks: checks.All(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Errors) > 0 {
		t.Errorf("점검 오류: %v", res.Errors)
	}

	got := map[string]finding.Finding{}
	for _, f := range res.Findings {
		got[f.CheckID] = f
		t.Logf("[%s] %s %s — %s", f.Severity, f.CheckID, f.Target, f.Evidence.Note)
	}
	t.Logf("요청 %d건, 발견 %d건", requests.Load(), len(res.Findings))

	// Juice Shop 의 알려진 특징: /ftp 디렉터리 리스팅, SPA 라 모든 경로에 200 (soft 404).
	if f, ok := got["COMMON-EXP-003"]; !ok || !strings.Contains(f.Target, "/ftp") {
		t.Errorf("/ftp 디렉터리 리스팅 미검출")
	}
	// soft 404 서버에서 백업·소스 파일 오탐이 없어야 한다.
	for _, id := range []string{"COMMON-EXP-001", "COMMON-EXP-002", "PHP-010", "PHP-014"} {
		if f, ok := got[id]; ok {
			t.Errorf("%s 오탐: %s", id, f.Target)
		}
	}
}
