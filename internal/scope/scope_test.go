package scope

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
)

const sample = `
engagement:
  name: test
  approved_by: 보안담당
  approval_ref: DOC-1
  window:
    start: "2026-11-10T19:00:00+09:00"
    end:   "2026-11-10T23:00:00+09:00"
targets:
  - name: ERP
    base_url: https://erp.example.local
    ports: [7001]
allow:
  cidrs: [10.0.10.0/28, 127.0.0.1/32]
exclude_paths:
  - /*/delete*
`

func mustScope(t *testing.T, y string) *Scope {
	t.Helper()
	c, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestDefaults(t *testing.T) {
	s := mustScope(t, sample)
	o := s.Config().Options
	if o.RateLimit != DefaultRateLimit || o.Concurrency != DefaultConcurrency || o.TimeoutSec != DefaultTimeoutSec {
		t.Fatalf("기본값 미적용: %+v", o)
	}
	if o.ActiveChecks {
		t.Fatal("active_checks 기본값은 false 여야 함")
	}
}

func TestRejectPlaintextPassword(t *testing.T) {
	y := sample + `
auth:
  - target: ERP
    type: form
    username: u
    password: secret
`
	if _, err := Parse([]byte(y)); err == nil {
		t.Fatal("평문 password 필드는 거부되어야 함")
	}
}

func TestValidateMissing(t *testing.T) {
	_, err := Parse([]byte(`targets: []`))
	if err == nil {
		t.Fatal("오류가 나야 함")
	}
	for _, want := range []string{"approved_by", "window", "targets", "allow.cidrs"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("오류 메시지에 %q 없음: %v", want, err)
		}
	}
}

func TestWindow(t *testing.T) {
	s := mustScope(t, sample)
	kst := time.FixedZone("KST", 9*3600)
	cases := []struct {
		at time.Time
		ok bool
	}{
		{time.Date(2026, 11, 10, 18, 59, 59, 0, kst), false},
		{time.Date(2026, 11, 10, 19, 0, 0, 0, kst), true},
		{time.Date(2026, 11, 10, 22, 59, 0, 0, kst), true},
		{time.Date(2026, 11, 10, 23, 0, 0, 0, kst), false},
	}
	for _, c := range cases {
		err := s.CheckWindow(c.at)
		if (err == nil) != c.ok {
			t.Errorf("%s: ok=%v err=%v", c.at, c.ok, err)
		}
		if err != nil && !errors.Is(err, ErrOutOfWindow) {
			t.Errorf("ErrOutOfWindow 아님: %v", err)
		}
	}
}

func TestAllowURL(t *testing.T) {
	s := mustScope(t, sample)
	cases := []struct {
		url  string
		want error
	}{
		{"https://erp.example.local/", nil},
		{"https://ERP.example.local:7001/console", nil},
		{"http://erp.example.local/", ErrPort},
		{"https://erp.example.local:8443/", ErrPort},
		{"https://evil.example.com/", ErrHost},
		{"ftp://erp.example.local/", ErrHost},
		{"https://erp.example.local/logout.do", ErrExcluded},
		{"https://erp.example.local/board/delete.do?id=1", ErrExcluded},
		{"https://erp.example.local/a/b/Delete", ErrExcluded},
		{"https://erp.example.local/approval/submit", ErrExcluded},
	}
	for _, c := range cases {
		u, _ := url.Parse(c.url)
		err := s.AllowURL(u)
		if c.want == nil && err != nil || c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%s: want %v, got %v", c.url, c.want, err)
		}
	}
}

func TestAllowIP(t *testing.T) {
	s := mustScope(t, sample)
	for ip, ok := range map[string]bool{
		"10.0.10.1":        true,
		"10.0.10.15":       true,
		"10.0.10.16":       false,
		"192.168.0.1":      false,
		"::ffff:10.0.10.2": true,
	} {
		err := s.AllowIP(netip.MustParseAddr(ip))
		if (err == nil) != ok {
			t.Errorf("%s: ok=%v err=%v", ip, ok, err)
		}
	}
}

func TestResolveAllowedLiteral(t *testing.T) {
	s := mustScope(t, sample)
	if _, err := s.ResolveAllowed(context.Background(), "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveAllowed(context.Background(), "8.8.8.8"); !errors.Is(err, ErrIP) {
		t.Fatalf("ErrIP 기대, got %v", err)
	}
}

func TestSafeModeEffective(t *testing.T) {
	c, err := Parse([]byte(sample + "options: {safe_mode: true, rate_limit: 10, concurrency: 8}\n"))
	if err != nil {
		t.Fatal(err)
	}
	e := c.Options.Effective()
	if e.RateLimit != SafeRateLimit || e.Concurrency != 1 || e.MaxRequestsPerTarget != SafeMaxRequestsPerTarget || e.PauseOn5xx != SafePauseOn5xx || e.ActiveChecks {
		t.Fatalf("safe_mode 상한 미적용: %+v", e)
	}
	// 설정값이 더 엄격하면 설정값을 따른다.
	c.Options.RateLimit, c.Options.MaxRequestsPerTarget, c.Options.PauseOn5xx = 1, 20, 2
	if e := c.Options.Effective(); e.RateLimit != 1 || e.MaxRequestsPerTarget != 20 || e.PauseOn5xx != 2 {
		t.Fatalf("더 엄격한 설정값이 무시됨: %+v", e)
	}
	if _, err := Parse([]byte(sample + "options: {safe_mode: true, active_checks: true}\n")); err == nil {
		t.Fatal("safe_mode + active_checks 는 거부되어야 함")
	}
}
