package php

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Sangmoo/intrasec/pkg/finding"
)

var testNow = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

func TestParseVersion(t *testing.T) {
	cases := map[string]string{
		"PHP/8.4.26":                       "8.4.26",
		"PHP/8.1.2-1ubuntu2.14":            "8.1.2-1ubuntu2.14",
		"Apache/2.4.6 (CentOS) PHP/5.4.16": "5.4.16",
		"PHP Version 7.4.33":               "7.4.33",
		"PHP/8.2.12, ASP.NET":              "8.2.12",
	}
	for in, want := range cases {
		v, ok := ParseVersion(in)
		if !ok || v.String() != want {
			t.Errorf("%q: want %s, got %v %v", in, want, v, ok)
		}
	}
	if _, ok := ParseVersion("nginx/1.24.0"); ok {
		t.Error("PHP 가 아닌 버전을 파싱함")
	}
}

func eval(t *testing.T, ver string, env Env) []string {
	t.Helper()
	v, ok := ParseVersion("PHP/" + ver)
	if !ok {
		t.Fatal(ver)
	}
	var out []string
	for _, f := range evaluate("https://x.local/", v, env, testNow, finding.Evidence{}) {
		out = append(out, f.CheckID+":"+string(f.Severity))
	}
	sort.Strings(out)
	return out
}

func TestEvaluate(t *testing.T) {
	cases := []struct {
		ver  string
		env  Env
		want string
	}{
		// PHP2Shell 경계값
		{"8.4.26", Env{}, "PHP-002:critical"},
		{"8.4.27", Env{}, ""},
		{"8.5.11", Env{}, "PHP-002:critical"},
		{"8.5.12", Env{}, ""},
		{"8.3.36", Env{}, ""},
		// 8.2: 2026-12-31 종료 임박
		{"8.2.34", Env{}, "PHP-001:low,PHP-002:critical"},
		{"8.2.35", Env{}, "PHP-001:low"},
		// EOL 브랜치는 공식 수정 없음
		{"8.1.34", Env{}, "PHP-001:high,PHP-002:critical"},
		{"5.3.29", Env{}, "PHP-001:high"},
		// CVE-2024-4577: Windows 일 때만, CGI 확인 시 critical
		{"8.1.28", Env{Windows: true}, "PHP-001:high,PHP-002:critical,PHP-003:high"},
		{"8.1.28", Env{Windows: true, SAPI: "CGI/FastCGI", SAPIKnown: true}, "PHP-001:high,PHP-002:critical,PHP-003:critical"},
		{"8.1.28", Env{Windows: true, SAPI: "Apache 2.0 Handler", SAPIKnown: true}, "PHP-001:high,PHP-002:critical"},
		{"8.3.7", Env{Windows: true}, "PHP-002:critical,PHP-003:high"},
		// CVE-2019-11043: nginx + FPM
		{"7.3.10", Env{Nginx: true}, "PHP-001:high,PHP-002:critical,PHP-004:high"},
		{"7.3.11", Env{Nginx: true}, "PHP-001:high,PHP-002:critical"},
		{"7.4.0", Env{Nginx: true}, "PHP-001:high,PHP-002:critical"},
		// 미래 브랜치는 판단하지 않음
		{"8.6.0", Env{}, ""},
	}
	for _, c := range cases {
		got := strings.Join(eval(t, c.ver, c.env), ",")
		if got != c.want {
			t.Errorf("%s %+v: want %q, got %q", c.ver, c.env, c.want, got)
		}
	}
}

func TestDistroNote(t *testing.T) {
	v, _ := ParseVersion("PHP/8.1.2-1ubuntu2.14")
	fs := evaluate("https://x.local/", v, Env{Sources: []string{"X-Powered-By 헤더"}}, testNow, finding.Evidence{})
	if len(fs) == 0 || !strings.Contains(fs[0].Evidence.Note, "백포트") {
		t.Fatalf("배포판 빌드 안내 누락: %+v", fs)
	}
}
