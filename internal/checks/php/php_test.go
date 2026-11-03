package php

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sangmoo/intrasec/internal/checks/checkstest"
	"github.com/Sangmoo/intrasec/pkg/finding"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "php", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func run(t *testing.T, h http.Handler, tags ...string) []finding.Finding {
	t.Helper()
	tgt, s := checkstest.Serve(t, h, tags...)
	fs, err := phpCheck{now: func() time.Time { return testNow }}.Run(context.Background(), tgt, s)
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

func checkIDs(fs []finding.Finding) []string {
	m := map[string]bool{}
	for _, f := range fs {
		m[f.CheckID] = true
	}
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestVulnerablePHPServer(t *testing.T) {
	html := "text/html; charset=UTF-8"
	fs := run(t, checkstest.Files{
		Headers: map[string]string{"X-Powered-By": "PHP/8.4.26", "Server": "nginx/1.24.0"},
		Paths: map[string]checkstest.File{
			"/":            {ContentType: html, Body: fixture(t, "error_page.html")},
			"/phpinfo.php": {ContentType: html, Body: fixture(t, "phpinfo.html")},
			"/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php": {ContentType: "text/plain", Body: ""},
			"/_ignition/health-check":                             {ContentType: "application/json", Body: `{"can_execute_commands":true}`},
			"/composer.lock":                                      {ContentType: "application/json", Body: `{"content-hash":"x","packages":[]}`},
			"/adminer.php":                                        {ContentType: html, Body: `<title>Login - Adminer</title><select name="auth[driver]">`},
			"/.user.ini":                                          {ContentType: "text/plain", Body: "auto_prepend_file = /var/www/x.php\n"},
		},
	})
	got := strings.Join(checkIDs(fs), ",")
	// phpinfo 의 8.1.2-1ubuntu 버전이 헤더 버전보다 우선한다 -> EOL(PHP-001) + PHP2Shell(PHP-002)
	want := "PHP-001,PHP-002,PHP-010,PHP-011,PHP-012,PHP-013,PHP-014,PHP-016,PHP-017"
	if got != want {
		t.Fatalf("want %s\n got %s", want, got)
	}
	for _, f := range fs {
		if f.CheckID == "PHP-010" && !strings.Contains(f.Evidence.Note, "session.upload_progress.enabled=On") {
			t.Errorf("phpinfo 위험 설정 비고 누락: %q", f.Evidence.Note)
		}
		if f.CheckID == "PHP-011" && !strings.Contains(f.Evidence.Note, "/var/www/html/lib/db.php") {
			t.Errorf("에러 경로 비고 누락: %q", f.Evidence.Note)
		}
		if f.CheckID == "PHP-002" && !strings.Contains(f.Evidence.Note, "phpinfo()") {
			t.Errorf("버전 출처 누락: %q", f.Evidence.Note)
		}
	}
}

func TestSoftNotFoundNoFalsePositive(t *testing.T) {
	fs := run(t, checkstest.Files{
		Headers:      map[string]string{"X-Powered-By": "PHP/8.4.27"},
		SoftNotFound: true,
	})
	if len(fs) != 0 {
		t.Fatalf("soft 404 서버에서 오탐: %v", checkIDs(fs))
	}
}

func TestNonPHPSkipsProbes(t *testing.T) {
	var n atomic.Int32
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n.Add(1)
		w.Header().Set("Server", "Apache-Coyote/1.1")
		_, _ = w.Write([]byte("<html><a href='/main.do'>main</a></html>"))
	})
	if fs := run(t, h); len(fs) != 0 || n.Load() != 1 {
		t.Fatalf("PHP 흔적 없는 대상은 기본 페이지 1회만 요청해야 함: findings=%d requests=%d", len(fs), n.Load())
	}
	n.Store(0)
	run(t, h, TagPHP)
	if n.Load() <= 1 {
		t.Fatal("php 태그가 있으면 경로 탐색을 해야 함")
	}
}
