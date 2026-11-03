// Package checkstest 는 점검 플러그인 테스트용으로 httptest 서버를 대상으로 하는 Session 을 만든다.
package checkstest

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/Sangmoo/intrasec/internal/checks"
	"github.com/Sangmoo/intrasec/internal/scope"
	"github.com/Sangmoo/intrasec/internal/transport"
)

// Serve 는 h 로 로컬 서버를 띄우고, 그 서버만 허용하는 Target 과 Session 을 돌려준다.
func Serve(t *testing.T, h http.Handler, tags ...string) (checks.Target, *checks.Session) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return session(t, srv, tags)
}

// ServeTLS 는 cfg(nil 이면 httptest 기본값)로 HTTPS 서버를 띄운다.
// httptest 의 인증서는 127.0.0.1 용 자체 서명 인증서다.
func ServeTLS(t *testing.T, h http.Handler, cfg *tls.Config, tags ...string) (checks.Target, *checks.Session) {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	if cfg != nil {
		srv.TLS = cfg
	}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // 점검의 의도적 핸드셰이크 실패 로그 숨김
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return session(t, srv, tags)
}

func session(t *testing.T, srv *httptest.Server, tags []string) (checks.Target, *checks.Session) {
	t.Helper()
	y := fmt.Sprintf(`
engagement: {name: t, approved_by: a, approval_ref: r, window: {start: "2000-01-01T00:00:00Z", end: "2100-01-01T00:00:00Z"}}
targets: [{name: lab, base_url: %q}]
allow: {cidrs: [127.0.0.1/32]}
options: {rate_limit: 50}
`, srv.URL)
	cfg, err := scope.Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	sc, err := scope.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(srv.URL)
	return checks.Target{Name: "lab", BaseURL: u, Tags: tags},
		&checks.Session{HTTP: transport.New(sc, transport.Options{RateLimit: 50})}
}

// Files 는 경로 -> (Content-Type, 본문) 맵으로 응답하고 나머지는 404 를 주는 핸들러다.
// headers 는 모든 응답에 붙는다.
type Files struct {
	Headers map[string]string
	Paths   map[string]File
	// SoftNotFound 가 true 면 없는 경로에도 200 과 같은 HTML 을 준다.
	SoftNotFound bool
}

type File struct {
	ContentType string
	Body        string
}

func (f Files) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	for k, v := range f.Headers {
		w.Header().Set(k, v)
	}
	if file, ok := f.Paths[r.URL.Path]; ok {
		if file.ContentType != "" {
			w.Header().Set("Content-Type", file.ContentType)
		}
		_, _ = w.Write([]byte(file.Body))
		return
	}
	if f.SoftNotFound {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><body>페이지를 찾을 수 없습니다. 메인으로 이동하세요.</body></html>"))
		return
	}
	http.NotFound(w, r)
}
