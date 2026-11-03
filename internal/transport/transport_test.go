package transport

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Sangmoo/intrasec/internal/scope"
)

func newScope(t *testing.T, base string) *scope.Scope {
	t.Helper()
	u, _ := url.Parse(base)
	y := fmt.Sprintf(`
engagement:
  name: t
  approved_by: a
  approval_ref: r
  window: {start: "2000-01-01T00:00:00Z", end: "2100-01-01T00:00:00Z"}
targets:
  - name: lab
    base_url: %s
allow:
  cidrs: [127.0.0.1/32]
options:
  rate_limit: 50
`, u.String())
	c, err := scope.Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	s, err := scope.New(c)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRedirectOutOfScopeBlocked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/out":
			http.Redirect(w, r, "http://evil.example.com/", http.StatusFound)
		case "/in":
			http.Redirect(w, r, "/ok", http.StatusFound)
		default:
			fmt.Fprint(w, "ok")
		}
	}))
	defer srv.Close()
	c := New(newScope(t, srv.URL), Options{RateLimit: 50})

	resp, err := c.Get(context.Background(), srv.URL+"/in")
	if err != nil {
		t.Fatalf("스코프 내 리다이렉트는 허용: %v", err)
	}
	_ = resp.Body.Close()

	_, err = c.Get(context.Background(), srv.URL+"/out")
	if !errors.Is(err, scope.ErrHost) {
		t.Fatalf("스코프 밖 리다이렉트는 차단되어야 함: %v", err)
	}
}

func TestMethodBlocked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	c := New(newScope(t, srv.URL), Options{RateLimit: 50})
	for _, m := range []string{http.MethodDelete, http.MethodPut, http.MethodPatch, "PROPFIND"} {
		req, _ := http.NewRequest(m, srv.URL+"/", nil)
		if _, err := c.Do(req); !errors.Is(err, ErrMethodBlocked) {
			t.Errorf("%s 는 차단되어야 함: %v", m, err)
		}
	}
}

func TestAutoPauseOn5xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	c := New(newScope(t, srv.URL), Options{RateLimit: 50, Max5xx: 3})
	for i := 0; i < 3; i++ {
		resp, err := c.Get(context.Background(), srv.URL+"/")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	if _, err := c.Get(context.Background(), srv.URL+"/"); !errors.Is(err, ErrPaused) {
		t.Fatalf("일시정지 기대: %v", err)
	}
	c.Resume()
	resp, err := c.Get(context.Background(), srv.URL+"/")
	if err != nil {
		t.Fatalf("Resume 후 재개 기대: %v", err)
	}
	_ = resp.Body.Close()
}

func TestMasking(t *testing.T) {
	got := MaskSetCookie("JSESSIONID=abc123; Path=/; HttpOnly")
	if got != "JSESSIONID=****; Path=/; HttpOnly" {
		t.Fatal(got)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://x.local/a", nil)
	req.Header.Set("Cookie", "JSESSIONID=abc123")
	req.Header.Set("Authorization", "Basic Zm9vOmJhcg==")
	d := DumpRequest(req)
	if strings.Contains(d, "abc123") || strings.Contains(d, "Zm9v") {
		t.Fatalf("민감값 노출: %s", d)
	}
}

func TestRequestBudget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/r" {
			http.Redirect(w, r, "/", http.StatusFound)
		}
	}))
	defer srv.Close()
	c := New(newScope(t, srv.URL), Options{RateLimit: 50, MaxRequestsPerHost: 3})
	// 리다이렉트 홉도 1건으로 센다: /r -> / = 2건
	resp, err := c.Get(context.Background(), srv.URL+"/r")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	resp, err = c.Get(context.Background(), srv.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if _, err := c.Get(context.Background(), srv.URL+"/"); !errors.Is(err, ErrBudget) {
		t.Fatalf("상한 초과 시 ErrBudget 기대: %v", err)
	}
}
