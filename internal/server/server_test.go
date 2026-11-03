package server

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sangmoo/intrasec/internal/audit"
	_ "github.com/Sangmoo/intrasec/internal/checks/common"
	"github.com/Sangmoo/intrasec/internal/store"
)

func newTestServer(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	s, err := New(Config{Version: "test", Store: st, Audit: audit.New(io.Discard),
		LookupEnv: func(string) (string, bool) { return "", false }})
	if err != nil {
		t.Fatal(err)
	}
	return s, s.Handler()
}

func TestSecurityMiddleware(t *testing.T) {
	s, h := newTestServer(t)
	cases := []struct {
		name   string
		method string
		host   string
		token  string
		origin string
		want   int
	}{
		{"정상", http.MethodGet, "127.0.0.1:7777", s.Token, "", http.StatusOK},
		{"localhost 허용", http.MethodGet, "localhost:7777", s.Token, "", http.StatusOK},
		{"리바인딩 Host 거부", http.MethodGet, "evil.example.com:7777", s.Token, "", http.StatusForbidden},
		{"토큰 없음", http.MethodGet, "127.0.0.1:7777", "", "", http.StatusUnauthorized},
		{"토큰 불일치", http.MethodGet, "127.0.0.1:7777", "bad", "", http.StatusUnauthorized},
		{"POST Origin 없음", http.MethodPost, "127.0.0.1:7777", s.Token, "", http.StatusForbidden},
		{"POST 외부 Origin", http.MethodPost, "127.0.0.1:7777", s.Token, "http://evil.example.com", http.StatusForbidden},
		{"DELETE 거부", http.MethodDelete, "127.0.0.1:7777", s.Token, "http://127.0.0.1:7777", http.StatusMethodNotAllowed},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, "/api/health", nil)
		req.Host = c.host
		if c.token != "" {
			req.Header.Set(tokenHeader, c.token)
		}
		if c.origin != "" {
			req.Header.Set("Origin", c.origin)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("%s: want %d, got %d", c.name, c.want, rec.Code)
		}
	}
}

// api 는 토큰·Host·Origin 을 채워 API 를 호출한다.
type api struct {
	t   *testing.T
	s   *Server
	srv *httptest.Server
}

func (a api) do(method, path string, body any) (int, []byte) {
	a.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, a.srv.URL+path, rd)
	req.Header.Set(tokenHeader, a.s.Token)
	req.Header.Set("Origin", a.srv.URL)
	resp, err := a.srv.Client().Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func TestScanLifecycle(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>lab</html>"))
	}))
	defer target.Close()

	s, h := newTestServer(t)
	srv := httptest.NewServer(h) // 127.0.0.1 바인딩
	defer srv.Close()
	a := api{t, s, srv}

	now := time.Now()
	scopeYAML := fmt.Sprintf(`
engagement: {name: lab, approved_by: me, approval_ref: test, window: {start: %q, end: %q}}
targets: [{name: lab, base_url: %q}]
allow: {cidrs: [127.0.0.1/32]}
options: {rate_limit: 50}
`, now.Add(-time.Hour).Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339), target.URL)

	// 승인 정보 없는 scope 는 저장 거부
	code, _ := a.do("POST", "/api/projects", map[string]string{"name": "x", "scope_yaml": strings.Replace(scopeYAML, "approved_by: me", "approved_by: ''", 1)})
	if code != http.StatusBadRequest {
		t.Fatalf("승인자 없는 scope 거부 기대: %d", code)
	}

	code, body := a.do("POST", "/api/projects", map[string]string{"name": "lab", "scope_yaml": scopeYAML})
	if code != http.StatusCreated {
		t.Fatalf("프로젝트 생성 %d %s", code, body)
	}
	var p store.Project
	_ = json.Unmarshal(body, &p)

	// dry-run 은 요청 없이 계획만
	code, body = a.do("POST", "/api/scans", map[string]any{"project_id": p.ID, "safe": true, "dry_run": true, "only": []string{"headers"}})
	if code != http.StatusOK || !strings.Contains(string(body), `"safe_mode":true`) || !strings.Contains(string(body), "COMMON-HDR") {
		t.Fatalf("dry-run %d %s", code, body)
	}

	code, body = a.do("POST", "/api/scans", map[string]any{"project_id": p.ID, "only": []string{"headers", "cookies"}})
	if code != http.StatusAccepted {
		t.Fatalf("점검 시작 %d %s", code, body)
	}
	var started struct {
		ScanID string `json:"scan_id"`
	}
	_ = json.Unmarshal(body, &started)

	// SSE: finished 이벤트까지 읽는다
	req, _ := http.NewRequest("GET", srv.URL+"/api/scans/"+started.ScanID+"/events", nil)
	req.Header.Set(tokenHeader, s.Token)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(resp.Body)
	var finished string
	for sc.Scan() {
		if line := sc.Text(); strings.HasPrefix(line, "data: ") && strings.Contains(line, `"finished"`) {
			finished = line
			break
		}
	}
	_ = resp.Body.Close()
	if !strings.Contains(finished, `"status":"done"`) {
		t.Fatalf("finished 이벤트 이상: %q", finished)
	}

	code, body = a.do("GET", "/api/scans/"+started.ScanID+"/findings", nil)
	if code != http.StatusOK || !strings.Contains(string(body), "COMMON-HDR-001") {
		t.Fatalf("findings %d %s", code, body)
	}
	code, body = a.do("GET", "/api/scans/"+started.ScanID+"/report?format=md", nil)
	if code != http.StatusOK || !strings.Contains(string(body), "# 보안 점검 결과") {
		t.Fatalf("report %d", code)
	}
	code, body = a.do("GET", "/api/scans/"+started.ScanID+"/diff/"+started.ScanID, nil)
	if code != http.StatusOK || !strings.Contains(string(body), `"new":[]`) {
		t.Fatalf("diff %d %s", code, body)
	}
	code, body = a.do("GET", fmt.Sprintf("/api/projects/%d/scans", p.ID), nil)
	if code != http.StatusOK || !strings.Contains(string(body), `"status":"done"`) {
		t.Fatalf("scan 목록 %d %s", code, body)
	}

	// 끝난 점검의 SSE 는 최종 상태만 보내고 닫는다 (서버 재시작 후 상황 흉내)
	delete(s.runs, started.ScanID)
	code, body = a.do("GET", "/api/scans/"+started.ScanID+"/events", nil)
	if code != http.StatusOK || !strings.Contains(string(body), `"status":"done"`) {
		t.Fatalf("저장된 점검 SSE %d %s", code, body)
	}
}

func TestScanRefusedOutsideWindow(t *testing.T) {
	s, h := newTestServer(t)
	srv := httptest.NewServer(h)
	defer srv.Close()
	a := api{t, s, srv}
	y := `
engagement: {name: lab, approved_by: me, approval_ref: test, window: {start: "2000-01-01T00:00:00Z", end: "2000-01-02T00:00:00Z"}}
targets: [{name: lab, base_url: "http://127.0.0.1:1"}]
allow: {cidrs: [127.0.0.1/32]}
`
	_, body := a.do("POST", "/api/projects", map[string]string{"name": "old", "scope_yaml": y})
	var p store.Project
	_ = json.Unmarshal(body, &p)
	code, body := a.do("POST", "/api/scans", map[string]any{"project_id": p.ID})
	if code != http.StatusConflict || !strings.Contains(string(body), "시간대") {
		t.Fatalf("시간대 밖 거부 기대: %d %s", code, body)
	}
}
