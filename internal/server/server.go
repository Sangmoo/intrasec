// Package server 는 serve 모드의 로컬 웹 UI 와 REST API 를 제공한다.
// 127.0.0.1 바인딩, 실행별 랜덤 토큰, Host 헤더 검증(DNS 리바인딩 방지),
// 상태 변경 요청의 POST + 토큰 + Origin 검사를 강제한다.
package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Sangmoo/intrasec/internal/audit"
	"github.com/Sangmoo/intrasec/internal/store"
)

const tokenHeader = "X-Intrasec-Token" //nolint:gosec // 헤더 이름이지 비밀값이 아님

// DefaultPort 는 serve 의 기본 포트다. 8080 은 사내 WAS·ERP 개발 서버와 자주 겹쳐 피한다.
const DefaultPort = 7777

type Config struct {
	Version string
	Store   *store.Store
	Audit   *audit.Logger
	// UI 는 빌드된 Svelte UI 다. nil 이면 안내 페이지를 보여준다.
	UI fs.FS
	// LookupEnv 는 auth.password_env 조회용이다 (기본 os.LookupEnv). 테스트에서 바꾼다.
	LookupEnv func(string) (string, bool)
}

type Server struct {
	Token string
	cfg   Config
	mux   *http.ServeMux

	mu     sync.Mutex
	active *run            // 실행 중인 점검 (한 번에 하나)
	runs   map[string]*run // 이번 실행 동안 시작한 점검 (SSE 재생용)
}

func New(cfg Config) (*Server, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	s := &Server{Token: hex.EncodeToString(b), cfg: cfg, mux: http.NewServeMux(), runs: map[string]*run{}}
	s.routes()
	return s, nil
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": s.cfg.Version})
	})
	s.mux.HandleFunc("GET /api/checks", s.listChecks)
	s.mux.HandleFunc("GET /api/projects", s.listProjects)
	s.mux.HandleFunc("POST /api/projects", s.createProject)
	s.mux.HandleFunc("GET /api/projects/{id}", s.getProject)
	s.mux.HandleFunc("POST /api/projects/{id}", s.updateProject)
	s.mux.HandleFunc("POST /api/projects/{id}/delete", s.deleteProject)
	s.mux.HandleFunc("GET /api/projects/{id}/scans", s.listScans)
	s.mux.HandleFunc("POST /api/scope/validate", s.validateScope)
	s.mux.HandleFunc("POST /api/resolve", s.resolveHosts)
	s.mux.HandleFunc("POST /api/scans", s.startScan)
	s.mux.HandleFunc("GET /api/scans/{id}", s.getScan)
	s.mux.HandleFunc("POST /api/scans/{id}/cancel", s.cancelScan)
	s.mux.HandleFunc("GET /api/scans/{id}/events", s.scanEvents)
	s.mux.HandleFunc("GET /api/scans/{id}/findings", s.scanFindings)
	s.mux.HandleFunc("GET /api/scans/{id}/report", s.scanReport)
	s.mux.HandleFunc("GET /api/scans/{a}/diff/{b}", s.scanDiff)

	if s.cfg.UI != nil {
		s.mux.Handle("GET /", http.FileServerFS(s.cfg.UI))
	} else {
		s.mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(placeholderPage))
		})
	}
}

// Handler 는 보안 미들웨어가 적용된 핸들러를 반환한다.
func (s *Server) Handler() http.Handler {
	return securityHeaders(s.checkHost(s.checkToken(s.mux)))
}

// HTTPServer 는 루프백 주소만 허용하는 http.Server 를 만든다.
func (s *Server) HTTPServer(port int) *http.Server {
	return &http.Server{
		Addr:              net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
}

func (s *Server) checkHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackHost(r.Host) {
			http.Error(w, "invalid host", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// checkToken 은 /api/ 요청의 토큰과, 상태 변경 요청의 Origin 을 검사한다.
// 정적 페이지는 토큰 없이 열리되, 페이지가 URL 프래그먼트로 받은 토큰을 헤더에 실어 API 를 호출한다.
func (s *Server) checkToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			got := r.Header.Get(tokenHeader)
			if subtle.ConstantTimeCompare([]byte(got), []byte(s.Token)) != 1 {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				if r.Method != http.MethodPost {
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}
				if !validOrigin(r.Header.Get("Origin")) {
					http.Error(w, "invalid origin", http.StatusForbidden)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func isLoopbackHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	return host == "127.0.0.1" || strings.EqualFold(host, "localhost")
}

func validOrigin(origin string) bool {
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	return err == nil && u.Scheme == "http" && isLoopbackHost(u.Host)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError 는 {"error": "..."} 형태로 오류를 돌려준다.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// placeholderPage 는 웹 UI 없이 빌드된 바이너리(예: go build 만 실행)에서 보여 준다.
const placeholderPage = `<!doctype html><html lang="ko"><head><meta charset="utf-8"><title>intrasec - 웹 UI 없음</title></head>
<body>
<h1>intrasec</h1>
<p><b>이 실행 파일에는 웹 화면이 포함되어 있지 않습니다.</b> (<code>go build</code> / <code>go run</code> 으로 직접 빌드하면 웹 UI 가 빠집니다)</p>
<h2>방법 1. 릴리스 파일 사용 (권장)</h2>
<ol>
<li><a href="https://github.com/Sangmoo/intrasec/releases/latest" rel="noreferrer">GitHub Releases</a> 에서 <code>intrasec_&lt;버전&gt;_windows_amd64.zip</code> 을 받아 압축을 풉니다.</li>
<li>PowerShell 에서 <code>.\intrasec.exe serve</code> 를 실행합니다.</li>
</ol>
<h2>방법 2. 소스에서 빌드 (Go, Node.js 필요)</h2>
<ol>
<li>프로젝트 폴더의 PowerShell 에서 <code>.\build.ps1 -Run</code> 을 실행합니다. (macOS/Linux: <code>make build</code>)</li>
<li>웹 UI 가 포함된 <code>bin\intrasec.exe</code> 가 만들어지고 브라우저가 열립니다.</li>
</ol>
<p>지금 실행 중인 서버는 <code>Ctrl+C</code> 로 종료한 뒤 위 방법으로 다시 실행하십시오.</p>
</body></html>`
