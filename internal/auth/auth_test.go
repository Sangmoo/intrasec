package auth

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sangmoo/intrasec/internal/audit"
	"github.com/Sangmoo/intrasec/internal/checks"
	"github.com/Sangmoo/intrasec/internal/checks/checkstest"
	"github.com/Sangmoo/intrasec/internal/scope"
	"github.com/Sangmoo/intrasec/internal/transport"
)

const testPassword = "test-only-password"

// fakeERP 는 CSRF hidden 필드가 있는 폼 로그인과 세션 만료를 흉내 낸다.
type fakeERP struct {
	mu       sync.Mutex
	sessions map[string]bool
	logins   int
}

func (e *fakeERP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.mu.Lock()
	defer e.mu.Unlock()
	switch r.URL.Path {
	case "/login.jsp":
		_, _ = w.Write([]byte(`<form method="post" action="/loginProc.do">
<input type="hidden" name="_csrf" value="tok123"><input name="userId"><input type="password" name="userPw"></form>`))
	case "/loginProc.do":
		_ = r.ParseForm()
		if r.PostForm.Get("_csrf") != "tok123" || r.PostForm.Get("userId") != "scan_test01" || r.PostForm.Get("userPw") != testPassword {
			http.Redirect(w, r, "/login.jsp?error=1", http.StatusFound)
			return
		}
		e.logins++
		sid := "S" + strings.Repeat("x", e.logins)
		e.sessions[sid] = true
		http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: sid, Path: "/"})
		http.Redirect(w, r, "/main.do", http.StatusFound)
	default:
		c, err := r.Cookie("JSESSIONID")
		if err != nil || !e.sessions[c.Value] {
			http.Redirect(w, r, "/login.jsp", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("<html>업무 메인</html>"))
	}
}

func (e *fakeERP) expireAll() {
	e.mu.Lock()
	e.sessions = map[string]bool{}
	e.mu.Unlock()
}

func setup(t *testing.T, pw string) (*fakeERP, checks.Target, *checks.Session, *Form, *bytes.Buffer) {
	t.Helper()
	erp := &fakeERP{sessions: map[string]bool{}}
	tgt, s := checkstest.Serve(t, erp)
	var logBuf bytes.Buffer
	f, err := New(scope.Auth{
		Target: "lab", Type: "form", LoginURL: tgt.BaseURL.String() + "/login.jsp",
		UsernameField: "userId", PasswordField: "userPw", Username: "scan_test01", PasswordEnv: "X",
		CheckURL: tgt.BaseURL.String() + "/main.do",
	}, s.HTTP, audit.New(&logBuf), func(string, string) (string, error) { return pw, nil })
	if err != nil {
		t.Fatal(err)
	}
	s.Auth = map[string]checks.Authenticator{f.Host(): f}
	return erp, tgt, s, f, &logBuf
}

func TestLoginAndRelogin(t *testing.T) {
	erp, tgt, s, f, logBuf := setup(t, testPassword)
	ctx := context.Background()
	if err := f.Login(ctx); err != nil {
		t.Fatal(err)
	}
	p, err := checks.Fetch(ctx, s, tgt.BaseURL.String()+"/board.do")
	if err != nil || !strings.Contains(string(p.Body), "업무 메인") {
		t.Fatalf("로그인 세션으로 접근 실패: %v %s", err, p.Body)
	}

	// 세션 만료 → Fetch 가 감지하고 재로그인 후 재요청
	erp.expireAll()
	f.lastLogin = time.Now().Add(-time.Minute)
	p, err = checks.Fetch(ctx, s, tgt.BaseURL.String()+"/board.do")
	if err != nil || !strings.Contains(string(p.Body), "업무 메인") {
		t.Fatalf("재로그인 후 접근 실패: %v %s", err, p.Body)
	}
	if erp.logins != 2 || f.relogins != 1 {
		t.Fatalf("로그인 2회·재로그인 1회 기대: logins=%d relogins=%d", erp.logins, f.relogins)
	}

	// 세션 없이 요청하면 재로그인하지 않는다.
	p, err = checks.Fetch(transport.Anonymous(ctx), s, tgt.BaseURL.String()+"/board.do")
	if err != nil || !strings.HasSuffix(p.URL, "/login.jsp") || erp.logins != 2 {
		t.Fatalf("Anonymous 요청 이상: %v %s logins=%d", err, p.URL, erp.logins)
	}

	if strings.Contains(logBuf.String(), testPassword) {
		t.Fatal("감사 로그에 비밀번호가 기록됨")
	}
}

func TestReloginRateLimited(t *testing.T) {
	erp, tgt, s, f, _ := setup(t, testPassword)
	ctx := context.Background()
	if err := f.Login(ctx); err != nil {
		t.Fatal(err)
	}
	erp.expireAll()
	// 직전 로그인 직후라 재로그인하지 않는다 (계정 잠금 방지).
	p, err := checks.Fetch(ctx, s, tgt.BaseURL.String()+"/board.do")
	if err != nil || erp.logins != 1 || !strings.HasSuffix(p.URL, "/login.jsp") {
		t.Fatalf("간격 제한 미적용: logins=%d url=%s err=%v", erp.logins, p.URL, err)
	}
	if err := f.Relogin(ctx); !errors.Is(err, ErrReloginLimit) {
		t.Fatalf("ErrReloginLimit 기대: %v", err)
	}
}

func TestLoginWrongPassword(t *testing.T) {
	_, _, _, f, _ := setup(t, "wrong")
	if err := f.Login(context.Background()); !errors.Is(err, ErrLoginFailed) {
		t.Fatalf("ErrLoginFailed 기대: %v", err)
	}
}

func TestNoPassword(t *testing.T) {
	_, err := New(scope.Auth{LoginURL: "https://x.local/login", PasswordEnv: "INTRASEC_X"}, nil, nil,
		func(string, string) (string, error) { return "", nil })
	if !errors.Is(err, ErrNoPassword) {
		t.Fatalf("ErrNoPassword 기대: %v", err)
	}
}
