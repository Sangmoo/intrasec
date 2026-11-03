// Package auth 는 폼 로그인, 세션 쿠키 유지, 세션 만료 감지 후 재로그인을 담당한다.
//
// 비밀번호는 scope.yaml 의 password_env 로 지정한 환경변수(없으면 실행 시 입력)에서만 읽으며
// DB·로그·리포트·감사 로그에 남기지 않는다. 로그인 요청 본문은 요청 기록에도 포함되지 않는다.
// 로그아웃 URL 은 scope 의 기본 제외 경로로 요청 자체가 차단된다.
package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Sangmoo/intrasec/internal/audit"
	"github.com/Sangmoo/intrasec/internal/checks"
	"github.com/Sangmoo/intrasec/internal/scope"
	"github.com/Sangmoo/intrasec/internal/transport"
)

var (
	ErrLoginFailed  = errors.New("로그인 실패")
	ErrReloginLimit = errors.New("재로그인 횟수 초과 (세션이 계속 만료됨 — 로그아웃 유발 요청 또는 동시 로그인 제한 확인 필요)")
	ErrNoPassword   = errors.New("비밀번호 없음")
)

const (
	// MaxRelogins 는 점검 한 번에서 대상별 최대 재로그인 횟수다.
	MaxRelogins = 5
	// MinReloginInterval 안에 다시 만료되면 재로그인하지 않는다 (로그인 반복으로 계정 잠금 방지).
	MinReloginInterval = 10 * time.Second
)

// Form 은 폼 로그인 세션 관리자다. checks.Authenticator 를 구현한다.
type Form struct {
	cfg       scope.Auth
	password  string
	http      *transport.Client
	audit     *audit.Logger
	loginURL  *url.URL
	loggedOut *regexp.Regexp
	now       func() time.Time

	mu        sync.Mutex
	lastLogin time.Time
	relogins  int
	actionURL *url.URL // 실제 로그인 폼 action (로그인 페이지에서 찾음)
}

// PasswordSource 는 환경변수 이름으로 비밀번호를 찾는다. 기본은 os.LookupEnv, 없으면 터미널 입력.
type PasswordSource func(envName, prompt string) (string, error)

// New 는 설정을 검증하고 비밀번호를 읽는다. 로그인은 Login 에서 한다.
func New(cfg scope.Auth, c *transport.Client, al *audit.Logger, pw PasswordSource) (*Form, error) {
	lu, err := url.Parse(cfg.LoginURL)
	if err != nil {
		return nil, err
	}
	f := &Form{cfg: cfg, http: c, audit: al, loginURL: lu, now: time.Now}
	if cfg.LoggedOutPattern != "" {
		if f.loggedOut, err = regexp.Compile(cfg.LoggedOutPattern); err != nil {
			return nil, err
		}
	}
	f.password, err = pw(cfg.PasswordEnv, fmt.Sprintf("%s (%s) 비밀번호", cfg.Target, cfg.Username))
	if err != nil {
		return nil, err
	}
	if f.password == "" {
		return nil, fmt.Errorf("%w: %s 환경변수를 설정하거나 실행 시 입력하십시오", ErrNoPassword, cfg.PasswordEnv)
	}
	return f, nil
}

// Host 는 이 세션이 적용되는 호스트명(소문자)이다.
func (f *Form) Host() string { return strings.ToLower(f.loginURL.Hostname()) }

// Login 은 로그인 페이지에서 폼(hidden 필드·action)을 읽고 계정을 전송한 뒤 로그인 여부를 확인한다.
func (f *Form) Login(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.loginLocked(ctx)
}

func (f *Form) loginLocked(ctx context.Context) error {
	action, fields := f.loginURL, url.Values{}
	if page, err := f.get(ctx, f.loginURL.String()); err == nil {
		if a, hidden, ok := parseLoginForm(page, f.cfg.PasswordField); ok {
			action, fields = a, hidden
		}
	} else if checks.Abort(err) {
		return err
	}
	f.actionURL = action
	fields.Set(f.cfg.UsernameField, f.cfg.Username)
	fields.Set(f.cfg.PasswordField, f.password)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, action.String(), strings.NewReader(fields.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", f.loginURL.String())
	resp, err := f.http.Do(req) //nolint:bodyclose // transport.ReadBody 가 닫는다
	if err != nil {
		f.log("auth.login.fail", err.Error())
		return fmt.Errorf("%w: %w", ErrLoginFailed, err)
	}
	body, _ := transport.ReadBody(resp, checks.MaxProbeBody)
	result := &checks.Page{URL: resp.Request.URL.String(), Status: resp.StatusCode, Header: resp.Header, Body: body}

	// 로그인 확인: check_url 이 있으면 그 페이지로, 없으면 로그인 응답 자체로 판단한다.
	if f.cfg.CheckURL != "" {
		if result, err = f.get(ctx, f.cfg.CheckURL); err != nil {
			f.log("auth.login.fail", "check_url: "+err.Error())
			return fmt.Errorf("%w: check_url 요청 실패: %w", ErrLoginFailed, err)
		}
	}
	if f.loggedOutLocked(f.cfg.CheckURL, result) || hasPasswordField(result.Body, f.cfg.PasswordField) {
		f.log("auth.login.fail", fmt.Sprintf("로그인 후에도 로그아웃 상태 (HTTP %d)", result.Status))
		return fmt.Errorf("%w: 계정·필드 이름·login_url 을 확인하십시오 (HTTP %d, %s)", ErrLoginFailed, result.Status, result.URL)
	}
	f.lastLogin = f.now()
	f.log("auth.login", "성공")
	return nil
}

// Relogin 은 세션 만료 시 다시 로그인한다. 횟수·간격 제한으로 계정 잠금을 막는다.
func (f *Form) Relogin(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.relogins >= MaxRelogins {
		return ErrReloginLimit
	}
	if !f.lastLogin.IsZero() && f.now().Sub(f.lastLogin) < MinReloginInterval {
		return fmt.Errorf("%w: 직전 로그인 후 %s 안에 다시 만료됨", ErrReloginLimit, MinReloginInterval)
	}
	f.relogins++
	f.log("auth.relogin", fmt.Sprintf("세션 만료 감지, 재로그인 %d/%d", f.relogins, MaxRelogins))
	return f.loginLocked(ctx)
}

// LoggedOut 은 응답이 세션 만료 상태로 보이는지 판단한다.
// 로그인 페이지 자체를 요청한 경우는 만료로 보지 않는다.
func (f *Form) LoggedOut(requested string, p *checks.Page) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.loggedOutLocked(requested, p)
}

func (f *Form) loggedOutLocked(requested string, p *checks.Page) bool {
	if p == nil {
		return false
	}
	if ru, err := url.Parse(requested); err == nil && f.isLoginPath(ru.Path) {
		return false
	}
	if p.Status == http.StatusUnauthorized {
		return true
	}
	if f.loggedOut != nil {
		return f.loggedOut.Match(p.Body)
	}
	if fu, err := url.Parse(p.URL); err == nil && f.isLoginPath(fu.Path) {
		return true
	}
	return false
}

func (f *Form) isLoginPath(p string) bool {
	if p == "" {
		return false
	}
	if strings.EqualFold(p, f.loginURL.Path) {
		return true
	}
	return f.actionURL != nil && strings.EqualFold(p, f.actionURL.Path)
}

// get 은 재로그인 훅을 거치지 않는 단순 GET 이다 (로그인 과정 내부용).
func (f *Form) get(ctx context.Context, raw string) (*checks.Page, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.http.Do(req) //nolint:bodyclose // transport.ReadBody 가 닫는다
	if err != nil {
		return nil, err
	}
	body, err := transport.ReadBody(resp, checks.MaxProbeBody)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, err
	}
	return &checks.Page{URL: resp.Request.URL.String(), Status: resp.StatusCode, Header: resp.Header, Body: body}, nil
}

func (f *Form) log(action, detail string) {
	f.audit.Log(audit.Event{Action: action, Target: f.loginURL.String(), Detail: f.cfg.Target + " / " + f.cfg.Username + ": " + detail})
}

var (
	formRe   = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form>`)
	actionRe = regexp.MustCompile(`(?i)\baction\s*=\s*["']?([^"'\s>]*)`)
	inputRe  = regexp.MustCompile(`(?is)<input\b[^>]*>`)
	attrRe   = regexp.MustCompile(`(?i)\b(type|name|value)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
)

// parseLoginForm 은 비밀번호 필드가 있는 폼의 action 과 hidden 필드(CSRF 토큰 등)를 찾는다.
func parseLoginForm(p *checks.Page, passwordField string) (*url.URL, url.Values, bool) {
	base, err := url.Parse(p.URL)
	if err != nil {
		return nil, nil, false
	}
	for _, m := range formRe.FindAllSubmatch(p.Body, -1) {
		inner := m[2]
		if !hasPasswordField(inner, passwordField) {
			continue
		}
		action := base
		if am := actionRe.FindSubmatch(m[1]); am != nil && len(am[1]) > 0 {
			if ref, err := url.Parse(string(am[1])); err == nil {
				action = base.ResolveReference(ref)
			}
		}
		hidden := url.Values{}
		for _, in := range inputRe.FindAll(inner, -1) {
			attrs := map[string]string{}
			for _, a := range attrRe.FindAllSubmatch(in, -1) {
				attrs[strings.ToLower(string(a[1]))] = string(a[2]) + string(a[3]) + string(a[4])
			}
			if strings.EqualFold(attrs["type"], "hidden") && attrs["name"] != "" {
				hidden.Set(attrs["name"], attrs["value"])
			}
		}
		return action, hidden, true
	}
	return nil, nil, false
}

func hasPasswordField(b []byte, name string) bool {
	re := regexp.MustCompile(`(?i)<input\b[^>]*name\s*=\s*["']?` + regexp.QuoteMeta(name) + `["'\s>]`)
	for _, in := range re.FindAll(b, -1) {
		if regexp.MustCompile(`(?i)type\s*=\s*["']?password`).Match(in) {
			return true
		}
	}
	return regexp.MustCompile(`(?i)<input\b[^>]*type\s*=\s*["']?password[^>]*name\s*=\s*["']?` + regexp.QuoteMeta(name)).Match(b)
}
