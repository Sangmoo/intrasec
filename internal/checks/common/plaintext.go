package common

import (
	"context"
	"net/url"
	"regexp"

	"github.com/Sangmoo/intrasec/internal/checks"
	"github.com/Sangmoo/intrasec/pkg/finding"
)

func init() {
	checks.Register(plaintextLoginCheck{})
}

// plaintextLoginCheck 는 COMMON-HTTP-001 (비밀번호 입력 폼을 HTTP 평문으로 제공)을 판단한다.
type plaintextLoginCheck struct{}

func (plaintextLoginCheck) ID() string          { return "COMMON-HTTP" }
func (plaintextLoginCheck) Name() string        { return "로그인 평문 전송 점검" }
func (plaintextLoginCheck) Level() checks.Level { return checks.Passive }
func (plaintextLoginCheck) Tags() []string      { return []string{checks.TagCommon, "http"} }

var (
	passwordInput = regexp.MustCompile(`(?i)<input[^>]+type\s*=\s*["']?password`)
	// formAction 은 https 페이지 안에서 http:// 로 전송하는 로그인 폼을 찾는다.
	httpFormAction = regexp.MustCompile(`(?i)<form[^>]+action\s*=\s*["']?(http://[^"'\s>]+)`)
)

// loginPaths 는 흔한 로그인 경로다. base_url 이 로그인 페이지가 아닐 때를 대비한다.
var loginPaths = []string{"/login", "/login.do", "/login.jsp", "/login.php", "/login.aspx", "/member/login", "/user/login", "/account/login"}

func (plaintextLoginCheck) Run(ctx context.Context, t checks.Target, s *checks.Session) ([]finding.Finding, error) {
	urls := []string{t.BaseURL.String()}
	// https 대상이면 같은 호스트의 http(80) 도 확인한다. scope 에 80 포트가 없으면 transport 가 거부하므로 건너뛴다.
	if t.BaseURL.Scheme == "https" {
		u := *t.BaseURL
		u.Scheme, u.Host = "http", u.Hostname()
		urls = append(urls, u.String())
	}
	if t.BaseURL.Scheme == "http" && !s.Safe {
		for _, p := range loginPaths {
			urls = append(urls, checks.ProbeURLs(t, p)...)
		}
	}

	notFound := s.NotFoundPage(ctx, t)
	var out []finding.Finding
	seen := map[string]bool{}
	for _, u := range urls {
		p, err := checks.Fetch(ctx, s, u)
		if err != nil {
			if checks.Abort(err) {
				return out, err
			}
			continue
		}
		if seen[p.URL] || (u != t.BaseURL.String() && !checks.Found(p, notFound)) {
			continue
		}
		seen[p.URL] = true
		if f, ok := analyzePlaintextLogin(p); ok {
			out = append(out, f)
		}
	}
	return out, nil
}

func analyzePlaintextLogin(p *checks.Page) (finding.Finding, bool) {
	if !passwordInput.Match(p.Body) {
		return finding.Finding{}, false
	}
	u, err := url.Parse(p.URL)
	if err != nil {
		return finding.Finding{}, false
	}
	ev := p.Evidence
	switch u.Scheme {
	case "http":
		ev.Note = "비밀번호 입력 필드가 HTTP 응답에 포함됨 (HTTPS 리다이렉트 없음)"
	default:
		m := httpFormAction.FindSubmatch(p.Body)
		if m == nil {
			return finding.Finding{}, false
		}
		ev.Note = "HTTPS 페이지의 로그인 폼이 평문 주소로 전송: " + string(m[1])
	}
	return finding.Finding{
		CheckID: "COMMON-HTTP-001", Title: "로그인 페이지 HTTP 평문 제공", Severity: finding.SevHigh, Target: p.URL, Evidence: ev,
		CWE: []string{"CWE-319"}, OWASP: []string{"A02:2021"}, KISA: []string{"SN"},
		Description: "계정과 비밀번호가 암호화되지 않은 HTTP 로 전송되어, 같은 네트워크의 공격자가 스니핑으로 계정을 탈취할 수 있습니다.",
		Remediation: "로그인을 포함한 전체 서비스를 HTTPS 로 제공하고, HTTP 요청은 HTTPS 로 301 리다이렉트하며 HSTS 를 설정하십시오.",
	}, true
}
