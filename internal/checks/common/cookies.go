package common

import (
	"context"
	"net/http"
	"strings"

	"github.com/Sangmoo/intrasec/internal/checks"
	"github.com/Sangmoo/intrasec/pkg/finding"
)

func init() {
	checks.Register(cookiesCheck{})
}

// cookiesCheck 는 COMMON-CKE-001~003 을 판단한다.
type cookiesCheck struct{}

func (cookiesCheck) ID() string          { return "COMMON-CKE" }
func (cookiesCheck) Name() string        { return "세션 쿠키 속성 점검" }
func (cookiesCheck) Level() checks.Level { return checks.Passive }
func (cookiesCheck) Tags() []string      { return []string{checks.TagCommon, "cookies"} }

func (cookiesCheck) Run(ctx context.Context, t checks.Target, s *checks.Session) ([]finding.Finding, error) {
	p, err := checks.Fetch(ctx, s, t.BaseURL.String())
	if err != nil {
		return nil, err
	}
	cookies := (&http.Response{Header: p.Header}).Cookies()
	return analyzeCookies(p.URL, strings.HasPrefix(p.URL, "https://"), cookies, p.Evidence), nil
}

// sessionCookieHints 는 세션 쿠키로 간주할 이름 조각이다.
var sessionCookieHints = []string{"session", "sessid", "jsessionid", "phpsessid", "asp.net_sessionid", "sid", "token", "auth"}

func isSessionCookie(name string) bool {
	n := strings.ToLower(name)
	for _, h := range sessionCookieHints {
		if strings.Contains(n, h) {
			return true
		}
	}
	return false
}

func analyzeCookies(target string, isHTTPS bool, cookies []*http.Cookie, ev finding.Evidence) []finding.Finding {
	var noSecure, noHTTPOnly, noSameSite []string
	for _, c := range cookies {
		if !isSessionCookie(c.Name) {
			continue
		}
		if isHTTPS && !c.Secure {
			noSecure = append(noSecure, c.Name)
		}
		if !c.HttpOnly {
			noHTTPOnly = append(noHTTPOnly, c.Name)
		}
		// 속성이 없으면 0, 값 없이 "SameSite" 만 있으면 SameSiteDefaultMode 다.
		if c.SameSite == 0 || c.SameSite == http.SameSiteDefaultMode {
			noSameSite = append(noSameSite, c.Name)
		}
	}

	var out []finding.Finding
	add := func(id, title string, sev finding.Severity, cwe string, names []string, desc, fix string) {
		if len(names) == 0 {
			return
		}
		e := ev
		e.Note = "대상 쿠키: " + strings.Join(names, ", ")
		out = append(out, finding.Finding{
			CheckID: id, Title: title, Severity: sev, Target: target, Evidence: e,
			CWE: []string{cwe}, OWASP: []string{"A05:2021"}, Description: desc, Remediation: fix,
		})
	}
	add("COMMON-CKE-001", "세션 쿠키 Secure 누락", finding.SevMedium, "CWE-614", noSecure,
		"HTTPS 서비스의 세션 쿠키에 Secure 속성이 없어 평문 HTTP 요청 시 세션이 노출될 수 있습니다.",
		"세션 쿠키에 Secure 속성을 설정하십시오 (WebLogic: weblogic.xml cookie-secure=true).")
	add("COMMON-CKE-002", "세션 쿠키 HttpOnly 누락", finding.SevMedium, "CWE-1004", noHTTPOnly,
		"세션 쿠키에 HttpOnly 속성이 없어 XSS 발생 시 스크립트로 세션이 탈취될 수 있습니다.",
		"세션 쿠키에 HttpOnly 속성을 설정하십시오 (WebLogic: weblogic.xml cookie-http-only=true).")
	add("COMMON-CKE-003", "세션 쿠키 SameSite 미설정", finding.SevLow, "CWE-1275", noSameSite,
		"세션 쿠키에 SameSite 속성이 없어 CSRF 공격 완화가 브라우저 기본 동작에 의존합니다.",
		"세션 쿠키에 SameSite=Lax 이상을 설정하십시오.")
	return out
}
