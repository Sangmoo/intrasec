// Package common 은 대상 종류와 무관한 공통 점검(헤더, TLS, 쿠키, 노출 파일 등)을 담는다.
package common

import (
	"context"
	"net/http"
	"regexp"
	"strings"

	"github.com/Sangmoo/intrasec/internal/checks"
	"github.com/Sangmoo/intrasec/pkg/finding"
)

func init() {
	checks.Register(headersCheck{})
}

// headersCheck 는 COMMON-HDR-001~005 를 한 번의 GET 으로 판단한다.
type headersCheck struct{}

func (headersCheck) ID() string          { return "COMMON-HDR" }
func (headersCheck) Name() string        { return "보안 헤더 점검" }
func (headersCheck) Level() checks.Level { return checks.Passive }
func (headersCheck) Tags() []string      { return []string{checks.TagCommon, "headers"} }

func (headersCheck) Run(ctx context.Context, t checks.Target, s *checks.Session) ([]finding.Finding, error) {
	p, err := checks.Fetch(ctx, s, t.BaseURL.String())
	if err != nil {
		return nil, err
	}
	return analyzeHeaders(p.URL, strings.HasPrefix(p.URL, "https://"), p.Header, p.Evidence), nil
}

var versionLike = regexp.MustCompile(`\d+(\.\d+)+`)

func analyzeHeaders(target string, isHTTPS bool, h http.Header, ev finding.Evidence) []finding.Finding {
	var out []finding.Finding
	add := func(id, title string, sev finding.Severity, cwe, owasp []string, desc, fix string) {
		out = append(out, finding.Finding{
			CheckID: id, Title: title, Severity: sev, Target: target, Evidence: ev,
			CWE: cwe, OWASP: owasp, Description: desc, Remediation: fix,
		})
	}

	csp := h.Get("Content-Security-Policy")
	if csp == "" {
		add("COMMON-HDR-001", "Content-Security-Policy 누락", finding.SevMedium,
			[]string{"CWE-693"}, []string{"A05:2021"},
			"응답에 Content-Security-Policy 헤더가 없어 XSS 등 콘텐츠 주입 공격의 피해를 완화할 수 없습니다.",
			"웹 서버 또는 애플리케이션에서 Content-Security-Policy 헤더를 설정하십시오. 우선 Content-Security-Policy-Report-Only 로 영향도를 확인한 뒤 적용을 권장합니다.")
	}

	if isHTTPS && h.Get("Strict-Transport-Security") == "" {
		add("COMMON-HDR-002", "Strict-Transport-Security 누락", finding.SevMedium,
			[]string{"CWE-319"}, []string{"A05:2021"},
			"HTTPS 응답에 HSTS 헤더가 없어 HTTP 다운그레이드 및 SSL 스트리핑 공격에 노출될 수 있습니다.",
			"Strict-Transport-Security: max-age=31536000; includeSubDomains 헤더를 설정하십시오.")
	}

	if h.Get("X-Frame-Options") == "" && !strings.Contains(strings.ToLower(csp), "frame-ancestors") {
		add("COMMON-HDR-003", "X-Frame-Options / frame-ancestors 누락", finding.SevMedium,
			[]string{"CWE-1021"}, []string{"A05:2021"},
			"프레임 삽입 제한이 없어 클릭재킹 공격에 노출될 수 있습니다.",
			"X-Frame-Options: SAMEORIGIN 또는 CSP frame-ancestors 'self' 를 설정하십시오.")
	}

	if !strings.EqualFold(strings.TrimSpace(h.Get("X-Content-Type-Options")), "nosniff") {
		add("COMMON-HDR-004", "X-Content-Type-Options 누락", finding.SevLow,
			[]string{"CWE-693"}, []string{"A05:2021"},
			"X-Content-Type-Options: nosniff 가 없어 브라우저의 MIME 스니핑으로 인한 스크립트 실행 위험이 있습니다.",
			"모든 응답에 X-Content-Type-Options: nosniff 헤더를 설정하십시오.")
	}

	var leaks []string
	if v := h.Get("Server"); versionLike.MatchString(v) {
		leaks = append(leaks, "Server: "+v)
	}
	for _, k := range []string{"X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"} {
		if v := h.Get(k); v != "" {
			leaks = append(leaks, k+": "+v)
		}
	}
	if len(leaks) > 0 {
		add("COMMON-HDR-005", "Server / X-Powered-By 버전 노출", finding.SevLow,
			[]string{"CWE-200"}, []string{"A05:2021"},
			"응답 헤더에 서버 제품/버전 정보가 노출되어 공격자가 알려진 취약점을 선별하는 데 이용할 수 있습니다: "+strings.Join(leaks, ", "),
			"웹 서버 설정에서 버전 정보를 숨기십시오 (예: Apache ServerTokens Prod, nginx server_tokens off, WebLogic 'Send Server Header' 비활성화).")
	}
	return out
}
