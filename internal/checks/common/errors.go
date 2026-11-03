package common

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"

	"github.com/Sangmoo/intrasec/internal/checks"
	"github.com/Sangmoo/intrasec/pkg/finding"
)

func init() {
	checks.Register(errorDisclosureCheck{})
}

// errorDisclosureCheck 는 COMMON-ERR-001 (상세 에러·스택트레이스 노출)을 판단한다.
// 기본 페이지와 존재하지 않는 경로(.jsp/.do/.aspx)의 오류 응답만 확인하며 파라미터 변조는 하지 않는다.
// PHP 에러 메시지는 PHP-011 에서 다룬다.
type errorDisclosureCheck struct{}

func (errorDisclosureCheck) ID() string          { return "COMMON-ERR" }
func (errorDisclosureCheck) Name() string        { return "상세 에러 노출 점검" }
func (errorDisclosureCheck) Level() checks.Level { return checks.Passive }
func (errorDisclosureCheck) Tags() []string      { return []string{checks.TagCommon, "errors"} }

type errPattern struct {
	name string
	sev  finding.Severity
	re   *regexp.Regexp
}

var errPatterns = []errPattern{
	{"Java 스택트레이스", finding.SevMedium, regexp.MustCompile(`(?m)(?:^|\s|>)at (?:java|javax|jakarta|org\.apache|org\.springframework|weblogic|com\.sun|com\.ibm|oracle)\.[\w.$]+\([\w.]*(?::\d+)?\)|\bjava\.lang\.\w+(?:Exception|Error)\b`)},
	{"ASP.NET 상세 오류", finding.SevMedium, regexp.MustCompile(`Server Error in '/[^']*' Application|<b>\s*Stack Trace:\s*</b>|Detailed Error Information`)},
	{"Python 트레이스백", finding.SevMedium, regexp.MustCompile(`Traceback \(most recent call last\)`)},
	{"Node.js 스택트레이스", finding.SevMedium, regexp.MustCompile(`at [\w.<>]+ \((?:/|[A-Z]:\\)[^)]+\.js:\d+:\d+\)`)},
	{"DB 오류 메시지", finding.SevMedium, regexp.MustCompile(`\bORA-\d{5}\b|SQLSTATE\[\w+\]|You have an error in your SQL syntax|Microsoft OLE DB Provider for|Unclosed quotation mark after the character string|org\.postgresql\.util\.PSQLException|java\.sql\.SQLException`)},
	{"에러 페이지 서버 버전 노출", finding.SevLow, regexp.MustCompile(`Apache Tomcat/\d+\.\d+[\d.]*|JBoss(?:Web)?/\d+\.\d+|Jetty\(\d+\.\d+|WebLogic Server \d+\.\d+|Oracle-Application-Server-\d+`)},
}

func (errorDisclosureCheck) Run(ctx context.Context, t checks.Target, s *checks.Session) ([]finding.Finding, error) {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	rnd := "intrasec-" + hex.EncodeToString(b)
	urls := []string{t.BaseURL.String()}
	exts := []string{".jsp", ".do", ".aspx"}
	if s.Safe {
		exts = exts[:1]
	}
	for _, ext := range exts {
		urls = append(urls, t.BaseURL.ResolveReference(&url.URL{Path: "/" + rnd + ext}).String())
	}

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
		for _, f := range analyzeErrorPage(p) {
			if !seen[f.Title] {
				seen[f.Title] = true
				out = append(out, f)
			}
		}
	}
	return out, nil
}

func analyzeErrorPage(p *checks.Page) []finding.Finding {
	var out []finding.Finding
	for _, ep := range errPatterns {
		loc := ep.re.FindIndex(p.Body)
		if loc == nil {
			continue
		}
		ev := p.Evidence
		ev.Note = ep.name + " 표식: " + snippet(p.Body, loc[0], loc[1])
		title := "상세 에러/스택트레이스 노출 (" + ep.name + ")"
		desc := "오류 응답에 " + ep.name + " 정보가 노출되어 내부 구조, 프레임워크·DB 종류와 버전, 소스 경로가 공개됩니다. SQL 인젝션 등 추가 공격의 단서가 됩니다."
		if ep.sev == finding.SevLow {
			title = "에러 페이지 서버 버전 노출"
			desc = "기본 오류 페이지에 WAS 제품·버전이 노출되어 알려진 취약점 선별에 이용됩니다."
		}
		out = append(out, finding.Finding{
			CheckID: "COMMON-ERR-001", Title: title, Severity: ep.sev, Target: p.URL, Evidence: ev,
			CWE: []string{"CWE-209"}, OWASP: []string{"A05:2021"}, KISA: []string{"IL"},
			Description: desc,
			Remediation: "운영 환경에서 상세 오류 출력을 끄고(예: web.xml <error-page>, ASP.NET customErrors mode=On, Spring server.error.include-stacktrace=never) 공통 오류 페이지를 사용하십시오. 상세 내용은 서버 로그에만 남기십시오.",
		})
	}
	return out
}

// snippet 은 일치 위치 주변을 한 줄로 잘라 근거로 쓴다 (최대 160자).
func snippet(b []byte, start, end int) string {
	from, to := max(0, start-40), min(len(b), end+80)
	s := strings.Join(strings.Fields(string(b[from:to])), " ")
	if r := []rune(s); len(r) > 160 {
		s = string(r[:160]) + "…"
	}
	return s
}
