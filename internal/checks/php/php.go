// Package php 는 PHP 기반 웹 시스템 점검을 담는다.
//
// 모든 요청은 GET 이며 공격 코드를 보내지 않는다 (passive). 취약점은 버전·노출 근거로만 판단한다.
//
//   - PHP-001~004 버전 기반 판단 (EOL, PHP2Shell, CVE-2024-4577, CVE-2019-11043)
//   - PHP-010~017 위험 파일·도구·디버그 페이지 노출
package php

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/Sangmoo/intrasec/internal/checks"
	"github.com/Sangmoo/intrasec/pkg/finding"
)

func init() {
	checks.Register(phpCheck{now: time.Now})
}

const TagPHP = "php"

type phpCheck struct {
	now func() time.Time
}

func (phpCheck) ID() string          { return "PHP" }
func (phpCheck) Name() string        { return "PHP 버전·노출 점검" }
func (phpCheck) Level() checks.Level { return checks.Passive }

// Tags 에 common 을 넣어 모든 대상에서 PHP 흔적을 확인한다.
// 흔적이 없고 대상 태그에 php 가 없으면 경로 탐색은 건너뛴다.
func (phpCheck) Tags() []string { return []string{checks.TagCommon, TagPHP} }

func (c phpCheck) Run(ctx context.Context, t checks.Target, s *checks.Session) ([]finding.Finding, error) {
	base, err := checks.Fetch(ctx, s, t.BaseURL.String())
	if err != nil {
		return nil, err
	}
	fp := fingerprint(base)
	if !fp.php && !hasTag(t.Tags, TagPHP) {
		return nil, nil
	}

	var out []finding.Finding
	errReported := false
	if f, ok := detectErrorDisclosure(base); ok {
		out = append(out, f)
		errReported = true
	}

	// 운영 안전 모드에서는 경로 탐색 없이 헤더 기반 버전 판단만 한다.
	activeProbes := probes
	if s.Safe {
		activeProbes = nil
	}
	var notFound *checks.Page
	if len(activeProbes) > 0 {
		notFound = s.NotFoundPage(ctx, t)
	}
	for _, p := range activeProbes {
		for _, u := range checks.ProbeURLs(t, p.path) {
			page, err := checks.Fetch(ctx, s, u)
			if err != nil {
				if checks.Abort(err) {
					return out, err
				}
				continue
			}
			if !errReported {
				if f, ok := detectErrorDisclosure(page); ok {
					out = append(out, f)
					errReported = true
				}
			}
			if !checks.Found(page, notFound) {
				continue
			}
			note, ok := p.match(page)
			if !ok {
				continue
			}
			ev := page.Evidence
			ev.Note = note
			out = append(out, finding.Finding{
				CheckID: p.id, Title: p.title, Severity: p.sev, Target: page.URL, Evidence: ev,
				CWE: p.cwe, OWASP: p.owasp, KISA: p.kisa, Description: p.desc, Remediation: p.fix,
			})
			if p.id == "PHP-010" {
				fp.merge(parsePHPInfo(page.Body))
			}
		}
	}

	if fp.version != nil {
		out = append(out, evaluate(t.BaseURL.String(), *fp.version, fp.env, c.now(), base.Evidence)...)
	}
	return out, nil
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if strings.EqualFold(t, want) {
			return true
		}
	}
	return false
}

// fp 는 PHP 사용 흔적과 버전·환경 추정 결과다.
type fp struct {
	php     bool
	version *Version
	env     Env
}

var phpLink = regexp.MustCompile(`(?i)\.php(?:["'?#/]|\s)`)

func fingerprint(p *checks.Page) fp {
	var r fp
	server := p.Header.Get("Server")
	powered := strings.Join(p.Header.Values("X-Powered-By"), ", ")

	for _, src := range []struct{ name, val string }{{"X-Powered-By", powered}, {"Server", server}} {
		if v, ok := ParseVersion(src.val); ok && r.version == nil {
			r.version = &v
			r.env.Sources = append(r.env.Sources, src.name+" 헤더")
		}
	}
	if r.version != nil || strings.Contains(strings.ToUpper(powered), "PHP") {
		r.php = true
	}
	for _, c := range p.Header.Values("Set-Cookie") {
		if strings.HasPrefix(strings.ToUpper(c), "PHPSESSID=") {
			r.php = true
		}
	}
	if phpLink.Match(p.Body) || strings.HasSuffix(strings.ToLower(p.URL), ".php") {
		r.php = true
	}

	ls := strings.ToLower(server)
	r.env.Windows = strings.Contains(ls, "win32") || strings.Contains(ls, "win64") || strings.Contains(ls, "microsoft-iis")
	r.env.Nginx = strings.Contains(ls, "nginx")
	return r
}

// merge 는 phpinfo 에서 얻은 더 정확한 정보로 덮어쓴다.
func (r *fp) merge(info phpInfo) {
	r.php = true
	if info.version != nil {
		r.version = info.version
		r.env.Sources = append(r.env.Sources, "phpinfo()")
	}
	if info.sapi != "" {
		r.env.SAPI, r.env.SAPIKnown = info.sapi, true
	}
	if info.windows {
		r.env.Windows = true
	}
}
