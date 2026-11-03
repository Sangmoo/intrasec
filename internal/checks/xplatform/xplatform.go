// Package xplatform 은 Tobesoft XPlatform / MiPlatform / Nexacro 서비스 URL 점검을 담는다.
//
//   - XP-001 서비스 URL 이 세션 없이 데이터를 응답 (scope 의 service_urls 에 등록한 조회성 서비스만 호출)
//   - XP-002 서비스 통신 평문(HTTP) 전송
//
// 서비스 호출은 빈 파라미터의 표준 데이터셋 XML 을 POST 하는 것으로, 실제 화면이 보내는 조회 요청과 같은 형태다.
// 저장·삭제·결재로 보이는 서비스는 scope 검증 단계에서 거부된다.
package xplatform

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/Sangmoo/intrasec/internal/checks"
	"github.com/Sangmoo/intrasec/internal/transport"
	"github.com/Sangmoo/intrasec/pkg/finding"
)

func init() {
	checks.Register(xpCheck{})
}

const TagXPlatform = "xplatform"

type xpCheck struct{}

func (xpCheck) ID() string          { return "XP" }
func (xpCheck) Name() string        { return "XPlatform/MiPlatform 서비스 점검" }
func (xpCheck) Level() checks.Level { return checks.Passive }
func (xpCheck) Tags() []string      { return []string{checks.TagCommon, TagXPlatform} }

// emptyRequest 는 파라미터·데이터셋이 비어 있는 XPlatform 표준 요청이다.
const emptyRequest = `<?xml version="1.0" encoding="UTF-8"?>
<Root xmlns="http://www.tobesoft.com/platform/Dataset" ver="4000">
<Parameters></Parameters>
</Root>`

func (xpCheck) Run(ctx context.Context, t checks.Target, s *checks.Session) ([]finding.Finding, error) {
	if len(t.ServiceURLs) == 0 && !t.HasTag(TagXPlatform) {
		return nil, nil
	}
	var out []finding.Finding
	if f, ok := plaintext(t); ok {
		out = append(out, f)
	}
	for _, u := range t.ServiceURLs {
		f, ok, err := callAnonymous(ctx, s, u.String())
		if err != nil {
			if checks.Abort(err) {
				return out, err
			}
			continue
		}
		if ok {
			out = append(out, f)
		}
	}
	return out, nil
}

// plaintext 는 XP-002: 서비스 URL(없으면 base_url)이 http 인지 판단한다. 요청은 보내지 않는다.
func plaintext(t checks.Target) (finding.Finding, bool) {
	var httpURLs []string
	for _, u := range t.ServiceURLs {
		if u.Scheme == "http" {
			httpURLs = append(httpURLs, u.String())
		}
	}
	if len(t.ServiceURLs) == 0 && t.BaseURL.Scheme == "http" {
		httpURLs = append(httpURLs, t.BaseURL.String())
	}
	if len(httpURLs) == 0 {
		return finding.Finding{}, false
	}
	shown := httpURLs
	if len(shown) > 5 {
		shown = append(shown[:5:5], fmt.Sprintf("외 %d건", len(httpURLs)-5))
	}
	return finding.Finding{
		CheckID: "XP-002", Title: "XPlatform 서비스 통신 평문 전송", Severity: finding.SevHigh, Target: t.BaseURL.String(),
		Evidence: finding.Evidence{Note: "HTTP 서비스 URL: " + strings.Join(shown, ", ")},
		CWE:      []string{"CWE-319"}, OWASP: []string{"A02:2021"}, KISA: []string{"SN"},
		Description: "XPlatform/MiPlatform 클라이언트와 서버 간 데이터셋(계정, 인사·회계 데이터 등)이 HTTP 평문으로 전송되어 같은 네트워크에서 스니핑·변조가 가능합니다.",
		Remediation: "서비스 URL 을 HTTPS 로 전환하고(TypeDefinition 의 Services prefixurl 변경), HTTP 접근은 차단하거나 HTTPS 로 리다이렉트하십시오.",
	}, true
}

var (
	xmlRoot      = regexp.MustCompile(`(?i)<Root[^>]+tobesoft\.com/platform/dataset`)
	xmlErrorCode = regexp.MustCompile(`(?i)<Parameter[^>]+id\s*=\s*["']ErrorCode["'][^>]*>\s*(-?\d+)\s*<`)
	xmlRows      = regexp.MustCompile(`(?i)<Row\b`)
	xmlDatasets  = regexp.MustCompile(`(?i)<Dataset[^>]+id\s*=\s*["']([^"']+)["']`)
	ssvErrorCode = regexp.MustCompile(`ErrorCode(?::\w+)?=(-?\d+)`)
	// SSV 는 레코드 구분자 0x1E, 컬럼 구분자 0x1F 를 쓴다. "Dataset:" 로 데이터셋이 시작된다.
	ssvDatasets = regexp.MustCompile(`Dataset:([\w$]+)`)
)

// parsed 는 XPlatform 응답 분석 결과다.
type parsed struct {
	format    string // "XML" / "SSV"
	errorCode *int
	rows      int
	datasets  []string
}

func parseResponse(b []byte) (parsed, bool) {
	var p parsed
	switch {
	case xmlRoot.Match(b):
		p.format = "XML"
		if m := xmlErrorCode.FindSubmatch(b); m != nil {
			n, _ := strconv.Atoi(string(m[1]))
			p.errorCode = &n
		}
		p.rows = len(xmlRows.FindAll(b, -1))
		for _, m := range xmlDatasets.FindAllSubmatch(b, -1) {
			p.datasets = append(p.datasets, string(m[1]))
		}
	case bytes.HasPrefix(b, []byte("SSV")):
		p.format = "SSV"
		if m := ssvErrorCode.FindSubmatch(b); m != nil {
			n, _ := strconv.Atoi(string(m[1]))
			p.errorCode = &n
		}
		for _, m := range ssvDatasets.FindAllSubmatch(b, -1) {
			p.datasets = append(p.datasets, string(m[1]))
		}
		// 데이터셋 헤더 레코드를 뺀 나머지 레코드 수를 대략적인 행 수로 본다.
		recs := bytes.Count(b, []byte{0x1e})
		p.rows = max(0, recs-2*len(p.datasets)-1)
	default:
		return p, false
	}
	return p, true
}

// callAnonymous 는 세션 없이 서비스를 호출해 정상 응답(ErrorCode 0)인지 확인한다 (XP-001).
func callAnonymous(ctx context.Context, s *checks.Session, rawURL string) (finding.Finding, bool, error) {
	ctx = transport.Anonymous(ctx)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(emptyRequest))
	if err != nil {
		return finding.Finding{}, false, err
	}
	req.Header.Set("Content-Type", "text/xml; charset=UTF-8")
	resp, err := s.HTTP.Do(req) //nolint:bodyclose // transport.ReadBody 가 닫는다
	if err != nil {
		return finding.Finding{}, false, err
	}
	body, err := transport.ReadBody(resp, checks.MaxProbeBody)
	if err != nil {
		return finding.Finding{}, false, err
	}
	if resp.StatusCode != http.StatusOK {
		return finding.Finding{}, false, nil
	}
	p, ok := parseResponse(body)
	if !ok || p.errorCode == nil || *p.errorCode < 0 {
		return finding.Finding{}, false, nil
	}

	note := fmt.Sprintf("세션 없이 %s 응답 ErrorCode=%d", p.format, *p.errorCode)
	sev := finding.SevHigh
	if p.rows > 0 {
		sev = finding.SevCritical
		note += fmt.Sprintf(", 데이터 %d행 반환", p.rows)
	}
	if len(p.datasets) > 0 {
		note += " (데이터셋: " + strings.Join(p.datasets, ", ") + ")"
	}
	note += ". 값은 기록하지 않음. 공개 서비스가 아니라면 인증 누락."
	return finding.Finding{
		CheckID: "XP-001", Title: "XPlatform 서비스 URL 세션 없이 응답", Severity: sev, Target: rawURL,
		Evidence: finding.Evidence{
			Request:  transport.DumpRequest(req) + "\r\n" + emptyRequest,
			Response: transport.DumpResponse(resp, nil, 0),
			Note:     note,
		},
		CWE: []string{"CWE-306", "CWE-862"}, OWASP: []string{"A01:2021", "A07:2021"}, KISA: []string{"IA"},
		Description: "로그인 세션 없이 서비스 URL 을 직접 호출해도 정상 응답(ErrorCode 0)이 반환됩니다. 화면(UI)에서만 로그인을 확인하고 서버 서비스에서 세션을 검증하지 않으면, " +
			"공격자가 서비스 URL 을 직접 호출해 업무 데이터를 조회할 수 있습니다.",
		Remediation: "모든 서비스 컨트롤러(또는 공통 인터셉터·필터)에서 세션과 사용자 권한을 검증하고, 미인증 요청은 ErrorCode 음수와 함께 거부하십시오. " +
			"화면 단위 권한도 서버에서 재확인하십시오.",
	}, true, nil
}
