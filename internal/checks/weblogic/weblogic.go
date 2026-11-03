// Package weblogic 은 Oracle WebLogic Server 점검을 담는다. 모든 요청은 GET 또는 프로토콜 핸드셰이크이며
// 공격 코드(역직렬화 페이로드 등)는 보내지 않는다.
//
//   - WLS-001 관리 콘솔(/console, /em) 접근 가능
//   - WLS-002 버전 노출
//   - WLS-003 T3/IIOP 프로토콜 노출
//   - WLS-004 알려진 취약 컴포넌트 노출 (wls-wsat, _async, uddiexplorer)
package weblogic

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Sangmoo/intrasec/internal/checks"
	"github.com/Sangmoo/intrasec/pkg/finding"
)

func init() {
	checks.Register(wlsCheck{})
}

const TagWebLogic = "weblogic"

type wlsCheck struct{}

func (wlsCheck) ID() string          { return "WLS" }
func (wlsCheck) Name() string        { return "WebLogic 점검" }
func (wlsCheck) Level() checks.Level { return checks.Passive }

// Tags 에 common 을 넣어 모든 대상에서 WebLogic 흔적을 확인한다.
// 흔적이 없고 대상 태그에 weblogic 이 없으면 나머지 요청은 보내지 않는다.
func (wlsCheck) Tags() []string { return []string{checks.TagCommon, TagWebLogic} }

var (
	serverVersionRe  = regexp.MustCompile(`(?i)WebLogic(?:\s+Server)?[ /:]*(\d+(?:\.\d+){1,4})`)
	consoleVersionRe = regexp.MustCompile(`(?i)WebLogic Server Version:\s*(\d+(?:\.\d+){1,4})`)
	t3HelloRe        = regexp.MustCompile(`^HELO:(\d+(?:\.\d+){1,4})?`)
)

// fingerprint 는 기본 페이지·404 페이지에서 WebLogic 흔적을 찾는다.
func fingerprint(pages ...*checks.Page) bool {
	for _, p := range pages {
		if p == nil {
			continue
		}
		if strings.Contains(strings.ToLower(p.Header.Get("Server")), "weblogic") ||
			bytes.Contains(p.Body, []byte("From RFC 2068 Hypertext Transfer Protocol")) ||
			bytes.Contains(p.Body, []byte("WebLogic Server")) {
			return true
		}
	}
	return false
}

// endpoint 는 점검할 호스트:포트와 그 포트에서 동작하는 HTTP 스킴이다.
type endpoint struct {
	host   string
	port   int
	scheme string // "" 이면 HTTP 미확인
}

func (e endpoint) url(path string) string {
	return (&url.URL{Scheme: e.scheme, Host: net.JoinHostPort(e.host, strconv.Itoa(e.port)), Path: path}).String()
}

func endpoints(t checks.Target) []endpoint {
	host := t.BaseURL.Hostname()
	basePort, _ := strconv.Atoi(t.BaseURL.Port())
	if basePort == 0 {
		basePort = map[string]int{"https": 443, "http": 80}[t.BaseURL.Scheme]
	}
	seen := map[int]bool{basePort: true}
	out := []endpoint{{host, basePort, t.BaseURL.Scheme}}
	for _, p := range t.Ports {
		if !seen[p] {
			seen[p] = true
			out = append(out, endpoint{host: host, port: p})
		}
	}
	return out
}

// resolveScheme 는 추가 포트에서 http / https 중 응답하는 스킴을 찾는다.
func resolveScheme(ctx context.Context, s *checks.Session, e *endpoint) error {
	if e.scheme != "" {
		return nil
	}
	for _, sc := range []string{"http", "https"} {
		e.scheme = sc
		p, err := checks.Fetch(ctx, s, e.url("/"))
		if err == nil && !bytes.Contains(p.Body, []byte("requires TLS")) && p.Status != 400 {
			return nil
		}
		if checks.Abort(err) {
			return err
		}
	}
	e.scheme = ""
	return nil
}

type versionSeen struct {
	version, source string
}

func (wlsCheck) Run(ctx context.Context, t checks.Target, s *checks.Session) ([]finding.Finding, error) {
	base, err := checks.Fetch(ctx, s, t.BaseURL.String())
	if err != nil {
		return nil, err
	}
	notFound := s.NotFoundPage(ctx, t)
	if !t.HasTag(TagWebLogic) && !fingerprint(base, notFound) {
		return nil, nil
	}

	var out []finding.Finding
	var versions []versionSeen
	for _, p := range []*checks.Page{base, notFound} {
		if m := serverVersionRe.FindStringSubmatch(p.Header.Get("Server")); m != nil {
			versions = append(versions, versionSeen{m[1], "Server 헤더"})
		}
	}

	for _, e := range endpoints(t) {
		if err := resolveScheme(ctx, s, &e); err != nil {
			return out, err
		}
		if e.scheme != "" {
			fs, vs, err := probeHTTP(ctx, s, e, notFound)
			out = append(out, fs...)
			versions = append(versions, vs...)
			if err != nil {
				return out, err
			}
		}
		fs, vs, err := probeProtocols(ctx, s, e)
		out = append(out, fs...)
		versions = append(versions, vs...)
		if err != nil {
			return out, err
		}
	}

	if f, ok := versionFinding(t.BaseURL.String(), versions, base.Evidence); ok {
		out = append(out, f)
	}
	return out, nil
}

type probe struct {
	id, title string
	sev       finding.Severity
	paths     []string
	cwe       []string
	desc, fix string
	match     func(p *checks.Page) (note string, version string, ok bool)
}

var httpProbes = []probe{
	{
		id: "WLS-001", title: "WebLogic 관리 콘솔 접근 가능", sev: finding.SevHigh,
		paths: []string{"/console/login/LoginForm.jsp", "/console/"},
		cwe:   []string{"CWE-306", "CWE-1220"},
		desc: "WebLogic 관리 콘솔이 점검 PC 에서 접근 가능합니다. 관리자 계정 대입 공격 대상이 되며, " +
			"콘솔 인증 우회 원격 코드 실행(CVE-2020-14882/14883, CISA KEV) 등 콘솔 경유 공격에 노출됩니다.",
		fix: "관리 콘솔을 별도 관리 포트·관리망으로 분리하거나(Administration Port), 운영 도메인에서 콘솔을 비활성화하십시오 " +
			"(Domain > Configuration > General > Advanced > Console Enabled 해제). 최신 CPU 패치를 적용하십시오.",
		match: func(p *checks.Page) (string, string, bool) {
			loginForm := bytes.Contains(p.Body, []byte("j_username")) && bytes.Contains(p.Body, []byte("WebLogic"))
			if !loginForm && !bytes.Contains(p.Body, []byte("WebLogic Server Administration Console")) {
				return "", "", false
			}
			v := ""
			if m := consoleVersionRe.FindSubmatch(p.Body); m != nil {
				v = string(m[1])
			}
			return "관리 콘솔 로그인 화면 확인", v, true
		},
	},
	{
		id: "WLS-001", title: "Fusion Middleware Control(EM) 콘솔 접근 가능", sev: finding.SevHigh,
		paths: []string{"/em/"},
		cwe:   []string{"CWE-306"},
		desc:  "Oracle Enterprise Manager Fusion Middleware Control 콘솔이 접근 가능하여 관리자 계정 대입 공격 대상이 됩니다.",
		fix:   "EM 콘솔을 관리망에서만 접근하도록 제한하거나 운영 환경에서 배포를 해제하십시오.",
		match: func(p *checks.Page) (string, string, bool) {
			if bytes.Contains(p.Body, []byte("Enterprise Manager")) && bytes.Contains(p.Body, []byte("Fusion Middleware")) {
				return "EM 로그인 화면 확인", "", true
			}
			return "", "", false
		},
	},
	{
		id: "WLS-004", title: "WebLogic wls-wsat 컴포넌트 노출 (CVE-2017-10271 공격 경로)", sev: finding.SevHigh,
		paths: []string{"/wls-wsat/CoordinatorPortType"},
		cwe:   []string{"CWE-502"},
		desc:  "wls-wsat 웹 서비스가 노출되어 있습니다. 미패치 시 XMLDecoder 역직렬화로 인증 없는 원격 코드 실행(CVE-2017-10271, CISA KEV)이 가능하며 채굴·랜섬웨어 공격에 대량 악용되었습니다.",
		fix:   "최신 CPU 를 적용하고, 사용하지 않으면 wls-wsat.war 를 삭제하거나 /wls-wsat/* 경로 접근을 차단하십시오.",
		match: func(p *checks.Page) (string, string, bool) {
			if bytes.Contains(p.Body, []byte("CoordinatorPortType")) || bytes.Contains(p.Body, []byte("Web Services")) && bytes.Contains(p.Body, []byte("wsat")) {
				return "wls-wsat 서비스 페이지 확인", "", true
			}
			return "", "", false
		},
	},
	{
		id: "WLS-004", title: "WebLogic _async 컴포넌트 노출 (CVE-2019-2725 공격 경로)", sev: finding.SevHigh,
		paths: []string{"/_async/AsyncResponseService"},
		cwe:   []string{"CWE-502"},
		desc:  "_async(bea_wls9_async_response) 웹 서비스가 노출되어 있습니다. 미패치 시 인증 없는 원격 코드 실행(CVE-2019-2725, CISA KEV)이 가능합니다.",
		fix:   "최신 CPU 를 적용하고, 사용하지 않으면 bea_wls9_async_response.war 를 삭제하거나 /_async/* 경로 접근을 차단하십시오.",
		match: func(p *checks.Page) (string, string, bool) {
			if bytes.Contains(p.Body, []byte("AsyncResponseService")) {
				return "_async 서비스 페이지 확인", "", true
			}
			return "", "", false
		},
	},
	{
		id: "WLS-004", title: "WebLogic UDDI Explorer 노출 (CVE-2014-4210 SSRF)", sev: finding.SevMedium,
		paths: []string{"/uddiexplorer/"},
		cwe:   []string{"CWE-918"},
		desc:  "UDDI Explorer 가 노출되어 미패치 시 서버를 경유한 내부망 요청 위조(SSRF, CVE-2014-4210)가 가능합니다.",
		fix:   "uddiexplorer.war 배포를 해제하고 최신 CPU 를 적용하십시오.",
		match: func(p *checks.Page) (string, string, bool) {
			if bytes.Contains(p.Body, []byte("UDDI Explorer")) {
				return "UDDI Explorer 화면 확인", "", true
			}
			return "", "", false
		},
	},
}

func probeHTTP(ctx context.Context, s *checks.Session, e endpoint, notFound *checks.Page) ([]finding.Finding, []versionSeen, error) {
	var out []finding.Finding
	var vs []versionSeen
	for _, pr := range httpProbes {
		for _, path := range pr.paths {
			p, err := checks.Fetch(ctx, s, e.url(path))
			if err != nil {
				if checks.Abort(err) {
					return out, vs, err
				}
				continue
			}
			if !checks.Found(p, notFound) {
				continue
			}
			note, v, ok := pr.match(p)
			if !ok {
				continue
			}
			if v != "" {
				vs = append(vs, versionSeen{v, "관리 콘솔 화면"})
			}
			ev := p.Evidence
			ev.Note = note
			out = append(out, finding.Finding{
				CheckID: pr.id, Title: pr.title, Severity: pr.sev, Target: p.URL, Evidence: ev,
				CWE: pr.cwe, OWASP: []string{"A05:2021"}, KISA: []string{"AE"},
				Description: pr.desc, Remediation: pr.fix,
			})
			break // 같은 항목의 다른 경로는 확인하지 않는다
		}
	}
	return out, vs, nil
}

// t3Hello 는 표준 T3 프로토콜 인사 메시지다 (nmap weblogic-t3-info 와 동일, 페이로드 없음).
var t3Hello = []byte("t3 12.2.1\nAS:255\nHL:19\nMS:10000000\n\n")

// giopLocateRequest 는 객체 키 "NameService" 에 대한 GIOP 1.2 LocateRequest 다 (조회만, 호출 없음).
func giopLocateRequest() []byte {
	key := []byte("NameService")
	var body bytes.Buffer
	_ = binary.Write(&body, binary.BigEndian, uint32(1))        // request_id
	_ = binary.Write(&body, binary.BigEndian, uint16(0))        // KeyAddr
	body.Write([]byte{0, 0})                                    // 4바이트 정렬
	_ = binary.Write(&body, binary.BigEndian, uint32(len(key))) //nolint:gosec // 고정 길이 object_key
	body.Write(key)
	h := []byte{'G', 'I', 'O', 'P', 1, 2, 0, 3}
	h = binary.BigEndian.AppendUint32(h, uint32(body.Len())) //nolint:gosec // 고정 길이
	return append(h, body.Bytes()...)
}

func probeProtocols(ctx context.Context, s *checks.Session, e endpoint) ([]finding.Finding, []versionSeen, error) {
	var exposed []string
	var vs []versionSeen
	resp, err := s.HTTP.TCPExchange(ctx, e.host, e.port, t3Hello, 256)
	if checks.Abort(err) {
		return nil, nil, err
	}
	if m := t3HelloRe.FindSubmatch(resp); err == nil && m != nil {
		note := "T3 (HELO 응답)"
		if len(m[1]) > 0 {
			vs = append(vs, versionSeen{string(m[1]), "T3 HELO 응답"})
			note = "T3 (HELO:" + string(m[1]) + ")"
		}
		exposed = append(exposed, note)
	}
	// T3 에 일반 HTTP 오류로 답한 포트는 WebLogic 다중 프로토콜 포트가 아니므로 IIOP 는 생략한다.
	if !bytes.HasPrefix(resp, []byte("HTTP/")) {
		resp, err = s.HTTP.TCPExchange(ctx, e.host, e.port, giopLocateRequest(), 64)
		if checks.Abort(err) {
			return nil, vs, err
		}
		if err == nil && bytes.HasPrefix(resp, []byte("GIOP")) {
			exposed = append(exposed, "IIOP (GIOP 응답)")
		}
	}
	if len(exposed) == 0 {
		return nil, vs, nil
	}
	target := fmt.Sprintf("tcp://%s", net.JoinHostPort(e.host, strconv.Itoa(e.port)))
	return []finding.Finding{{
		CheckID: "WLS-003", Title: "WebLogic T3/IIOP 프로토콜 노출", Severity: finding.SevHigh, Target: target,
		Evidence: finding.Evidence{Request: "T3 인사 메시지 / GIOP LocateRequest(NameService) → " + target, Note: "응답 확인: " + strings.Join(exposed, ", ")},
		CWE:      []string{"CWE-502"}, OWASP: []string{"A08:2021", "A05:2021"},
		Description: "T3/IIOP 프로토콜이 점검 PC 에서 접근 가능합니다. 이 프로토콜은 Java 역직렬화 원격 코드 실행 취약점" +
			"(CVE-2018-2628, CVE-2020-2551, CVE-2023-21839 등)의 주요 공격 경로로, 미패치 시 인증 없이 서버가 장악될 수 있습니다.",
		Remediation: "연결 필터(weblogic.security.net.ConnectionFilterImpl)로 T3/T3S/IIOP 를 관리 서버 간 통신 IP 로만 허용하고, " +
			"IIOP 를 사용하지 않으면 비활성화(Protocols > IIOP > Enable IIOP 해제)하며 최신 CPU 를 적용하십시오.",
	}}, vs, nil
}

func versionFinding(target string, vs []versionSeen, ev finding.Evidence) (finding.Finding, bool) {
	if len(vs) == 0 {
		return finding.Finding{}, false
	}
	bySrc := map[string]string{}
	for _, v := range vs {
		bySrc[v.source] = v.version
	}
	var parts []string
	old := false
	for src, v := range bySrc {
		parts = append(parts, v+" ("+src+")")
		if strings.HasPrefix(v, "10.") || strings.HasPrefix(v, "12.1.") || strings.HasPrefix(v, "9.") {
			old = true
		}
	}
	sort.Strings(parts)
	desc := "WebLogic 버전 정보가 노출되어 공격자가 해당 버전의 알려진 취약점을 선별하는 데 이용할 수 있습니다."
	if old {
		desc += " 탐지된 버전은 10.3.x / 12.1.x 이하 구 계열로, Oracle 지원 종료로 최신 CPU 가 제공되지 않을 수 있으므로 지원 상태를 확인하십시오."
	}
	ev.Note = "탐지 버전: " + strings.Join(parts, ", ")
	return finding.Finding{
		CheckID: "WLS-002", Title: "WebLogic 버전 노출", Severity: finding.SevLow, Target: target, Evidence: ev,
		CWE: []string{"CWE-200"}, OWASP: []string{"A05:2021", "A06:2021"}, KISA: []string{"IL"},
		Description: desc,
		Remediation: "Server 헤더 전송을 끄고(Server > Configuration > HTTP > Send Server Header 해제), T3 접근을 제한하며, " +
			"분기별 Oracle CPU 를 적용하고 지원되는 버전(14.1.x 등)으로 이전하십시오.",
	}, true
}
