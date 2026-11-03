package php

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Sangmoo/intrasec/pkg/finding"
)

// 버전 데이터 기준일: 2026-11-03
// 출처: https://www.php.net/supported-versions , https://www.php.net/ChangeLog-8.php ,
//       https://www.php.net/archive/2026.php (2026-10-21 보안 권고)
// 새 보안 릴리스가 나오면 이 파일의 표를 갱신하고 docs/checks.md 의 기준일도 바꾼다.

// Version 은 응답에서 추출한 PHP 버전이다.
type Version struct {
	Major, Minor, Patch int
	// Suffix 는 "-1ubuntu2.14", "+deb12u1" 같은 배포판 빌드 표시다.
	Suffix string
	Raw    string
}

var versionRe = regexp.MustCompile(`PHP(?:/|\s+Version\s+)(\d+)\.(\d+)\.(\d+)([\w.+~-]*)`)

// ParseVersion 은 "PHP/8.1.2-1ubuntu2.14" 또는 "PHP Version 8.3.6" 형태를 찾는다.
func ParseVersion(s string) (Version, bool) {
	m := versionRe.FindStringSubmatch(s)
	if m == nil {
		return Version{}, false
	}
	a, _ := strconv.Atoi(m[1])
	b, _ := strconv.Atoi(m[2])
	c, _ := strconv.Atoi(m[3])
	return Version{Major: a, Minor: b, Patch: c, Suffix: m[4], Raw: m[0]}, true
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d%s", v.Major, v.Minor, v.Patch, v.Suffix)
}
func (v Version) Branch() string { return fmt.Sprintf("%d.%d", v.Major, v.Minor) }

// Distro 는 배포판 패키지 빌드인지 여부다. 배포판은 버전 번호를 올리지 않고 보안 패치를 백포트한다.
func (v Version) Distro() bool { return v.Suffix != "" }

func (v Version) less(o Version) bool {
	if v.Major != o.Major {
		return v.Major < o.Major
	}
	if v.Minor != o.Minor {
		return v.Minor < o.Minor
	}
	return v.Patch < o.Patch
}

func branchOf(s string) Version {
	v, _ := ParseVersion("PHP/" + s + ".0")
	return v
}

// eolDates 는 브랜치별 공식 지원 종료일(보안 지원 포함)이다. 표에 없는 구 브랜치는 이미 종료.
var eolDates = map[string]time.Time{
	"8.1": time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC),
	"8.2": time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
	"8.3": time.Date(2027, 12, 31, 23, 59, 59, 0, time.UTC),
	"8.4": time.Date(2028, 12, 31, 23, 59, 59, 0, time.UTC),
	"8.5": time.Date(2029, 12, 31, 23, 59, 59, 0, time.UTC),
}

const eolWarnDays = 90

// Env 는 응답에서 추정한 실행 환경이다. Known 이 false 면 해당 값을 알 수 없다는 뜻이다.
type Env struct {
	Windows   bool
	Nginx     bool
	SAPI      string // phpinfo 의 Server API (예: "FPM/FastCGI", "CGI/FastCGI", "Apache 2.0 Handler")
	SAPIKnown bool
	Sources   []string
}

func (e Env) cgi() bool { return strings.HasPrefix(strings.ToUpper(e.SAPI), "CGI") }
func (e Env) fpm() bool { return strings.HasPrefix(strings.ToUpper(e.SAPI), "FPM") }

// vulnRule 은 버전 범위 기반 취약점 규칙이다.
type vulnRule struct {
	checkID string
	title   string
	cves    []string
	cwe     []string
	kev     bool
	// minAffected 미만은 영향 없음.
	minAffected Version
	// fixed 는 브랜치별 최초 수정 패치 번호다. 표의 가장 낮은 브랜치보다 낮은 브랜치는 공식 수정 없음(취약),
	// 가장 높은 브랜치보다 높은 브랜치는 영향 없음으로 본다.
	fixed map[string]int
	// applies 는 환경 조건을 검사해 (적용 여부, 심각도, 비고)를 돌려준다.
	applies     func(Env) (bool, finding.Severity, string)
	description string
	remediation string
}

func (r vulnRule) affected(v Version) (bool, string) {
	if v.less(r.minAffected) {
		return false, ""
	}
	if p, ok := r.fixed[v.Branch()]; ok {
		if v.Patch < p {
			return true, fmt.Sprintf("%s 브랜치 수정 버전 %s.%d 미만", v.Branch(), v.Branch(), p)
		}
		return false, ""
	}
	lo, hi := "", ""
	for b := range r.fixed {
		if lo == "" || branchOf(b).less(branchOf(lo)) {
			lo = b
		}
		if hi == "" || branchOf(hi).less(branchOf(b)) {
			hi = b
		}
	}
	if branchOf(hi).less(branchOf(v.Branch())) {
		return false, ""
	}
	if branchOf(v.Branch()).less(branchOf(lo)) {
		return true, v.Branch() + " 브랜치는 공식 수정 릴리스 없음 (지원 종료)"
	}
	return false, ""
}

var vulnRules = []vulnRule{
	{
		checkID:     "PHP-002",
		title:       "PHP2Shell 원격 코드 실행 취약 버전 (CVE-2026-109618, CVE-2026-109619)",
		cves:        []string{"CVE-2026-109618", "CVE-2026-109619"},
		cwe:         []string{"CWE-416", "CWE-787"},
		kev:         true,
		minAffected: Version{Major: 5, Minor: 4},
		fixed:       map[string]int{"8.2": 35, "8.3": 36, "8.4": 27, "8.5": 12},
		applies: func(e Env) (bool, finding.Severity, string) {
			// PHP-FPM, mod_php, php-cgi, FrankenPHP, LiteSpeed 모두 영향. mod_php 위험이 가장 높다.
			return true, finding.SevCritical, ""
		},
		description: "PHP 런타임의 메모리 손상(CVE-2026-109618) 및 요청 간 잔존 상태로 인한 use-after-free(CVE-2026-109619)로 " +
			"인증 없이 원격 코드 실행이 가능합니다. 2026-10-26 CISA KEV 에 등재되어 실제 공격이 확인되었습니다. " +
			"PHP-FPM, Apache mod_php, php-cgi, FrankenPHP, LiteSpeed 모두 영향을 받으며 mod_php 의 위험이 가장 높습니다.",
		remediation: "PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 이상으로 즉시 업데이트하고 모든 PHP 워커(FPM, Apache)를 재시작하십시오. " +
			"8.1 이하는 공식 릴리스가 없으므로 배포판 보안 패키지(백포트) 적용 여부를 확인하고 지원 버전으로 이전하십시오. " +
			"임시 완화(완전하지 않음): memory_limit 고정, post_max_size 축소(8M), session.upload_progress.enabled=0 을 php.ini 에 설정 후 재시작 " +
			"(ini_set() / .user.ini 로는 불충분).",
	},
	{
		checkID:     "PHP-003",
		title:       "Windows PHP-CGI 인자 주입 취약 버전 (CVE-2024-4577)",
		cves:        []string{"CVE-2024-4577"},
		cwe:         []string{"CWE-78"},
		kev:         true,
		minAffected: Version{Major: 5},
		fixed:       map[string]int{"8.1": 29, "8.2": 20, "8.3": 8},
		applies: func(e Env) (bool, finding.Severity, string) {
			if !e.Windows {
				return false, "", ""
			}
			if e.SAPIKnown {
				if e.cgi() {
					return true, finding.SevCritical, "Server API: " + e.SAPI
				}
				return false, "", ""
			}
			return true, finding.SevHigh, "Windows 환경 확인, CGI 모드 여부는 확인 필요 (XAMPP 기본 설정은 취약)"
		},
		description: "Windows 의 문자 인코딩 변환(Best-Fit)으로 php-cgi 인자 주입이 가능해 인증 없이 원격 명령 실행이 가능합니다. " +
			"CISA KEV 등재 및 랜섬웨어 공격에 사용된 취약점입니다.",
		remediation: "PHP 8.3.8 / 8.2.20 / 8.1.29 이상으로 업데이트하고, PHP-CGI 대신 PHP-FPM 또는 mod_php 를 사용하십시오. " +
			"8.0 이하는 수정 릴리스가 없으므로 지원 버전으로 이전하십시오.",
	},
	{
		checkID:     "PHP-004",
		title:       "nginx + PHP-FPM 원격 코드 실행 취약 버전 (CVE-2019-11043)",
		cves:        []string{"CVE-2019-11043"},
		cwe:         []string{"CWE-787"},
		kev:         true,
		minAffected: Version{Major: 5},
		fixed:       map[string]int{"7.1": 33, "7.2": 24, "7.3": 11},
		applies: func(e Env) (bool, finding.Severity, string) {
			if !e.Nginx || e.Windows {
				return false, "", ""
			}
			if e.SAPIKnown && !e.fpm() {
				return false, "", ""
			}
			return true, finding.SevHigh, "nginx 확인, fastcgi_split_path_info 설정에 따라 영향"
		},
		description: "nginx 의 fastcgi_split_path_info 설정과 PHP-FPM 의 버퍼 언더플로로 원격 코드 실행이 가능합니다. " +
			"CISA KEV 등재 및 랜섬웨어 공격에 사용된 취약점입니다.",
		remediation: "PHP 7.3.11 / 7.2.24 / 7.1.33 이상(가능하면 지원 버전 8.3+)으로 업데이트하고, " +
			"nginx location 에 try_files $fastcgi_script_name =404; 를 추가하십시오.",
	},
}

// evaluate 는 버전과 환경으로 PHP-001~004 판단을 수행한다.
func evaluate(target string, v Version, env Env, now time.Time, ev finding.Evidence) []finding.Finding {
	var out []finding.Finding
	baseNote := "탐지 버전: " + v.String() + " (" + strings.Join(env.Sources, ", ") + ")"
	if v.Distro() {
		baseNote += " — 배포판 빌드이므로 보안 패치가 백포트되었을 수 있음. 패키지 변경 이력 확인 필요"
	}
	baseNote += ". 버전 기반 판단이며 실제 공격 코드는 전송하지 않음."

	// PHP-001 지원 종료
	eol, known := eolDates[v.Branch()]
	if !known && v.less(branchOf("8.1")) {
		eol, known = time.Time{}, true
	}
	if known {
		e := ev
		e.Note = baseNote
		switch {
		case now.After(eol):
			out = append(out, finding.Finding{
				CheckID: "PHP-001", Title: "지원 종료(EOL) PHP 버전 사용", Severity: finding.SevHigh, Target: target, Evidence: e,
				CWE: []string{"CWE-1104"}, OWASP: []string{"A06:2021"},
				Description: fmt.Sprintf("PHP %s 브랜치는 공식 보안 지원이 종료되어 신규 취약점(예: 2026-10 PHP2Shell)에 대한 공식 패치가 제공되지 않습니다.", v.Branch()),
				Remediation: "PHP 8.4 이상 지원 버전으로 이전하십시오. 이전 전까지는 배포판/LTS 업체의 보안 백포트를 적용하십시오.",
			})
		case eol.Sub(now) < eolWarnDays*24*time.Hour:
			out = append(out, finding.Finding{
				CheckID: "PHP-001", Title: "PHP 지원 종료 임박", Severity: finding.SevLow, Target: target, Evidence: e,
				CWE: []string{"CWE-1104"}, OWASP: []string{"A06:2021"},
				Description: fmt.Sprintf("PHP %s 브랜치는 %s 에 보안 지원이 종료됩니다.", v.Branch(), eol.Format("2006-01-02")),
				Remediation: "PHP 8.4 이상 지원 버전으로 이전 계획을 수립하십시오.",
			})
		}
	}

	for _, r := range vulnRules {
		hit, why := r.affected(v)
		if !hit {
			continue
		}
		ok, sev, cond := r.applies(env)
		if !ok {
			continue
		}
		e := ev
		e.Note = baseNote + " 판단 근거: " + why
		if cond != "" {
			e.Note += "; " + cond
		}
		desc := r.description
		if r.kev {
			desc += " (" + strings.Join(r.cves, ", ") + ")"
		}
		out = append(out, finding.Finding{
			CheckID: r.checkID, Title: r.title, Severity: sev, Target: target, Evidence: e,
			CWE: append([]string{}, r.cwe...), OWASP: []string{"A06:2021"},
			Description: desc, Remediation: r.remediation,
		})
	}
	return out
}
