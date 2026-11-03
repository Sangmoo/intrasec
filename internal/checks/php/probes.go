package php

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/Sangmoo/intrasec/internal/checks"
	"github.com/Sangmoo/intrasec/pkg/finding"
)

// probe 는 GET 한 번으로 확인하는 경로 노출 점검이다.
// match 는 내용 기반 표식으로만 판단하며, 반환하는 비고에 본문(비밀값 등)을 넣지 않는다.
type probe struct {
	id, title string
	sev       finding.Severity
	path      string
	cwe       []string
	owasp     []string
	kisa      []string
	desc, fix string
	match     func(p *checks.Page) (string, bool)
}

func contains(b []byte, subs ...string) bool {
	for _, s := range subs {
		if !bytes.Contains(b, []byte(s)) {
			return false
		}
	}
	return true
}

func notHTML(p *checks.Page) bool { return !p.IsHTML() }

var probes = buildProbes()

func buildProbes() []probe {
	var ps []probe
	add := func(base probe, paths ...string) {
		for _, p := range paths {
			b := base
			b.path = p
			ps = append(ps, b)
		}
	}

	add(probe{
		id: "PHP-010", title: "phpinfo() 페이지 노출", sev: finding.SevMedium,
		cwe: []string{"CWE-200"}, owasp: []string{"A05:2021"}, kisa: []string{"IL"},
		desc: "phpinfo() 출력이 노출되어 PHP 정확한 버전, 설치 경로, 확장 모듈, 환경변수(비밀값 포함 가능), 보안 설정이 공개됩니다. " +
			"공격자가 취약 버전·설정을 선별하는 데 직접 이용됩니다.",
		fix: "phpinfo() 를 호출하는 테스트 파일을 운영 서버에서 삭제하십시오.",
		match: func(p *checks.Page) (string, bool) {
			if !contains(p.Body, "phpinfo()") || !bytes.Contains(p.Body, []byte("PHP Version")) {
				return "", false
			}
			info := parsePHPInfo(p.Body)
			return info.note(), true
		},
	}, "/phpinfo.php", "/info.php", "/php_info.php", "/test.php", "/i.php", "/pi.php", "/php.php", "/phpinfo")

	add(probe{
		id: "PHP-012", title: "DB 관리 도구(phpMyAdmin) 노출", sev: finding.SevHigh,
		cwe: []string{"CWE-306"}, owasp: []string{"A05:2021", "A07:2021"}, kisa: []string{"AE"},
		desc: "phpMyAdmin 로그인 화면이 노출되어 계정 대입 공격 및 phpMyAdmin 자체 취약점 공격 대상이 됩니다.",
		fix:  "운영 서버에서 phpMyAdmin 을 제거하거나, 관리자 IP 로만 접근을 제한하십시오.",
		match: func(p *checks.Page) (string, bool) {
			if contains(p.Body, "phpMyAdmin") && (contains(p.Body, "pma_username") || contains(p.Body, "pma_password") || contains(p.Body, "PMA_")) {
				return "phpMyAdmin 로그인 폼 확인", true
			}
			return "", false
		},
	}, "/phpmyadmin/", "/phpMyAdmin/", "/pma/", "/myadmin/", "/dbadmin/", "/mysql/")

	add(probe{
		id: "PHP-012", title: "DB 관리 도구(Adminer) 노출", sev: finding.SevHigh,
		cwe: []string{"CWE-306"}, owasp: []string{"A05:2021", "A07:2021"}, kisa: []string{"AE"},
		desc: "Adminer 단일 파일 DB 관리 도구가 노출되어 계정 대입 공격 및 SSRF·파일 읽기 취약점 공격 대상이 됩니다.",
		fix:  "운영 서버에서 adminer.php 를 삭제하십시오.",
		match: func(p *checks.Page) (string, bool) {
			if contains(p.Body, "Adminer") && (contains(p.Body, "auth[driver]") || contains(p.Body, "adminer.org")) {
				return "Adminer 로그인 폼 확인", true
			}
			return "", false
		},
	}, "/adminer.php", "/adminer/", "/adminer/adminer.php")

	add(probe{
		id: "PHP-013", title: "Laravel Ignition 디버그 엔드포인트 노출", sev: finding.SevCritical,
		cwe: []string{"CWE-489"}, owasp: []string{"A05:2021"}, kisa: []string{"IL"},
		desc: "운영 환경에서 Laravel 디버그 모드(Ignition)가 활성화되어 있습니다. 구버전 Ignition 은 인증 없는 원격 코드 실행(CVE-2021-3129)이 가능하며, " +
			"디버그 화면을 통해 .env 비밀값과 소스 코드가 노출됩니다.",
		fix: ".env 에서 APP_DEBUG=false 로 설정하고, facade/ignition 을 최신 버전으로 업데이트하거나 운영 의존성에서 제외(--no-dev)하십시오.",
		match: func(p *checks.Page) (string, bool) {
			if contains(p.Body, `"can_execute_commands"`) {
				note := "Ignition health-check 응답 확인"
				if contains(p.Body, `"can_execute_commands":true`) {
					note += " (can_execute_commands: true — 명령 실행 기능 활성)"
				}
				return note, true
			}
			return "", false
		},
	}, "/_ignition/health-check")

	add(probe{
		id: "PHP-013", title: "Symfony 프로파일러 노출", sev: finding.SevHigh,
		cwe: []string{"CWE-489"}, owasp: []string{"A05:2021"}, kisa: []string{"IL"},
		desc: "Symfony 웹 프로파일러가 노출되어 요청 기록, 세션, 환경 변수, DB 쿼리가 조회될 수 있습니다.",
		fix:  "APP_ENV=prod 로 운영하고 운영 배포에서 symfony/web-profiler-bundle 을 제외하십시오.",
		match: func(p *checks.Page) (string, bool) {
			if contains(p.Body, "Symfony Profiler") {
				return "Symfony Profiler 화면 확인", true
			}
			return "", false
		},
	}, "/_profiler/", "/app_dev.php/_profiler/")

	add(probe{
		id: "PHP-013", title: "Laravel Telescope / Horizon 대시보드 노출", sev: finding.SevHigh,
		cwe: []string{"CWE-306"}, owasp: []string{"A01:2021"}, kisa: []string{"AE"},
		desc: "Laravel Telescope/Horizon 대시보드가 인증 없이 노출되어 요청·예외·쿼리·작업 내역과 민감정보가 조회될 수 있습니다.",
		fix:  "운영 환경에서 비활성화하거나 gate 설정으로 관리자만 접근하도록 제한하십시오.",
		match: func(p *checks.Page) (string, bool) {
			switch {
			case contains(p.Body, "window.Telescope"):
				return "Telescope 대시보드 확인", true
			case contains(p.Body, "window.Horizon"):
				return "Horizon 대시보드 확인", true
			}
			return "", false
		},
	}, "/telescope", "/horizon")

	add(probe{
		id: "PHP-014", title: "PHPUnit eval-stdin.php 노출 (CVE-2017-9841)", sev: finding.SevCritical,
		cwe: []string{"CWE-94"}, owasp: []string{"A06:2021", "A05:2021"},
		desc: "vendor 디렉터리의 PHPUnit eval-stdin.php 가 웹에서 실행 가능한 상태입니다. 요청 본문의 PHP 코드를 그대로 실행하는 원격 코드 실행 취약점(CVE-2017-9841, CISA KEV)으로 " +
			"지금도 대량 스캔·웹셸 설치에 사용됩니다. 본 점검은 GET 으로 파일 존재(빈 200 응답)만 확인했습니다.",
		fix: "vendor 디렉터리를 웹 루트 밖으로 옮기고, 운영 배포 시 composer install --no-dev 로 PHPUnit 을 제외하십시오.",
		match: func(p *checks.Page) (string, bool) {
			if len(bytes.TrimSpace(p.Body)) == 0 && !p.IsHTML() {
				return "200 응답, 빈 본문 (PHP 파일 실행됨)", true
			}
			return "", false
		},
	}, "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/vendor/phpunit/phpunit/Util/PHP/eval-stdin.php")

	add(probe{
		id: "PHP-015", title: "PHP-FPM 상태 페이지 노출", sev: finding.SevMedium,
		cwe: []string{"CWE-200"}, owasp: []string{"A05:2021"}, kisa: []string{"IL"},
		desc: "PHP-FPM status 페이지가 노출되어 처리 중인 요청 URI, 클라이언트 정보, 프로세스 상태가 공개됩니다.",
		fix:  "pm.status_path 를 비활성화하거나 웹 서버에서 내부 IP 로만 접근을 제한하십시오.",
		match: func(p *checks.Page) (string, bool) {
			if contains(p.Body, "pool:") && contains(p.Body, "process manager:") {
				return "FPM status 출력 확인", true
			}
			return "", false
		},
	}, "/status", "/fpm-status", "/php-fpm-status", "/status.php")

	add(probe{
		id: "PHP-016", title: "Composer 의존성 정보 노출", sev: finding.SevLow,
		cwe: []string{"CWE-200"}, owasp: []string{"A05:2021", "A06:2021"}, kisa: []string{"IL"},
		desc: "composer 파일이 노출되어 사용 중인 라이브러리와 정확한 버전이 공개되며, 알려진 취약 라이브러리 선별에 이용됩니다.",
		fix:  "웹 루트를 public/ 디렉터리로 분리하고 composer.json, composer.lock, vendor/ 접근을 차단하십시오.",
		match: func(p *checks.Page) (string, bool) {
			if !notHTML(p) {
				return "", false
			}
			switch {
			case contains(p.Body, `"content-hash"`, `"packages"`):
				return "composer.lock 형식 확인", true
			case contains(p.Body, `"packages"`) && strings.Contains(p.URL, "installed.json"):
				return "vendor/composer/installed.json 형식 확인", true
			case bytes.HasPrefix(bytes.TrimSpace(p.Body), []byte("{")) && contains(p.Body, `"require"`):
				return "composer.json 형식 확인", true
			}
			return "", false
		},
	}, "/composer.json", "/composer.lock", "/vendor/composer/installed.json")

	add(probe{
		id: "PHP-017", title: "PHP 설정 파일 노출 (.user.ini / php.ini)", sev: finding.SevMedium,
		cwe: []string{"CWE-538"}, owasp: []string{"A05:2021"}, kisa: []string{"IL"},
		desc: "PHP 설정 파일이 노출되어 auto_prepend_file, open_basedir 등 보안 설정과 서버 경로가 공개됩니다.",
		fix:  "웹 서버에서 .user.ini, php.ini 및 점(.)으로 시작하는 파일 접근을 차단하십시오.",
		match: func(p *checks.Page) (string, bool) {
			if notHTML(p) && iniDirective.Match(p.Body) {
				return "PHP ini 지시어 확인", true
			}
			return "", false
		},
	}, "/.user.ini", "/php.ini")

	return ps
}

var iniDirective = regexp.MustCompile(`(?m)^\s*(auto_prepend_file|auto_append_file|open_basedir|display_errors|upload_max_filesize|memory_limit|disable_functions|allow_url_include)\s*=`)

// PHP 에러 메시지 패턴 (display_errors=On).
var phpErrorRe = regexp.MustCompile(`(?i)(?:<b>)?(?:PHP )?(Warning|Fatal error|Parse error|Notice|Deprecated|Uncaught \w+)(?:</b>)?:\s.{0,300}?\sin\s(?:<b>)?((?:/|[A-Z]:\\)[^<\s]+\.php)(?:</b>)?\son\sline\s(?:<b>)?\d+`)

// detectErrorDisclosure 는 이미 받은 응답에서 PHP 에러 메시지 노출을 찾는다 (추가 요청 없음).
func detectErrorDisclosure(p *checks.Page) (finding.Finding, bool) {
	m := phpErrorRe.FindSubmatch(p.Body)
	if m == nil {
		return finding.Finding{}, false
	}
	ev := p.Evidence
	ev.Note = "PHP " + string(m[1]) + " 메시지에 서버 파일 경로 노출: " + string(m[2])
	return finding.Finding{
		CheckID: "PHP-011", Title: "PHP 에러 메시지 노출 (display_errors)", Severity: finding.SevMedium, Target: p.URL, Evidence: ev,
		CWE: []string{"CWE-209"}, OWASP: []string{"A05:2021"}, KISA: []string{"IL"},
		Description: "PHP 에러 메시지가 사용자에게 그대로 출력되어 서버 내부 경로와 코드 구조가 노출됩니다. SQL 인젝션 등 추가 공격의 단서가 됩니다.",
		Remediation: "php.ini 에서 display_errors=Off, log_errors=On 으로 설정하고 사용자에게는 일반 오류 페이지를 보여주십시오.",
	}, true
}

// phpInfo 는 phpinfo() 출력에서 뽑은 정보다.
type phpInfo struct {
	version *Version
	sapi    string
	windows bool
	risky   []string
}

var (
	infoVersionRe = regexp.MustCompile(`PHP Version\s+(\d+\.\d+\.\d+[\w.+~-]*)`)
	infoSAPIRe    = regexp.MustCompile(`Server API\s*</td>\s*<td[^>]*>\s*([^<]+?)\s*<`)
	infoSystemRe  = regexp.MustCompile(`System\s*</td>\s*<td[^>]*>\s*([^<]+?)\s*<`)
	infoRowRe     = regexp.MustCompile(`<td class="e">\s*([a-z0-9_.]+)\s*</td>\s*<td class="v">\s*([^<]*?)\s*</td>`)
)

// riskySettings 는 값이 위험할 때 비고에 표시할 설정이다.
var riskySettings = map[string]func(string) bool{
	"allow_url_include":               func(v string) bool { return strings.EqualFold(v, "On") },
	"display_errors":                  func(v string) bool { return strings.EqualFold(v, "On") || v == "1" || strings.EqualFold(v, "STDOUT") },
	"expose_php":                      func(v string) bool { return strings.EqualFold(v, "On") },
	"session.upload_progress.enabled": func(v string) bool { return strings.EqualFold(v, "On") }, // PHP2Shell(CVE-2026-109619) 완화 대상
	"memory_limit":                    func(v string) bool { return v == "-1" },
	"session.cookie_httponly":         func(v string) bool { return strings.EqualFold(v, "Off") || v == "0" || v == "" || v == "no value" },
	"session.use_strict_mode":         func(v string) bool { return strings.EqualFold(v, "Off") || v == "0" },
}

func parsePHPInfo(b []byte) phpInfo {
	var info phpInfo
	if m := infoVersionRe.FindSubmatch(b); m != nil {
		if v, ok := ParseVersion("PHP/" + string(m[1])); ok {
			info.version = &v
		}
	}
	if m := infoSAPIRe.FindSubmatch(b); m != nil {
		info.sapi = string(m[1])
	}
	if m := infoSystemRe.FindSubmatch(b); m != nil && bytes.Contains(bytes.ToLower(m[1]), []byte("windows")) {
		info.windows = true
	}
	seen := map[string]bool{}
	for _, m := range infoRowRe.FindAllSubmatch(b, -1) {
		k, v := string(m[1]), string(m[2])
		if bad, ok := riskySettings[k]; ok && !seen[k] && bad(v) {
			seen[k] = true
			info.risky = append(info.risky, k+"="+v)
		}
	}
	return info
}

func (i phpInfo) note() string {
	var parts []string
	if i.version != nil {
		parts = append(parts, "PHP "+i.version.String())
	}
	if i.sapi != "" {
		parts = append(parts, "Server API: "+i.sapi)
	}
	if i.windows {
		parts = append(parts, "Windows")
	}
	if len(i.risky) > 0 {
		parts = append(parts, "주의 설정: "+strings.Join(i.risky, ", "))
	}
	return strings.Join(parts, " / ")
}
