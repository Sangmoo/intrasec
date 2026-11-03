package common

import (
	"bytes"
	"context"
	"regexp"
	"sort"
	"strings"

	"github.com/Sangmoo/intrasec/internal/checks"
	"github.com/Sangmoo/intrasec/pkg/finding"
)

func init() {
	checks.Register(exposureCheck{})
}

// exposureCheck 는 COMMON-EXP-001~003 (소스 저장소·백업/설정 파일·디렉터리 리스팅 노출)을 판단한다.
// 표식(marker) 기반으로만 판단하고, 비밀값이 있을 수 있는 본문은 근거에 넣지 않는다.
type exposureCheck struct{}

func (exposureCheck) ID() string          { return "COMMON-EXP" }
func (exposureCheck) Name() string        { return "노출 파일·디렉터리 점검" }
func (exposureCheck) Level() checks.Level { return checks.Passive }
func (exposureCheck) Tags() []string      { return []string{checks.TagCommon, "exposure"} }

type exposure struct {
	id, title string
	sev       finding.Severity
	cwe       string
	kisa      string
	desc, fix string
	paths     []string
	match     func(p *checks.Page) (string, bool)
}

var (
	gitHead      = regexp.MustCompile(`^(ref: refs/|[0-9a-f]{40}\s*$)`)
	svnEntries   = regexp.MustCompile(`^\d{1,2}\s`)
	envLine      = regexp.MustCompile(`(?m)^\s*(?:export\s+)?([A-Z][A-Z0-9_]{1,63})\s*=`)
	envSecretKey = regexp.MustCompile(`(?i)(PASS|SECRET|KEY|TOKEN|DB_|DATABASE|AWS_|MAIL_|REDIS_|JWT)`)
	sqlDump      = regexp.MustCompile(`(?i)(-- MySQL dump|-- PostgreSQL database dump|CREATE TABLE\s|INSERT INTO\s)`)
	phpSource    = regexp.MustCompile(`<\?php`)
	dirListing   = regexp.MustCompile(`(?i)(<title>Index of /|<h1>Index of /|Directory Listing For /|\[To Parent Directory\]|<title>Directory listing for /)`)
)

var exposures = []exposure{
	{
		id: "COMMON-EXP-001", title: "소스 저장소(.git/.svn) 노출", sev: finding.SevHigh, cwe: "CWE-527", kisa: "IL",
		desc:  "버전 관리 디렉터리가 웹에서 접근 가능해 전체 소스 코드, 커밋 이력, 하드코딩된 비밀번호·키가 복원될 수 있습니다.",
		fix:   "배포 산출물에서 .git/.svn 을 제외하고, 웹 서버에서 점(.)으로 시작하는 경로 접근을 차단하십시오.",
		paths: []string{"/.git/HEAD", "/.git/config", "/.svn/entries", "/.svn/wc.db"},
		match: func(p *checks.Page) (string, bool) {
			b := bytes.TrimSpace(p.Body)
			switch {
			case strings.HasSuffix(p.URL, "/HEAD") && gitHead.Match(b):
				return ".git/HEAD 형식 확인", true
			case strings.HasSuffix(p.URL, "/config") && bytes.Contains(b, []byte("[core]")):
				return ".git/config 형식 확인", true
			case strings.HasSuffix(p.URL, "/wc.db") && bytes.HasPrefix(p.Body, []byte("SQLite format 3")):
				return ".svn/wc.db (SQLite) 확인", true
			case strings.HasSuffix(p.URL, "/entries") && !p.IsHTML() && svnEntries.Match(b):
				return ".svn/entries 형식 확인", true
			}
			return "", false
		},
	},
	{
		id: "COMMON-EXP-002", title: "환경 설정 파일(.env) 노출", sev: finding.SevCritical, cwe: "CWE-538", kisa: "IL",
		desc:  ".env 파일이 노출되어 DB 접속 정보, API 키, 암호화 키(APP_KEY 등)가 공개됩니다. Laravel APP_KEY 노출은 역직렬화를 통한 원격 코드 실행으로 이어질 수 있습니다.",
		fix:   "웹 루트를 public/ 으로 분리하고 .env 접근을 차단한 뒤, 노출된 모든 비밀번호·키를 즉시 교체하십시오.",
		paths: []string{"/.env", "/.env.local", "/.env.production", "/.env.bak", "/.env.backup", "/.env.old"},
		match: func(p *checks.Page) (string, bool) {
			if p.IsHTML() {
				return "", false
			}
			ms := envLine.FindAllSubmatch(p.Body, -1)
			var secret []string
			for _, m := range ms {
				if envSecretKey.Match(m[1]) {
					secret = append(secret, string(m[1]))
				}
			}
			if len(ms) >= 2 && len(secret) > 0 {
				sort.Strings(secret)
				if len(secret) > 8 {
					secret = append(secret[:8], "...")
				}
				return "비밀값으로 보이는 키 이름(값은 기록하지 않음): " + strings.Join(secret, ", "), true
			}
			return "", false
		},
	},
	{
		id: "COMMON-EXP-002", title: "백업·설정 파일 노출", sev: finding.SevHigh, cwe: "CWE-530", kisa: "IL",
		desc: "백업 또는 설정 파일이 실행되지 않고 원문으로 내려받아져 소스 코드, DB 접속 정보, 내부 구조가 노출됩니다.",
		fix:  "운영 서버에서 백업·임시 파일을 삭제하고, 웹 서버에서 .bak/.old/~/.sql/.zip 등 확장자 접근을 차단하십시오.",
		paths: []string{
			"/index.php.bak", "/index.php~", "/config.php.bak", "/config.php.old", "/config.php~", "/config.inc.php.bak",
			"/wp-config.php.bak", "/wp-config.php~", "/wp-config.php.save", "/wp-config.php.old",
			"/WEB-INF/web.xml", "/web.config.bak",
			"/backup.sql", "/dump.sql", "/db.sql", "/database.sql",
			"/backup.zip", "/www.zip", "/site.zip", "/web.zip",
			"/.DS_Store",
		},
		match: func(p *checks.Page) (string, bool) {
			if p.IsHTML() {
				return "", false
			}
			u := strings.ToLower(p.URL)
			switch {
			case strings.Contains(u, ".php") && phpSource.Match(p.Body):
				return "PHP 소스 원문 확인 (<?php)", true
			case strings.HasSuffix(u, "web.xml") && bytes.Contains(p.Body, []byte("<web-app")):
				return "web.xml 원문 확인", true
			case strings.HasSuffix(u, "web.config.bak") && bytes.Contains(p.Body, []byte("<configuration")):
				return "web.config 원문 확인", true
			case strings.HasSuffix(u, ".sql") && sqlDump.Match(p.Body):
				return "SQL 덤프 형식 확인", true
			case strings.HasSuffix(u, ".zip") && bytes.HasPrefix(p.Body, []byte("PK\x03\x04")):
				return "ZIP 압축 파일 확인", true
			case strings.HasSuffix(u, ".ds_store") && bytes.Contains(p.Body[:min(len(p.Body), 16)], []byte("Bud1")):
				return ".DS_Store 확인 (디렉터리 내 파일 목록 노출)", true
			}
			return "", false
		},
	},
	{
		id: "COMMON-EXP-003", title: "디렉터리 리스팅 활성화", sev: finding.SevMedium, cwe: "CWE-548", kisa: "DI",
		desc:  "디렉터리 인덱싱이 활성화되어 업로드 파일, 백업 파일 등 의도하지 않은 파일 목록이 노출됩니다.",
		fix:   "웹 서버에서 디렉터리 인덱싱을 비활성화하십시오 (Apache: Options -Indexes, nginx: autoindex off, IIS: 디렉터리 검색 사용 안 함).",
		paths: []string{"/", "/upload/", "/uploads/", "/files/", "/file/", "/data/", "/backup/", "/images/", "/tmp/", "/temp/", "/logs/"},
		match: func(p *checks.Page) (string, bool) {
			if m := dirListing.Find(p.Body); m != nil {
				return "디렉터리 목록 표식: " + string(m), true
			}
			return "", false
		},
	},
}

func (exposureCheck) Run(ctx context.Context, t checks.Target, s *checks.Session) ([]finding.Finding, error) {
	notFound := s.NotFoundPage(ctx, t)
	var out []finding.Finding
	for _, e := range exposures {
		for _, path := range e.paths {
			for _, u := range checks.ProbeURLs(t, path) {
				p, err := checks.Fetch(ctx, s, u)
				if err != nil {
					if checks.Abort(err) {
						return out, err
					}
					continue
				}
				if !checks.Found(p, notFound) {
					continue
				}
				note, ok := e.match(p)
				if !ok {
					continue
				}
				ev := p.Evidence
				ev.Note = note
				out = append(out, finding.Finding{
					CheckID: e.id, Title: e.title, Severity: e.sev, Target: p.URL, Evidence: ev,
					CWE: []string{e.cwe}, OWASP: []string{"A05:2021"}, KISA: []string{e.kisa},
					Description: e.desc, Remediation: e.fix,
				})
			}
		}
	}
	return out, nil
}
