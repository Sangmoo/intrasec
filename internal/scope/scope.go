package scope

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	ErrOutOfWindow = errors.New("점검 허용 시간대가 아님")
	ErrHost        = errors.New("허용되지 않은 호스트")
	ErrPort        = errors.New("허용되지 않은 포트")
	ErrIP          = errors.New("허용 대역 밖의 IP")
	ErrExcluded    = errors.New("제외 경로")
)

// DefaultExcludePaths 는 scope.yaml 과 무관하게 항상 크롤링/요청에서 제외되는 위험 URL 패턴이다.
var DefaultExcludePaths = []string{
	"*logout*",
	"*logoff*",
	"*signout*",
	"*/delete*",
	"*/remove*",
	"*/approval/submit*",
	"*/approve*",
}

// Scope 는 검증된 Config 로부터 만든 허용 판단기다.
type Scope struct {
	cfg      *Config
	ports    map[string]map[int]bool // host -> 허용 포트
	nets     []netip.Prefix
	excludes []*regexp.Regexp
	resolver *net.Resolver
}

func New(cfg *Config) (*Scope, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	s := &Scope{cfg: cfg, ports: map[string]map[int]bool{}, resolver: net.DefaultResolver}
	for _, t := range cfg.Targets {
		u, _ := url.Parse(t.BaseURL)
		host := strings.ToLower(u.Hostname())
		if s.ports[host] == nil {
			s.ports[host] = map[int]bool{}
		}
		s.ports[host][portOf(u)] = true
		for _, p := range t.Ports {
			s.ports[host][p] = true
		}
	}
	for _, c := range cfg.Allow.CIDRs {
		p, _ := netip.ParsePrefix(c)
		s.nets = append(s.nets, p.Masked())
	}
	for _, p := range append(append([]string{}, DefaultExcludePaths...), cfg.ExcludePaths...) {
		s.excludes = append(s.excludes, compileGlob(p))
	}
	return s, nil
}

func (s *Scope) Config() *Config { return s.cfg }

// CheckWindow 는 now 가 점검 시간대 안인지 확인한다.
func (s *Scope) CheckWindow(now time.Time) error {
	w := s.cfg.Engagement.Window
	if now.Before(w.Start) || !now.Before(w.End) {
		return fmt.Errorf("%w: 현재 %s, 허용 %s ~ %s", ErrOutOfWindow,
			now.Format(time.RFC3339), w.Start.Format(time.RFC3339), w.End.Format(time.RFC3339))
	}
	return nil
}

// AllowURL 은 호스트·포트·경로 기준 허용 여부를 판단한다 (DNS 해석 없음).
// 실제 연결 IP 검사는 AllowIP 로 transport 의 dialer 에서 수행한다.
func (s *Scope) AllowURL(u *url.URL) error {
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: 지원하지 않는 스킴 %q", ErrHost, u.Scheme)
	}
	host := strings.ToLower(u.Hostname())
	ports, ok := s.ports[host]
	if !ok {
		return fmt.Errorf("%w: %s", ErrHost, host)
	}
	if p := portOf(u); !ports[p] {
		return fmt.Errorf("%w: %s:%d", ErrPort, host, p)
	}
	if s.Excluded(u.EscapedPath()) {
		return fmt.Errorf("%w: %s", ErrExcluded, u.Path)
	}
	return nil
}

// AllowIP 는 IP 가 allow.cidrs 안에 있는지 확인한다.
func (s *Scope) AllowIP(ip netip.Addr) error {
	ip = ip.Unmap()
	for _, n := range s.nets {
		if n.Contains(ip) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s", ErrIP, ip)
}

// ResolveAllowed 는 host 를 해석해 허용 대역 안의 IP 만 반환한다. 하나도 없으면 오류.
func (s *Scope) ResolveAllowed(ctx context.Context, host string) ([]netip.Addr, error) {
	var addrs []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{ip}
	} else {
		addrs, err = s.resolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
	}
	var ok []netip.Addr
	for _, a := range addrs {
		if s.AllowIP(a) == nil {
			ok = append(ok, a.Unmap())
		}
	}
	if len(ok) == 0 {
		return nil, fmt.Errorf("%w: %s -> %v", ErrIP, host, addrs)
	}
	return ok, nil
}

// Allow 는 URL 검사와 DNS 해석 후 IP 검사를 모두 수행한다.
func (s *Scope) Allow(ctx context.Context, u *url.URL) error {
	if err := s.AllowURL(u); err != nil {
		return err
	}
	_, err := s.ResolveAllowed(ctx, u.Hostname())
	return err
}

// Excluded 는 경로가 제외 패턴에 해당하는지 판단한다 (대소문자 무시, 접두사 일치).
func (s *Scope) Excluded(path string) bool {
	if path == "" {
		path = "/"
	}
	for _, re := range s.excludes {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

// compileGlob 은 `*` 를 임의 문자열(`/` 포함)로 보는 패턴을 접두사 일치 정규식으로 바꾼다.
// 제외 목록은 넓게 잡을수록 안전하므로 `/logout` 은 `/logout.do` 도 제외한다.
func compileGlob(p string) *regexp.Regexp {
	q := regexp.QuoteMeta(strings.ToLower(p))
	q = strings.ReplaceAll(q, `\*`, `.*`)
	return regexp.MustCompile(`(?i)^` + q)
}

func portOf(u *url.URL) int {
	if p := u.Port(); p != "" {
		n, _ := strconv.Atoi(p)
		return n
	}
	if u.Scheme == "https" {
		return 443
	}
	return 80
}
