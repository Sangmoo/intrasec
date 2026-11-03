// Package transport 는 모든 점검 플러그인이 사용하는 공통 HTTP 클라이언트다.
// 스코프 검사(매 리다이렉트 홉, 실제 연결 IP), 레이트리밋, 위험 메서드 차단,
// 연속 5xx 자동 일시정지, 요청 기록을 담당한다.
package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/Sangmoo/intrasec/internal/scope"
)

var (
	ErrMethodBlocked = errors.New("차단된 HTTP 메서드")
	ErrPaused        = errors.New("연속 5xx 응답으로 자동 일시정지됨")
	ErrTooManyHops   = errors.New("리다이렉트 횟수 초과")
)

const (
	DefaultMax5xx    = 10
	DefaultMaxRedirs = 10
	userAgent        = "intrasec (authorized internal security assessment)"
)

// Entry 는 요청 기록 한 건이다.
type Entry struct {
	Time     time.Time
	Method   string
	URL      string
	Status   int
	Duration time.Duration
	Err      string
}

type Options struct {
	RateLimit    float64 // 초당 요청 수
	Timeout      time.Duration
	AllowUnsafe  bool // DELETE/PUT/PATCH 허용 (기본 false)
	Max5xx       int
	MaxRedirects int
	Record       func(Entry)
}

type Client struct {
	scope   *scope.Scope
	opts    Options
	limiter *rate.Limiter
	hc      *http.Client

	mu        sync.Mutex
	consec5xx int
}

func New(s *scope.Scope, o Options) *Client {
	if o.RateLimit <= 0 {
		o.RateLimit = scope.DefaultRateLimit
	}
	if o.Timeout <= 0 {
		o.Timeout = scope.DefaultTimeoutSec * time.Second
	}
	if o.Max5xx <= 0 {
		o.Max5xx = DefaultMax5xx
	}
	if o.MaxRedirects <= 0 {
		o.MaxRedirects = DefaultMaxRedirs
	}
	c := &Client{
		scope:   s,
		opts:    o,
		limiter: rate.NewLimiter(rate.Limit(o.RateLimit), 1),
	}
	dialer := &net.Dialer{Timeout: o.Timeout}
	tr := &http.Transport{
		// 프록시 경유 시 실제 연결 IP 검사가 무력화되므로 사용하지 않는다.
		Proxy:       nil,
		DialContext: c.dialFunc(dialer),
		TLSClientConfig: &tls.Config{
			// 사내 시스템은 자체 서명 인증서가 흔하다. 인증서 문제는 COMMON-TLS-003 이 별도로 보고한다.
			InsecureSkipVerify: true, //nolint:gosec // 점검 도구 특성상 의도적
			// 구버전 TLS 만 지원하는 서버도 점검할 수 있어야 한다.
			MinVersion: tls.VersionTLS10, //nolint:gosec // 점검 도구 특성상 의도적
		},
		TLSHandshakeTimeout:   o.Timeout,
		ResponseHeaderTimeout: o.Timeout,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       30 * time.Second,
	}
	jar, _ := cookiejar.New(nil)
	c.hc = &http.Client{
		Transport:     tr,
		Timeout:       o.Timeout,
		Jar:           jar,
		CheckRedirect: c.checkRedirect,
	}
	return c
}

// dialFunc 는 DNS 해석 결과 중 허용 대역의 IP 로만 직접 연결한다.
// 해석과 연결 사이에 DNS 응답이 바뀌는 리바인딩도 이 방식으로 막는다.
func (c *Client) dialFunc(d *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := c.scope.ResolveAllowed(ctx, host)
		if err != nil {
			return nil, err
		}
		var lastErr error
		for _, ip := range ips {
			conn, err := d.DialContext(ctx, network, netip.AddrPortFrom(ip, mustPort(port)).String())
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}

func (c *Client) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= c.opts.MaxRedirects {
		return ErrTooManyHops
	}
	if err := c.scope.AllowURL(req.URL); err != nil {
		return fmt.Errorf("리다이렉트 차단: %w", err)
	}
	return c.limiter.Wait(req.Context())
}

// Do 는 스코프·메서드·레이트리밋 검사를 거친 뒤 요청을 보낸다.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if err := c.checkMethod(req.Method); err != nil {
		return nil, err
	}
	if err := c.scope.AllowURL(req.URL); err != nil {
		return nil, err
	}
	if c.paused() {
		return nil, ErrPaused
	}
	if err := c.limiter.Wait(req.Context()); err != nil {
		return nil, err
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", userAgent)
	}

	start := time.Now()
	resp, err := c.hc.Do(req)
	e := Entry{Time: start, Method: req.Method, URL: req.URL.String(), Duration: time.Since(start)}
	if err != nil {
		e.Err = err.Error()
	} else {
		e.Status = resp.StatusCode
		c.observe(resp.StatusCode)
	}
	if c.opts.Record != nil {
		c.opts.Record(e)
	}
	return resp, err
}

// Get 은 편의 함수다.
func (c *Client) Get(ctx context.Context, rawURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

func (c *Client) checkMethod(m string) error {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPost:
		return nil
	case http.MethodDelete, http.MethodPut, http.MethodPatch:
		if c.opts.AllowUnsafe {
			return nil
		}
	}
	return fmt.Errorf("%w: %s", ErrMethodBlocked, m)
}

func (c *Client) observe(status int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if status >= 500 {
		c.consec5xx++
	} else {
		c.consec5xx = 0
	}
}

func (c *Client) paused() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.consec5xx >= c.opts.Max5xx
}

// Resume 은 자동 일시정지를 해제한다.
func (c *Client) Resume() {
	c.mu.Lock()
	c.consec5xx = 0
	c.mu.Unlock()
}

func mustPort(p string) uint16 {
	n, _ := strconv.ParseUint(p, 10, 16)
	return uint16(n)
}
