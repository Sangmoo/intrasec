package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/url"
	"strconv"
	"time"
)

// TLSHandshake 는 HTTP 요청 없이 TLS 핸드셰이크만 수행하고 연결 상태를 돌려준다.
// 스코프(호스트·포트·실제 IP), 레이트리밋, 자동 일시정지는 HTTP 요청과 동일하게 적용된다.
// cfg 의 ServerName 이 비어 있으면 URL 호스트명으로 채운다 (SNI).
func (c *Client) TLSHandshake(ctx context.Context, rawURL string, cfg *tls.Config) (tls.ConnectionState, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	if u.Scheme != "https" {
		return tls.ConnectionState{}, errors.New("TLS 핸드셰이크는 https URL 만 가능")
	}
	if err := c.scope.AllowURL(u); err != nil {
		return tls.ConnectionState{}, err
	}
	if c.paused() {
		return tls.ConnectionState{}, ErrPaused
	}
	if err := c.limiter.Wait(ctx); err != nil {
		return tls.ConnectionState{}, err
	}

	port := u.Port()
	if port == "" {
		port = "443"
	}
	start := time.Now()
	cs, err := c.handshake(ctx, u.Hostname(), port, cfg)
	e := Entry{Time: start, Method: "TLS", URL: u.Scheme + "://" + net.JoinHostPort(u.Hostname(), port), Duration: time.Since(start)}
	if err != nil {
		e.Err = err.Error()
	} else {
		e.Status = int(cs.Version)
	}
	if c.opts.Record != nil {
		c.opts.Record(e)
	}
	return cs, err
}

func (c *Client) handshake(ctx context.Context, host, port string, cfg *tls.Config) (tls.ConnectionState, error) {
	ctx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()
	conn, err := c.dialFunc(&net.Dialer{Timeout: c.opts.Timeout})(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer func() { _ = conn.Close() }()

	cfg = cfg.Clone()
	if cfg.ServerName == "" && net.ParseIP(host) == nil {
		cfg.ServerName = host
	}
	// 인증서 검증은 점검 플러그인이 PeerCertificates 로 직접 수행한다.
	cfg.InsecureSkipVerify = true //nolint:gosec // 점검 도구 특성상 의도적
	tc := tls.Client(conn, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		return tls.ConnectionState{}, err
	}
	return tc.ConnectionState(), nil
}

// TLSVersionName 은 tls.VersionTLS12 같은 값을 "TLS 1.2" 로 바꾼다.
func TLSVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	}
	return "0x" + strconv.FormatUint(uint64(v), 16)
}
