package transport

import (
	"context"
	"io"
	"net"
	"net/url"
	"strconv"
	"time"
)

const tcpReadWait = 5 * time.Second

// TCPExchange 는 host:port 에 TCP 로 연결해 payload 를 보내고 최대 max 바이트를 읽는다.
// WebLogic T3/IIOP 처럼 HTTP 가 아닌 프로토콜의 "노출 여부" 핸드셰이크 확인용이다.
// 스코프(호스트·포트·실제 IP), 레이트리밋, 호스트당 상한, 자동 일시정지가 동일하게 적용된다.
func (c *Client) TCPExchange(ctx context.Context, host string, port int, payload []byte, max int) ([]byte, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	if err := c.scope.AllowURL(&url.URL{Scheme: "http", Host: addr, Path: "/"}); err != nil {
		return nil, err
	}
	if c.paused() {
		return nil, ErrPaused
	}
	if err := c.spend(host); err != nil {
		return nil, err
	}
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, err
	}

	start := time.Now()
	b, err := c.exchange(ctx, addr, payload, max)
	e := Entry{Time: start, Method: "TCP", URL: "tcp://" + addr, Status: len(b), Duration: time.Since(start)}
	if err != nil {
		e.Err = err.Error()
	}
	if c.opts.Record != nil {
		c.opts.Record(e)
	}
	return b, err
}

func (c *Client) exchange(ctx context.Context, addr string, payload []byte, max int) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()
	conn, err := c.dialFunc(&net.Dialer{Timeout: c.opts.Timeout})(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	// 응답하지 않는 포트에서 오래 기다리지 않도록 읽기 대기는 최대 tcpReadWait 로 제한한다.
	dl := time.Now().Add(min(c.opts.Timeout, tcpReadWait))
	_ = conn.SetDeadline(dl)
	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}
	buf := make([]byte, max)
	n, err := io.ReadAtLeast(conn, buf, 1)
	if err != nil && n == 0 {
		return nil, err
	}
	return buf[:n], nil
}
