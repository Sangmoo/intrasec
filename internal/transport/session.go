package transport

import (
	"context"
	"net/http"
	"net/url"
)

type anonKey struct{}

// Anonymous 는 세션 쿠키 없이 요청하도록 표시한 컨텍스트를 돌려준다.
// "로그인 없이도 응답하는가"를 확인하는 점검(XP-001 등)에서 사용한다.
func Anonymous(ctx context.Context) context.Context {
	return context.WithValue(ctx, anonKey{}, true)
}

func IsAnonymous(ctx context.Context) bool {
	v, _ := ctx.Value(anonKey{}).(bool)
	return v
}

// Cookies 는 u 에 보낼 세션 쿠키를 돌려준다 (인증 모듈의 로그인 확인용).
func (c *Client) Cookies(u *url.URL) []*http.Cookie {
	return c.hc.Jar.Cookies(u)
}
