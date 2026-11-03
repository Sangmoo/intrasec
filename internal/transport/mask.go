package transport

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

const maskValue = "****"

// sensitiveHeaders 는 값 전체를 마스킹하는 헤더다.
var sensitiveHeaders = map[string]bool{
	"Cookie":              true,
	"Authorization":       true,
	"Proxy-Authorization": true,
	"X-Auth-Token":        true,
	"X-Csrf-Token":        true,
}

var setCookieValue = regexp.MustCompile(`^([^=;]+)=([^;]*)`)

// MaskSetCookie 는 Set-Cookie 의 이름과 속성은 남기고 값만 가린다.
func MaskSetCookie(v string) string {
	return setCookieValue.ReplaceAllString(v, "${1}="+maskValue)
}

func maskHeader(name, v string) string {
	switch {
	case sensitiveHeaders[http.CanonicalHeaderKey(name)]:
		return maskValue
	case strings.EqualFold(name, "Set-Cookie"):
		return MaskSetCookie(v)
	}
	return v
}

func writeHeaders(b *strings.Builder, h http.Header) {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range h[k] {
			fmt.Fprintf(b, "%s: %s\r\n", k, maskHeader(k, v))
		}
	}
}

// DumpRequest 는 근거용 요청 텍스트(헤더만, 민감값 마스킹)를 만든다.
func DumpRequest(req *http.Request) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s %s\r\nHost: %s\r\n", req.Method, req.URL.RequestURI(), req.Proto, req.URL.Host)
	writeHeaders(&b, req.Header)
	return b.String()
}

// DumpResponse 는 근거용 응답 텍스트를 만든다. 본문은 maxBody 바이트까지만 포함한다.
// body 는 호출자가 이미 읽은 본문(없으면 nil)이다.
func DumpResponse(resp *http.Response, body []byte, maxBody int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\r\n", resp.Proto, resp.Status)
	writeHeaders(&b, resp.Header)
	if len(body) > 0 && maxBody > 0 {
		b.WriteString("\r\n")
		if len(body) > maxBody {
			b.Write(body[:maxBody])
			b.WriteString("\n...(생략)")
		} else {
			b.Write(body)
		}
	}
	return b.String()
}

// ReadBody 는 최대 limit 바이트까지 본문을 읽고 닫는다.
func ReadBody(resp *http.Response, limit int64) ([]byte, error) {
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}
