package checks

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/Sangmoo/intrasec/internal/scope"
	"github.com/Sangmoo/intrasec/internal/transport"
	"github.com/Sangmoo/intrasec/pkg/finding"
)

// MaxProbeBody 는 경로 탐색 시 읽는 본문 최대 크기다 (phpinfo 페이지가 100KB 내외).
const MaxProbeBody = 512 << 10

// Page 는 GET 한 번의 결과다. 리다이렉트를 따라간 최종 응답 기준.
type Page struct {
	URL    string
	Status int
	Header http.Header
	Body   []byte
	// Evidence 는 요청과 응답 헤더만 담는다 (본문은 민감정보가 있을 수 있어 제외).
	Evidence finding.Evidence
}

// Fetch 는 rawURL 에 GET 요청을 보내고 본문을 MaxProbeBody 까지 읽는다.
func Fetch(ctx context.Context, s *Session, rawURL string) (*Page, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.HTTP.Do(req) //nolint:bodyclose // transport.ReadBody 가 닫는다
	if err != nil {
		return nil, err
	}
	body, err := transport.ReadBody(resp, MaxProbeBody)
	if err != nil {
		return nil, err
	}
	return &Page{
		URL:    resp.Request.URL.String(),
		Status: resp.StatusCode,
		Header: resp.Header,
		Body:   body,
		Evidence: finding.Evidence{
			Request:  transport.DumpRequest(req),
			Response: transport.DumpResponse(resp, nil, 0),
		},
	}, nil
}

// IsHTML 은 응답이 HTML 문서로 보이는지 판단한다.
func (p *Page) IsHTML() bool {
	if strings.Contains(strings.ToLower(p.Header.Get("Content-Type")), "text/html") {
		return true
	}
	head := bytes.ToLower(bytes.TrimSpace(p.Body[:min(len(p.Body), 512)]))
	return bytes.HasPrefix(head, []byte("<!doctype html")) || bytes.HasPrefix(head, []byte("<html"))
}

// Abort 는 경로 탐색 중 만난 오류가 점검 전체를 멈춰야 하는 오류인지 판단한다.
// 스코프 제외 경로·개별 연결 실패는 건너뛰고, 자동 일시정지·취소는 중단한다.
func Abort(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, scope.ErrExcluded) {
		return false
	}
	return errors.Is(err, transport.ErrPaused) || errors.Is(err, transport.ErrBudget) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// ProbeURLs 는 웹 루트 기준 경로와, base_url 에 컨텍스트 경로가 있으면 그 아래 경로를 함께 만든다.
// 예: base_url https://erp/app/ , p "/.git/HEAD" -> https://erp/.git/HEAD, https://erp/app/.git/HEAD
func ProbeURLs(t Target, p string) []string {
	root := t.BaseURL.ResolveReference(&url.URL{Path: p}).String()
	out := []string{root}
	if bp := strings.TrimSuffix(t.BaseURL.Path, "/"); bp != "" {
		u := *t.BaseURL
		u.Path = path.Join(bp, p)
		if strings.HasSuffix(p, "/") {
			u.Path += "/"
		}
		u.RawQuery, u.Fragment = "", ""
		if s := u.String(); s != root {
			out = append(out, s)
		}
	}
	return out
}

// NotFoundPage 는 존재하지 않는 경로의 응답을 대상별로 한 번만 받아 캐시한다.
// 모든 경로에 200 을 주는 "soft 404" 서버에서 오탐을 막는 기준선으로 쓴다.
func (s *Session) NotFoundPage(ctx context.Context, t Target) *Page {
	key := t.BaseURL.String()
	if v, ok := s.notFound.Load(key); ok {
		return v.(*Page)
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	p, err := Fetch(ctx, s, t.BaseURL.ResolveReference(&url.URL{Path: "/intrasec-" + hex.EncodeToString(b) + ".php"}).String())
	if err != nil {
		p = &Page{Status: http.StatusNotFound}
	}
	v, _ := s.notFound.LoadOrStore(key, p)
	return v.(*Page)
}

// Found 는 응답이 "실제로 존재하는 자원"으로 보이는지 판단한다.
// 200 이 아니거나, soft 404 기준선과 본문이 사실상 같으면 false.
func Found(p, notFound *Page) bool {
	if p == nil || p.Status != http.StatusOK {
		return false
	}
	if notFound == nil || notFound.Status != http.StatusOK {
		return true
	}
	return !similar(p.Body, notFound.Body)
}

// similar 는 두 본문의 길이가 5% 이내이고 앞부분이 같으면 같은 페이지로 본다.
func similar(a, b []byte) bool {
	la, lb := len(a), len(b)
	if la == 0 || lb == 0 {
		return la == lb
	}
	diff := la - lb
	if diff < 0 {
		diff = -diff
	}
	if diff*20 > max(la, lb) {
		return false
	}
	n := min(la, lb, 256)
	return bytes.Equal(a[:n], b[:n])
}
