package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecurityMiddleware(t *testing.T) {
	s, err := New("test")
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	cases := []struct {
		name   string
		method string
		host   string
		token  string
		origin string
		want   int
	}{
		{"정상", http.MethodGet, "127.0.0.1:8080", s.Token, "", http.StatusOK},
		{"localhost 허용", http.MethodGet, "localhost:8080", s.Token, "", http.StatusOK},
		{"리바인딩 Host 거부", http.MethodGet, "evil.example.com:8080", s.Token, "", http.StatusForbidden},
		{"토큰 없음", http.MethodGet, "127.0.0.1:8080", "", "", http.StatusUnauthorized},
		{"토큰 불일치", http.MethodGet, "127.0.0.1:8080", "bad", "", http.StatusUnauthorized},
		{"POST Origin 없음", http.MethodPost, "127.0.0.1:8080", s.Token, "", http.StatusForbidden},
		{"POST 외부 Origin", http.MethodPost, "127.0.0.1:8080", s.Token, "http://evil.example.com", http.StatusForbidden},
		{"DELETE 거부", http.MethodDelete, "127.0.0.1:8080", s.Token, "http://127.0.0.1:8080", http.StatusMethodNotAllowed},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, "/api/health", nil)
		req.Host = c.host
		if c.token != "" {
			req.Header.Set(tokenHeader, c.token)
		}
		if c.origin != "" {
			req.Header.Set("Origin", c.origin)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("%s: want %d, got %d", c.name, c.want, rec.Code)
		}
	}
}
