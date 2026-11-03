package common

import (
	"bufio"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sangmoo/intrasec/pkg/finding"
)

// loadResponse 는 testdata 의 녹화된 HTTP 응답을 읽는다.
func loadResponse(t *testing.T, name string) *http.Response {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "..", "testdata", "common", name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	resp, err := http.ReadResponse(bufio.NewReader(f), nil)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func ids(fs []finding.Finding) map[string]bool {
	m := map[string]bool{}
	for _, f := range fs {
		m[f.CheckID] = true
	}
	return m
}

func TestHeadersInsecure(t *testing.T) {
	resp := loadResponse(t, "insecure_response.http")
	got := ids(analyzeHeaders("https://app.example.local/", true, resp.Header, finding.Evidence{}))
	for _, want := range []string{"COMMON-HDR-001", "COMMON-HDR-002", "COMMON-HDR-003", "COMMON-HDR-004", "COMMON-HDR-005"} {
		if !got[want] {
			t.Errorf("%s 미검출", want)
		}
	}
}

func TestHeadersHardened(t *testing.T) {
	resp := loadResponse(t, "hardened_response.http")
	if fs := analyzeHeaders("https://app.example.local/", true, resp.Header, finding.Evidence{}); len(fs) != 0 {
		t.Errorf("오탐: %+v", ids(fs))
	}
}

func TestHSTSOnlyForHTTPS(t *testing.T) {
	resp := loadResponse(t, "insecure_response.http")
	if ids(analyzeHeaders("http://app.example.local/", false, resp.Header, finding.Evidence{}))["COMMON-HDR-002"] {
		t.Error("HTTP 응답에는 HSTS 를 요구하지 않아야 함")
	}
}

func TestCookiesInsecure(t *testing.T) {
	resp := loadResponse(t, "insecure_response.http")
	got := analyzeCookies("https://app.example.local/", true, resp.Cookies(), finding.Evidence{})
	m := ids(got)
	for _, want := range []string{"COMMON-CKE-001", "COMMON-CKE-002", "COMMON-CKE-003"} {
		if !m[want] {
			t.Errorf("%s 미검출", want)
		}
	}
	for _, f := range got {
		if f.Evidence.Note != "대상 쿠키: JSESSIONID" {
			t.Errorf("세션 쿠키가 아닌 쿠키까지 포함됨: %q", f.Evidence.Note)
		}
	}
}

func TestCookiesHardened(t *testing.T) {
	resp := loadResponse(t, "hardened_response.http")
	if fs := analyzeCookies("https://app.example.local/", true, resp.Cookies(), finding.Evidence{}); len(fs) != 0 {
		t.Errorf("오탐: %+v", ids(fs))
	}
}
