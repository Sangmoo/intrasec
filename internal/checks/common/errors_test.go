package common

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Sangmoo/intrasec/internal/checks"
	"github.com/Sangmoo/intrasec/internal/checks/checkstest"
)

func TestAnalyzeErrorPage(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "common", "java_error.html"))
	if err != nil {
		t.Fatal(err)
	}
	fs := analyzeErrorPage(&checks.Page{URL: "http://x/", Body: b})
	var got []string
	for _, f := range fs {
		got = append(got, string(f.Severity)+" "+f.Title)
	}
	sort.Strings(got)
	want := "low 에러 페이지 서버 버전 노출|medium 상세 에러/스택트레이스 노출 (Java 스택트레이스)"
	if strings.Join(got, "|") != want {
		t.Fatalf("want %s\n got %v", want, got)
	}
	if !strings.Contains(fs[0].Evidence.Note+fs[1].Evidence.Note, "NullPointerException") {
		t.Error("근거 발췌 누락")
	}
}

func TestAnalyzeErrorPageClean(t *testing.T) {
	body := []byte(`<html><body><h1>요청하신 페이지를 찾을 수 없습니다</h1><p>at the moment, java is great</p></body></html>`)
	if fs := analyzeErrorPage(&checks.Page{URL: "http://x/", Body: body}); len(fs) != 0 {
		t.Fatalf("오탐: %+v", fs)
	}
}

func TestPlaintextLogin(t *testing.T) {
	login := `<form method="post" action="/login.do"><input name="userId"><input type="password" name="userPw"></form>`
	tgt, s := checkstest.Serve(t, checkstest.Files{Paths: map[string]checkstest.File{
		"/":         {ContentType: "text/html", Body: "<html>main</html>"},
		"/login.do": {ContentType: "text/html", Body: login},
	}})
	fs, err := plaintextLoginCheck{}.Run(context.Background(), tgt, s)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || !strings.HasSuffix(fs[0].Target, "/login.do") {
		t.Fatalf("HTTP 로그인 페이지 1건 기대: %+v", fs)
	}
}

func TestHTTPSLoginPostsToHTTP(t *testing.T) {
	page := `<form action="http://erp.example.local/login.do"><input type='password' name=pw></form>`
	tgt, s := checkstest.ServeTLS(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(page))
	}), nil)
	fs, err := plaintextLoginCheck{}.Run(context.Background(), tgt, s)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || !strings.Contains(fs[0].Evidence.Note, "http://erp.example.local/login.do") {
		t.Fatalf("평문 전송 폼 미검출: %+v", fs)
	}
}
