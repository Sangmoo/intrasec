package xplatform

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sangmoo/intrasec/internal/checks/checkstest"
	"github.com/Sangmoo/intrasec/internal/scope"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "xplatform", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestServiceWithoutSession(t *testing.T) {
	xml := "text/xml; charset=UTF-8"
	tgt, s := checkstest.ServeOpts(t, checkstest.Files{Paths: map[string]checkstest.File{
		"/svc/selectUserList.do": {ContentType: xml, Body: fixture(t, "open_service.xml")},
		"/svc/selectSalary.do":   {ContentType: xml, Body: fixture(t, "denied_service.xml")},
	}}, checkstest.Opts{ServiceURLs: []string{"/svc/selectUserList.do", "/svc/selectSalary.do"}})

	fs, err := xpCheck{}.Run(context.Background(), tgt, s)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range fs {
		got[f.CheckID] = string(f.Severity) + " " + f.Target + " " + f.Evidence.Note
	}
	if len(fs) != 2 {
		t.Fatalf("XP-001 1건 + XP-002 1건 기대: %v", got)
	}
	if v := got["XP-001"]; !strings.HasPrefix(v, "critical") || !strings.Contains(v, "selectUserList.do") || !strings.Contains(v, "2행") {
		t.Errorf("XP-001 이상: %s", v)
	}
	if strings.Contains(got["XP-001"], "U0001") {
		t.Error("응답 데이터 값이 근거에 기록됨")
	}
	if !strings.Contains(got["XP-002"], "http://") {
		t.Errorf("XP-002 이상: %s", got["XP-002"])
	}
}

func TestSkipWithoutServiceOrTag(t *testing.T) {
	tgt, s := checkstest.Serve(t, checkstest.Files{})
	if fs, err := (xpCheck{}).Run(context.Background(), tgt, s); err != nil || len(fs) != 0 {
		t.Fatalf("service_urls·태그 없으면 건너뛰어야 함: %v %v", fs, err)
	}
}

func TestParseSSV(t *testing.T) {
	ssv := "SSV:utf-8\x1eErrorCode:int=0\x1eErrorMsg:string=SUCC\x1eDataset:ds_list\x1e_RowType_\x1fID:STRING(10)\x1eN\x1fA\x1eN\x1fB\x1eN\x1fC\x1e"
	p, ok := parseResponse([]byte(ssv))
	if !ok || p.format != "SSV" || p.errorCode == nil || *p.errorCode != 0 || len(p.datasets) != 1 || p.rows < 3 {
		t.Fatalf("SSV 파싱 오류: %+v", p)
	}
}

func TestUnsafeServiceRejected(t *testing.T) {
	y := `
engagement: {name: t, approved_by: a, approval_ref: r, window: {start: "2026-01-01T00:00:00Z", end: "2027-01-01T00:00:00Z"}}
targets: [{name: erp, base_url: "https://erp.example.local", service_urls: ["/svc/saveUser.do", "/svc/deleteDoc.do", "/svc/selectList.do"]}]
allow: {cidrs: [10.0.0.0/8]}
`
	_, err := scope.Parse([]byte(y))
	if err == nil || !strings.Contains(err.Error(), "saveUser") || !strings.Contains(err.Error(), "deleteDoc") || strings.Contains(err.Error(), "selectList") {
		t.Fatalf("저장·삭제 서비스만 거부되어야 함: %v", err)
	}
}
