package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Sangmoo/intrasec/internal/engine"
	"github.com/Sangmoo/intrasec/pkg/finding"
)

func TestStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	p, err := s.CreateProject(ctx, "ERP", "engagement: {}")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateProject(ctx, "ERP", "x"); err == nil {
		t.Fatal("이름 중복은 거부되어야 함")
	}

	sc := &Scan{ID: "s1", ProjectID: p.ID, StartedAt: time.Now(), SafeMode: true}
	if err := s.StartScan(ctx, sc); err != nil {
		t.Fatal(err)
	}
	res := &engine.Result{ScanID: "s1", Findings: []finding.Finding{{ID: "f1", CheckID: "COMMON-HDR-001", Severity: finding.SevMedium}}}
	if err := s.FinishScan(ctx, "s1", StatusDone, res, ""); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetScan(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusDone || !got.SafeMode || got.Result == nil || len(got.Result.Findings) != 1 || got.Summary["medium"] != 1 || got.FinishedAt == nil {
		t.Fatalf("조회 결과 이상: %+v", got)
	}
	list, err := s.ListScans(ctx, p.ID)
	if err != nil || len(list) != 1 || list[0].Result != nil {
		t.Fatalf("목록은 결과 본문 없이 1건: %+v %v", list, err)
	}
	if _, err := s.GetScan(ctx, "none"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ErrNotFound 기대: %v", err)
	}

	// 실행 중에 종료된 점검은 다시 열 때 interrupted 로 바뀐다.
	if err := s.StartScan(ctx, &Scan{ID: "s2", ProjectID: p.ID, StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if got, _ := s.GetScan(ctx, "s2"); got.Status != StatusInterrupted {
		t.Fatalf("interrupted 기대: %s", got.Status)
	}

	// 프로젝트 삭제 시 점검도 함께 삭제
	if err := s.DeleteProject(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetScan(ctx, "s1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("연쇄 삭제 기대: %v", err)
	}
}
