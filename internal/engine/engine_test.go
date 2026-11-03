package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sangmoo/intrasec/internal/audit"
	"github.com/Sangmoo/intrasec/internal/checks"
	"github.com/Sangmoo/intrasec/internal/scope"
	"github.com/Sangmoo/intrasec/internal/transport"
	"github.com/Sangmoo/intrasec/pkg/finding"
)

type fakeCheck struct {
	id    string
	level checks.Level
	runs  atomic.Int32
}

func (f *fakeCheck) ID() string          { return f.id }
func (f *fakeCheck) Name() string        { return f.id }
func (f *fakeCheck) Level() checks.Level { return f.level }
func (f *fakeCheck) Tags() []string      { return []string{checks.TagCommon} }
func (f *fakeCheck) Run(ctx context.Context, t checks.Target, s *checks.Session) ([]finding.Finding, error) {
	f.runs.Add(1)
	resp, err := s.HTTP.Get(ctx, t.BaseURL.String())
	if err != nil {
		return nil, err
	}
	_ = resp.Body.Close()
	return []finding.Finding{{CheckID: f.id, Title: "t", Severity: finding.SevLow, Target: t.BaseURL.String()}}, nil
}

func setup(t *testing.T, active bool) (*scope.Scope, *transport.Client) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)
	y := fmt.Sprintf(`
engagement:
  name: t
  approved_by: a
  approval_ref: r
  window: {start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z"}
targets: [{name: lab, base_url: %s}]
allow: {cidrs: [127.0.0.1/32]}
options: {rate_limit: 50, active_checks: %v}
`, srv.URL, active)
	c, err := scope.Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	s, _ := scope.New(c)
	return s, transport.New(s, transport.Options{RateLimit: 50})
}

var inWindow = func() time.Time { return time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC) }

func TestOutOfWindowRefused(t *testing.T) {
	s, h := setup(t, false)
	c := &fakeCheck{id: "P"}
	_, err := Run(context.Background(), Options{Scope: s, HTTP: h, Checks: []checks.Check{c},
		Now: func() time.Time { return time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC) }})
	if !errors.Is(err, scope.ErrOutOfWindow) {
		t.Fatalf("시간대 밖 거부 기대: %v", err)
	}
	if c.runs.Load() != 0 {
		t.Fatal("시간대 밖에서 점검이 실행됨")
	}
}

func TestActiveChecksGated(t *testing.T) {
	s, h := setup(t, false)
	p, a := &fakeCheck{id: "P"}, &fakeCheck{id: "A", level: checks.Active}
	var buf bytes.Buffer
	res, err := Run(context.Background(), Options{Scope: s, HTTP: h, Checks: []checks.Check{p, a}, Now: inWindow, Audit: audit.New(&buf)})
	if err != nil {
		t.Fatal(err)
	}
	if a.runs.Load() != 0 {
		t.Fatal("active_checks: false 인데 active 점검이 실행됨")
	}
	if p.runs.Load() != 1 || len(res.Findings) != 1 || res.Findings[0].ID == "" {
		t.Fatalf("passive 점검 결과 이상: %+v", res)
	}
	if !strings.Contains(buf.String(), `"scan.finish"`) {
		t.Fatal("감사 로그 누락")
	}

	s, h = setup(t, true)
	a = &fakeCheck{id: "A", level: checks.Active}
	if _, err := Run(context.Background(), Options{Scope: s, HTTP: h, Checks: []checks.Check{a}, Now: inWindow}); err != nil {
		t.Fatal(err)
	}
	if a.runs.Load() != 1 {
		t.Fatal("active_checks: true 인데 active 점검이 실행되지 않음")
	}
}
