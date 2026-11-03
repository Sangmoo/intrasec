// Package engine 은 점검 오케스트레이션(대상×점검 작업 분배, 워커 풀, 취소)을 담당한다.
// 점검 레벨(passive/active)과 시간대 강제는 플러그인이 아닌 이 패키지에서 수행한다.
package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/Sangmoo/intrasec/internal/audit"
	"github.com/Sangmoo/intrasec/internal/checks"
	"github.com/Sangmoo/intrasec/internal/scope"
	"github.com/Sangmoo/intrasec/internal/transport"
	"github.com/Sangmoo/intrasec/pkg/finding"
)

type Options struct {
	Scope  *scope.Scope
	HTTP   *transport.Client
	Checks []checks.Check
	Audit  *audit.Logger
	// Progress 는 작업 하나가 끝날 때마다 호출된다 (SSE·CLI 진행 표시용). nil 가능.
	Progress func(Progress)
	Now      func() time.Time
}

type Progress struct {
	Done, Total int
	Target      string
	CheckID     string
	Findings    int
	Err         error
}

type Result struct {
	ScanID      string            `json:"scan_id"`
	Engagement  string            `json:"engagement"`
	ApprovedBy  string            `json:"approved_by"`
	ApprovalRef string            `json:"approval_ref"`
	Targets     []string          `json:"targets"`
	StartedAt   time.Time         `json:"started_at"`
	FinishedAt  time.Time         `json:"finished_at"`
	Checks      []string          `json:"checks"`
	Skipped     []string          `json:"skipped,omitempty"`
	Findings    []finding.Finding `json:"findings"`
	Errors      []string          `json:"errors,omitempty"`
	Canceled    bool              `json:"canceled,omitempty"`
}

type job struct {
	target checks.Target
	check  checks.Check
}

// Run 은 점검을 실행한다. 시간대 밖이면 아무 요청도 보내지 않고 거부한다.
func Run(ctx context.Context, o Options) (*Result, error) {
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	cfg := o.Scope.Config()
	res := &Result{
		ScanID:      newScanID(now()),
		Engagement:  cfg.Engagement.Name,
		ApprovedBy:  cfg.Engagement.ApprovedBy,
		ApprovalRef: cfg.Engagement.ApprovalRef,
		StartedAt:   now(),
		Findings:    []finding.Finding{},
	}

	if err := o.Scope.CheckWindow(now()); err != nil {
		o.Audit.Log(audit.Event{Action: "scan.denied", ScanID: res.ScanID, Engagement: res.Engagement, Detail: err.Error()})
		return nil, err
	}

	targets, err := buildTargets(cfg)
	if err != nil {
		return nil, err
	}
	for _, t := range targets {
		res.Targets = append(res.Targets, t.BaseURL.String())
	}

	var runnable []checks.Check
	for _, c := range o.Checks {
		if c.Level() == checks.Active && !cfg.Options.ActiveChecks {
			res.Skipped = append(res.Skipped, c.ID()+" (active_checks: false)")
			continue
		}
		runnable = append(runnable, c)
		res.Checks = append(res.Checks, c.ID())
	}

	var jobs []job
	for _, t := range targets {
		for _, c := range runnable {
			if checks.AppliesTo(c, t) {
				jobs = append(jobs, job{t, c})
			}
		}
	}

	o.Audit.Log(audit.Event{Action: "scan.start", ScanID: res.ScanID, Engagement: res.Engagement,
		Detail: fmt.Sprintf("targets=%d checks=%d jobs=%d", len(targets), len(runnable), len(jobs))})

	sess := &checks.Session{HTTP: o.HTTP}
	timeout := time.Duration(cfg.Options.TimeoutSec) * time.Second * 4

	var (
		mu   sync.Mutex
		done int
		wg   sync.WaitGroup
	)
	ch := make(chan job)
	for i := 0; i < cfg.Options.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range ch {
				fs, err := runOne(ctx, j, sess, timeout, o.Audit, res.ScanID)
				mu.Lock()
				done++
				for i := range fs {
					fs[i].ID = finding.StableID(fs[i].CheckID, fs[i].Target)
					if fs[i].FoundAt.IsZero() {
						fs[i].FoundAt = now()
					}
				}
				res.Findings = append(res.Findings, fs...)
				if err != nil {
					res.Errors = append(res.Errors, fmt.Sprintf("%s @ %s: %v", j.check.ID(), j.target.Name, err))
				}
				p := Progress{Done: done, Total: len(jobs), Target: j.target.Name, CheckID: j.check.ID(), Findings: len(fs), Err: err}
				mu.Unlock()
				if o.Progress != nil {
					o.Progress(p)
				}
			}
		}()
	}

feed:
	for _, j := range jobs {
		select {
		case ch <- j:
		case <-ctx.Done():
			res.Canceled = true
			break feed
		}
	}
	close(ch)
	wg.Wait()

	finding.Sort(res.Findings)
	res.FinishedAt = now()
	o.Audit.Log(audit.Event{Action: "scan.finish", ScanID: res.ScanID, Engagement: res.Engagement,
		Detail: fmt.Sprintf("findings=%d errors=%d canceled=%v", len(res.Findings), len(res.Errors), res.Canceled)})
	return res, nil
}

func runOne(ctx context.Context, j job, s *checks.Session, timeout time.Duration, al *audit.Logger, scanID string) (fs []finding.Finding, err error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	al.Log(audit.Event{Action: "check.run", ScanID: scanID, Target: j.target.BaseURL.String(), CheckID: j.check.ID()})
	return j.check.Run(ctx, j.target, s)
}

func buildTargets(cfg *scope.Config) ([]checks.Target, error) {
	out := make([]checks.Target, 0, len(cfg.Targets))
	for _, t := range cfg.Targets {
		u, err := url.Parse(t.BaseURL)
		if err != nil {
			return nil, err
		}
		out = append(out, checks.Target{Name: t.Name, BaseURL: u, Tags: t.Tags})
	}
	return out, nil
}

func newScanID(t time.Time) string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return t.Format("20060102-150405") + "-" + hex.EncodeToString(b)
}
