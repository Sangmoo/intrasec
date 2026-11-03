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
	// Auth 는 대상별 로그인 세션 관리자다. 점검 시작 시 로그인하며, 실패한 대상은 비로그인으로 점검한다.
	Auth []Authenticator
	// Progress 는 작업 하나가 끝날 때마다 호출된다 (SSE·CLI 진행 표시용). nil 가능.
	Progress func(Progress)
	Now      func() time.Time
}

// Authenticator 는 internal/auth.Form 이 구현한다.
type Authenticator interface {
	checks.Authenticator
	Host() string
	Login(ctx context.Context) error
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
	SafeMode    bool              `json:"safe_mode,omitempty"`
}

// Job 은 대상 하나에 점검 하나를 실행하는 작업 단위다.
type Job struct {
	Target checks.Target
	Check  checks.Check
}

// Plan 은 실제 요청 없이 계산한 실행 계획이다 (scan --dry-run 과 Run 이 공유).
type Plan struct {
	Options   scope.Options // safe_mode 반영된 실제 적용 옵션
	Targets   []checks.Target
	Checks    []checks.Check
	Skipped   []string
	Jobs      []Job
	WindowErr error // 시간대 밖이면 nil 이 아님
}

// NewPlan 은 점검 레벨·safe_mode·대상 태그를 반영해 실행할 작업을 계산한다.
func NewPlan(sc *scope.Scope, cs []checks.Check, now time.Time) (*Plan, error) {
	cfg := sc.Config()
	p := &Plan{Options: cfg.Options.Effective(), WindowErr: sc.CheckWindow(now)}
	var err error
	if p.Targets, err = buildTargets(cfg); err != nil {
		return nil, err
	}
	for _, c := range cs {
		if c.Level() == checks.Active && !p.Options.ActiveChecks {
			reason := "active_checks: false"
			if p.Options.SafeMode {
				reason = "safe_mode"
			}
			p.Skipped = append(p.Skipped, c.ID()+" ("+reason+")")
			continue
		}
		p.Checks = append(p.Checks, c)
	}
	for _, t := range p.Targets {
		for _, c := range p.Checks {
			if checks.AppliesTo(c, t) {
				p.Jobs = append(p.Jobs, Job{t, c})
			}
		}
	}
	return p, nil
}

// Run 은 점검을 실행한다. 시간대 밖이면 아무 요청도 보내지 않고 거부한다.
func Run(ctx context.Context, o Options) (*Result, error) {
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	cfg := o.Scope.Config()
	plan, err := NewPlan(o.Scope, o.Checks, now())
	if err != nil {
		return nil, err
	}
	res := &Result{
		ScanID:      newScanID(now()),
		Engagement:  cfg.Engagement.Name,
		ApprovedBy:  cfg.Engagement.ApprovedBy,
		ApprovalRef: cfg.Engagement.ApprovalRef,
		StartedAt:   now(),
		Findings:    []finding.Finding{},
		Skipped:     plan.Skipped,
		SafeMode:    plan.Options.SafeMode,
	}

	if plan.WindowErr != nil {
		o.Audit.Log(audit.Event{Action: "scan.denied", ScanID: res.ScanID, Engagement: res.Engagement, Detail: plan.WindowErr.Error()})
		return nil, plan.WindowErr
	}
	for _, t := range plan.Targets {
		res.Targets = append(res.Targets, t.BaseURL.String())
	}
	for _, c := range plan.Checks {
		res.Checks = append(res.Checks, c.ID())
	}
	jobs := plan.Jobs

	o.Audit.Log(audit.Event{Action: "scan.start", ScanID: res.ScanID, Engagement: res.Engagement,
		Detail: fmt.Sprintf("targets=%d checks=%d jobs=%d safe_mode=%v", len(plan.Targets), len(plan.Checks), len(jobs), plan.Options.SafeMode)})

	sess := &checks.Session{HTTP: o.HTTP, Safe: plan.Options.SafeMode, Auth: map[string]checks.Authenticator{}}
	for _, a := range o.Auth {
		if err := a.Login(ctx); err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("로그인 실패 (%s, 비로그인으로 점검): %v", a.Host(), err))
			continue
		}
		sess.Auth[a.Host()] = a
	}
	timeout := time.Duration(plan.Options.TimeoutSec) * time.Second * 4

	var (
		mu   sync.Mutex
		done int
		wg   sync.WaitGroup
	)
	ch := make(chan Job)
	for i := 0; i < plan.Options.Concurrency; i++ {
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
					res.Errors = append(res.Errors, fmt.Sprintf("%s @ %s: %v", j.Check.ID(), j.Target.Name, err))
				}
				p := Progress{Done: done, Total: len(jobs), Target: j.Target.Name, CheckID: j.Check.ID(), Findings: len(fs), Err: err}
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

func runOne(ctx context.Context, j Job, s *checks.Session, timeout time.Duration, al *audit.Logger, scanID string) (fs []finding.Finding, err error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	al.Log(audit.Event{Action: "check.run", ScanID: scanID, Target: j.Target.BaseURL.String(), CheckID: j.Check.ID()})
	return j.Check.Run(ctx, j.Target, s)
}

func buildTargets(cfg *scope.Config) ([]checks.Target, error) {
	out := make([]checks.Target, 0, len(cfg.Targets))
	for _, t := range cfg.Targets {
		u, err := url.Parse(t.BaseURL)
		if err != nil {
			return nil, err
		}
		ct := checks.Target{Name: t.Name, BaseURL: u, Tags: t.Tags, Ports: t.Ports}
		for _, su := range t.ServiceURLs {
			ref, err := url.Parse(su)
			if err != nil {
				return nil, err
			}
			ct.ServiceURLs = append(ct.ServiceURLs, u.ResolveReference(ref))
		}
		out = append(out, ct)
	}
	return out, nil
}

func newScanID(t time.Time) string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return t.Format("20060102-150405") + "-" + hex.EncodeToString(b)
}
