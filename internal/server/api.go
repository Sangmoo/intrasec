package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Sangmoo/intrasec/internal/auth"
	"github.com/Sangmoo/intrasec/internal/checks"
	"github.com/Sangmoo/intrasec/internal/engine"
	"github.com/Sangmoo/intrasec/internal/report"
	"github.com/Sangmoo/intrasec/internal/scope"
	"github.com/Sangmoo/intrasec/internal/store"
	"github.com/Sangmoo/intrasec/internal/transport"
)

const maxBody = 1 << 20

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "요청 형식 오류: "+err.Error())
		return false
	}
	return true
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "잘못된 ID")
		return 0, false
	}
	return id, true
}

func storeError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "찾을 수 없음")
		return
	}
	writeError(w, http.StatusInternalServerError, err.Error())
}

// ---- 점검 항목 ----

func (s *Server) listChecks(w http.ResponseWriter, _ *http.Request) {
	type item struct {
		ID    string   `json:"id"`
		Name  string   `json:"name"`
		Level string   `json:"level"`
		Tags  []string `json:"tags"`
	}
	out := []item{}
	for _, c := range checks.All() {
		out = append(out, item{c.ID(), c.Name(), c.Level().String(), c.Tags()})
	}
	writeJSON(w, http.StatusOK, out)
}

// ---- scope 검증 ----

type scopeSummary struct {
	Engagement   string   `json:"engagement"`
	ApprovedBy   string   `json:"approved_by"`
	ApprovalRef  string   `json:"approval_ref"`
	WindowStart  string   `json:"window_start"`
	WindowEnd    string   `json:"window_end"`
	InWindow     bool     `json:"in_window"`
	Targets      []string `json:"targets"`
	SafeMode     bool     `json:"safe_mode"`
	ActiveChecks bool     `json:"active_checks"`
	AuthEnvs     []string `json:"auth_envs"` // 비밀번호가 필요한 환경변수 이름
}

func summarizeScope(c *scope.Config, sc *scope.Scope) scopeSummary {
	sum := scopeSummary{
		Engagement: c.Engagement.Name, ApprovedBy: c.Engagement.ApprovedBy, ApprovalRef: c.Engagement.ApprovalRef,
		WindowStart: c.Engagement.Window.Start.Format(time.RFC3339), WindowEnd: c.Engagement.Window.End.Format(time.RFC3339),
		InWindow: sc.CheckWindow(time.Now()) == nil, SafeMode: c.Options.SafeMode, ActiveChecks: c.Options.ActiveChecks,
		Targets: []string{}, AuthEnvs: []string{},
	}
	for _, t := range c.Targets {
		sum.Targets = append(sum.Targets, t.Name+" "+t.BaseURL)
	}
	for _, a := range c.Auth {
		sum.AuthEnvs = append(sum.AuthEnvs, a.PasswordEnv)
	}
	return sum
}

// parseScope 는 YAML 을 검증해 설정과 오류 목록을 돌려준다.
func parseScope(y string) (*scope.Config, *scope.Scope, []string) {
	c, err := scope.Parse([]byte(y))
	if err != nil {
		return nil, nil, strings.Split(err.Error(), "\n")
	}
	sc, err := scope.New(c)
	if err != nil {
		return nil, nil, strings.Split(err.Error(), "\n")
	}
	return c, sc, nil
}

func (s *Server) validateScope(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ScopeYAML string `json:"scope_yaml"`
	}
	if !decode(w, r, &req) {
		return
	}
	c, sc, errs := parseScope(req.ScopeYAML)
	if errs != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "errors": errs})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "summary": summarizeScope(c, sc)})
}

// ---- 프로젝트 ----

func (s *Server) listProjects(w http.ResponseWriter, r *http.Request) {
	ps, err := s.cfg.Store.ListProjects(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ps)
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string `json:"name"`
		ScopeYAML string `json:"scope_yaml"`
	}
	if !decode(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "프로젝트 이름 필수")
		return
	}
	if _, _, errs := parseScope(req.ScopeYAML); errs != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "scope 검증 실패", "errors": errs})
		return
	}
	p, err := s.cfg.Store.CreateProject(r.Context(), req.Name, req.ScopeYAML)
	if err != nil {
		writeError(w, http.StatusConflict, "생성 실패 (이름 중복 등): "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

func (s *Server) getProject(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p, err := s.cfg.Store.GetProject(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	resp := map[string]any{"project": p}
	if c, sc, errs := parseScope(p.ScopeYAML); errs == nil {
		resp["summary"] = summarizeScope(c, sc)
	} else {
		resp["errors"] = errs
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) updateProject(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req struct {
		ScopeYAML string `json:"scope_yaml"`
	}
	if !decode(w, r, &req) {
		return
	}
	if _, _, errs := parseScope(req.ScopeYAML); errs != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "scope 검증 실패", "errors": errs})
		return
	}
	if err := s.cfg.Store.UpdateProjectScope(r.Context(), id, req.ScopeYAML); err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) deleteProject(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.cfg.Store.DeleteProject(r.Context(), id); err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) listScans(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	scans, err := s.cfg.Store.ListScans(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, scans)
}

// ---- 점검 실행 ----

type planView struct {
	InWindow     bool                `json:"in_window"`
	WindowError  string              `json:"window_error,omitempty"`
	SafeMode     bool                `json:"safe_mode"`
	RateLimit    float64             `json:"rate_limit"`
	Concurrency  int                 `json:"concurrency"`
	MaxRequests  int                 `json:"max_requests_per_target"`
	PauseOn5xx   int                 `json:"pause_on_5xx"`
	ActiveChecks bool                `json:"active_checks"`
	Jobs         int                 `json:"jobs"`
	Targets      map[string][]string `json:"targets"`
	Skipped      []string            `json:"skipped"`
}

func viewPlan(p *engine.Plan) planView {
	o := p.Options
	v := planView{
		InWindow: p.WindowErr == nil, SafeMode: o.SafeMode, RateLimit: o.RateLimit, Concurrency: o.Concurrency,
		MaxRequests: o.MaxRequestsPerTarget, PauseOn5xx: o.PauseOn5xx, ActiveChecks: o.ActiveChecks,
		Jobs: len(p.Jobs), Targets: map[string][]string{}, Skipped: append([]string{}, p.Skipped...),
	}
	if p.WindowErr != nil {
		v.WindowError = p.WindowErr.Error()
	}
	for _, t := range p.Targets {
		v.Targets[t.Name+" "+t.BaseURL.String()] = []string{}
	}
	for _, j := range p.Jobs {
		k := j.Target.Name + " " + j.Target.BaseURL.String()
		v.Targets[k] = append(v.Targets[k], j.Check.ID())
	}
	return v
}

func (s *Server) startScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProjectID int64    `json:"project_id"`
		Only      []string `json:"only"`
		Safe      bool     `json:"safe"`
		DryRun    bool     `json:"dry_run"`
		// Passwords 는 password_env 이름 -> 비밀번호다. 메모리에서만 쓰고 저장하지 않는다.
		Passwords map[string]string `json:"passwords"`
	}
	if !decode(w, r, &req) {
		return
	}
	p, err := s.cfg.Store.GetProject(r.Context(), req.ProjectID)
	if err != nil {
		storeError(w, err)
		return
	}
	cfg, _, errs := parseScope(p.ScopeYAML)
	if errs != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "scope 검증 실패", "errors": errs})
		return
	}
	if req.Safe {
		cfg.Options.SafeMode, cfg.Options.ActiveChecks = true, false
	}
	sc, err := scope.New(cfg)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	selected := checks.Select(req.Only)
	if len(selected) == 0 {
		writeError(w, http.StatusBadRequest, "선택한 점검 항목이 없음")
		return
	}
	plan, err := engine.NewPlan(sc, selected, time.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.DryRun {
		writeJSON(w, http.StatusOK, map[string]any{"plan": viewPlan(plan)})
		return
	}
	if plan.WindowErr != nil {
		writeError(w, http.StatusConflict, plan.WindowErr.Error())
		return
	}

	s.mu.Lock()
	if s.active != nil {
		busy := s.active.id
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "이미 실행 중인 점검이 있음: "+busy)
		return
	}
	// 점검은 요청과 무관하게 계속 실행되어야 하므로 요청 컨텍스트를 쓰지 않는다.
	ctx, cancel := context.WithCancel(context.Background())
	id := engine.NewScanID(time.Now())
	rn := newRun(id, cancel)
	s.active = rn
	s.runs[id] = rn
	s.mu.Unlock()

	fail := func(status int, msg string) {
		cancel()
		s.mu.Lock()
		s.active = nil
		delete(s.runs, id)
		s.mu.Unlock()
		writeError(w, status, msg)
	}

	client := transport.NewFromScope(sc, nil)
	lookup := s.cfg.LookupEnv
	if lookup == nil {
		lookup = os.LookupEnv
	}
	var auths []engine.Authenticator
	for _, a := range cfg.Auth {
		f, err := auth.New(a, client, s.cfg.Audit, func(env, _ string) (string, error) {
			if v := req.Passwords[env]; v != "" {
				return v, nil
			}
			v, _ := lookup(env)
			return v, nil
		})
		if err != nil {
			fail(http.StatusBadRequest, fmt.Sprintf("auth (%s): %v", a.Target, err))
			return
		}
		auths = append(auths, f)
	}

	if err := s.cfg.Store.StartScan(r.Context(), &store.Scan{ID: id, ProjectID: p.ID, StartedAt: time.Now(), SafeMode: plan.Options.SafeMode}); err != nil {
		fail(http.StatusInternalServerError, err.Error())
		return
	}
	// 점검은 요청이 끝난 뒤에도 계속되어야 하며 취소는 rn.cancel 로 한다.
	go s.execute(ctx, rn, engine.Options{Scope: sc, HTTP: client, Checks: selected, Audit: s.cfg.Audit, Auth: auths, ScanID: id}) //nolint:gosec // G118: 의도적
	writeJSON(w, http.StatusAccepted, map[string]any{"scan_id": id, "plan": viewPlan(plan)})
}

func (s *Server) cancelScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	rn := s.runs[id]
	running := rn != nil && s.active == rn
	s.mu.Unlock()
	if !running {
		writeError(w, http.StatusNotFound, "실행 중인 점검이 아님")
		return
	}
	rn.cancel()
	writeJSON(w, http.StatusAccepted, map[string]bool{"ok": true})
}

func (s *Server) getScan(w http.ResponseWriter, r *http.Request) {
	sc, err := s.cfg.Store.GetScan(r.Context(), r.PathValue("id"))
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"scan": sc, "result": sc.Result})
}

// scanEvents 는 SSE 로 진행 상황을 보낸다. 끝난 점검은 최종 상태 한 건만 보낸다.
func (s *Server) scanEvents(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	fl, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "스트리밍 미지원")
		return
	}
	s.mu.Lock()
	rn := s.runs[id]
	s.mu.Unlock()

	var backlog []Event
	var ch chan Event
	if rn != nil {
		backlog, ch = rn.subscribe()
		if ch != nil {
			defer rn.unsubscribe(ch)
		}
	} else {
		sc, err := s.cfg.Store.GetScan(r.Context(), id)
		if err != nil {
			storeError(w, err)
			return
		}
		backlog = []Event{{Type: "finished", Status: string(sc.Status), Error: sc.Error}}
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	send := func(e Event) {
		b, _ := json.Marshal(e)
		_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e.Type, b)
		fl.Flush()
	}
	for _, e := range backlog {
		send(e)
	}
	if ch == nil {
		return
	}
	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case e, open := <-ch:
			if !open {
				return
			}
			send(e)
		case <-keepalive.C:
			_, _ = fmt.Fprint(w, ": keepalive\n\n")
			fl.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (s *Server) finishedResult(w http.ResponseWriter, r *http.Request, id string) (*engine.Result, bool) {
	sc, err := s.cfg.Store.GetScan(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return nil, false
	}
	if sc.Result == nil {
		writeError(w, http.StatusConflict, "결과가 없는 점검 (상태: "+string(sc.Status)+")")
		return nil, false
	}
	return sc.Result, true
}

func (s *Server) scanFindings(w http.ResponseWriter, r *http.Request) {
	res, ok := s.finishedResult(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, res.Findings)
}

func (s *Server) scanReport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	f, err := report.ParseFormat(r.URL.Query().Get("format"))
	if r.URL.Query().Get("format") == "" {
		f, err = report.FormatHTML, nil
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, ok := s.finishedResult(w, r, id)
	if !ok {
		return
	}
	ctype := map[report.Format]string{
		report.FormatHTML: "text/html; charset=utf-8", report.FormatJSON: "application/json",
		report.FormatMarkdown: "text/markdown; charset=utf-8", report.FormatSARIF: "application/sarif+json",
	}[f]
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="intrasec-%s.%s"`, id, f))
	_ = report.Write(w, f, res)
}

func (s *Server) scanDiff(w http.ResponseWriter, r *http.Request) {
	a, ok := s.finishedResult(w, r, r.PathValue("a"))
	if !ok {
		return
	}
	b, ok := s.finishedResult(w, r, r.PathValue("b"))
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, report.DiffResults(a, b))
}
