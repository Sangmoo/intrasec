package server

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/Sangmoo/intrasec/internal/engine"
	"github.com/Sangmoo/intrasec/internal/store"
)

// Event 는 SSE 로 보내는 점검 진행 이벤트다.
type Event struct {
	Type     string `json:"type"` // "progress" | "finished"
	Done     int    `json:"done,omitempty"`
	Total    int    `json:"total,omitempty"`
	CheckID  string `json:"check_id,omitempty"`
	Target   string `json:"target,omitempty"`
	Findings int    `json:"findings,omitempty"`
	Error    string `json:"error,omitempty"`
	Status   string `json:"status,omitempty"` // finished 이벤트의 최종 상태
}

// run 은 실행 중(또는 이번 serve 실행 중 끝난) 점검이다. 이벤트를 쌓아 두고 구독자에게 전달한다.
type run struct {
	id     string
	cancel context.CancelFunc

	mu     sync.Mutex
	events []Event
	subs   map[chan Event]struct{}
	done   bool
}

func newRun(id string, cancel context.CancelFunc) *run {
	return &run{id: id, cancel: cancel, subs: map[chan Event]struct{}{}}
}

func (r *run) publish(e Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	for ch := range r.subs {
		select {
		case ch <- e:
		default: // 느린 구독자는 건너뛴다 (재접속 시 전체 이력을 다시 받음)
		}
	}
	if e.Type == "finished" {
		r.done = true
		for ch := range r.subs {
			close(ch)
		}
		r.subs = map[chan Event]struct{}{}
	}
}

// subscribe 는 지금까지의 이벤트와, 끝나지 않았다면 이후 이벤트를 받을 채널을 돌려준다.
func (r *run) subscribe() ([]Event, chan Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	backlog := append([]Event(nil), r.events...)
	if r.done {
		return backlog, nil
	}
	ch := make(chan Event, 64)
	r.subs[ch] = struct{}{}
	return backlog, ch
}

func (r *run) unsubscribe(ch chan Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.subs[ch]; ok {
		delete(r.subs, ch)
		close(ch)
	}
}

// execute 는 점검을 백그라운드로 실행하고 결과를 저장한다.
func (s *Server) execute(ctx context.Context, r *run, opts engine.Options) {
	opts.Progress = func(p engine.Progress) {
		e := Event{Type: "progress", Done: p.Done, Total: p.Total, CheckID: p.CheckID, Target: p.Target, Findings: p.Findings}
		if p.Err != nil {
			e.Error = p.Err.Error()
		}
		r.publish(e)
	}
	res, err := engine.Run(ctx, opts)

	status, msg := store.StatusDone, ""
	switch {
	case err != nil:
		status, msg = store.StatusFailed, err.Error()
	case res.Canceled || errors.Is(ctx.Err(), context.Canceled):
		status = store.StatusCanceled
	}
	// 요청 컨텍스트와 무관하게 저장한다.
	saveCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if serr := s.cfg.Store.FinishScan(saveCtx, r.id, status, res, msg); serr != nil && msg == "" {
		msg = "결과 저장 실패: " + serr.Error()
		status = store.StatusFailed
	}

	s.mu.Lock()
	if s.active == r {
		s.active = nil
	}
	s.mu.Unlock()
	r.publish(Event{Type: "finished", Status: string(status), Error: msg})
}
