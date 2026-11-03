// Package audit 는 실행자·시각·대상·점검 항목을 JSON Lines 감사 로그로 남긴다.
package audit

import (
	"encoding/json"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"sync"
	"time"
)

type Event struct {
	Time       time.Time `json:"time"`
	Actor      string    `json:"actor"`
	Host       string    `json:"host"`
	Action     string    `json:"action"` // scan.start, scan.finish, scan.denied, check.run ...
	ScanID     string    `json:"scan_id,omitempty"`
	Engagement string    `json:"engagement,omitempty"`
	Target     string    `json:"target,omitempty"`
	CheckID    string    `json:"check_id,omitempty"`
	Detail     string    `json:"detail,omitempty"`
}

type Logger struct {
	mu    sync.Mutex
	w     io.Writer
	c     io.Closer
	actor string
	host  string
}

// Open 은 path 에 append 모드로 감사 로그를 연다.
func Open(path string) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	l := New(f)
	l.c = f
	return l, nil
}

// New 는 임의의 Writer 로 로거를 만든다 (테스트용).
func New(w io.Writer) *Logger {
	l := &Logger{w: w, actor: "unknown"}
	if u, err := user.Current(); err == nil {
		l.actor = u.Username
	}
	l.host, _ = os.Hostname()
	return l
}

// Log 는 이벤트 한 건을 기록한다. nil 로거는 아무 것도 하지 않는다.
func (l *Logger) Log(e Event) {
	if l == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	e.Actor, e.Host = l.actor, l.host
	b, _ := json.Marshal(e)
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.w.Write(append(b, '\n'))
}

func (l *Logger) Close() error {
	if l == nil || l.c == nil {
		return nil
	}
	return l.c.Close()
}
