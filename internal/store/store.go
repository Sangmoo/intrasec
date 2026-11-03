// Package store 는 modernc.org/sqlite(순수 Go) 기반 로컬 저장소다.
// 프로젝트(scope 설정)와 점검 실행 결과를 저장한다. 테스트 계정 비밀번호는 저장하지 않는다.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // database/sql 드라이버 등록

	"github.com/Sangmoo/intrasec/internal/engine"
)

var ErrNotFound = errors.New("없음")

type Status string

const (
	StatusRunning     Status = "running"
	StatusDone        Status = "done"
	StatusFailed      Status = "failed"
	StatusCanceled    Status = "canceled"
	StatusInterrupted Status = "interrupted" // 실행 중 프로그램이 종료됨
)

type Project struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	ScopeYAML string    `json:"scope_yaml"`
	CreatedAt time.Time `json:"created_at"`
}

type Scan struct {
	ID         string         `json:"id"`
	ProjectID  int64          `json:"project_id"`
	Status     Status         `json:"status"`
	SafeMode   bool           `json:"safe_mode"`
	StartedAt  time.Time      `json:"started_at"`
	FinishedAt *time.Time     `json:"finished_at,omitempty"`
	Error      string         `json:"error,omitempty"`
	Summary    map[string]int `json:"summary,omitempty"` // 심각도별 건수
	Result     *engine.Result `json:"-"`
}

type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS projects (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	name       TEXT NOT NULL UNIQUE,
	scope_yaml TEXT NOT NULL,
	created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
	id          TEXT PRIMARY KEY,
	project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
	status      TEXT NOT NULL,
	safe_mode   INTEGER NOT NULL DEFAULT 0,
	started_at  TEXT NOT NULL,
	finished_at TEXT,
	error       TEXT NOT NULL DEFAULT '',
	summary     TEXT NOT NULL DEFAULT '{}',
	result      TEXT
);
CREATE INDEX IF NOT EXISTS scans_project ON scans(project_id, started_at);
`

// Open 은 DB 파일을 열고(없으면 생성) 스키마를 적용한다.
// 이전 실행에서 끝나지 않은 점검은 interrupted 로 바꾼다.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("스키마 적용 실패: %w", err)
	}
	if _, err := db.Exec(`UPDATE scans SET status = ? WHERE status = ?`, StatusInterrupted, StatusRunning); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) CreateProject(ctx context.Context, name, scopeYAML string) (*Project, error) {
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `INSERT INTO projects(name, scope_yaml, created_at) VALUES (?, ?, ?)`,
		name, scopeYAML, now.Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return &Project{ID: id, Name: name, ScopeYAML: scopeYAML, CreatedAt: now}, nil
}

func (s *Store) UpdateProjectScope(ctx context.Context, id int64, scopeYAML string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE projects SET scope_yaml = ? WHERE id = ?`, scopeYAML, id)
	if err != nil {
		return err
	}
	return mustAffect(res)
}

func (s *Store) ListProjects(ctx context.Context) ([]Project, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, scope_yaml, created_at FROM projects ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []Project{}
	for rows.Next() {
		var p Project
		var created string
		if err := rows.Scan(&p.ID, &p.Name, &p.ScopeYAML, &created); err != nil {
			return nil, err
		}
		p.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetProject(ctx context.Context, id int64) (*Project, error) {
	var p Project
	var created string
	err := s.db.QueryRowContext(ctx, `SELECT id, name, scope_yaml, created_at FROM projects WHERE id = ?`, id).
		Scan(&p.ID, &p.Name, &p.ScopeYAML, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	return &p, nil
}

func (s *Store) DeleteProject(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM projects WHERE id = ?`, id)
	if err != nil {
		return err
	}
	return mustAffect(res)
}

// StartScan 은 실행 중 상태의 점검을 기록한다.
func (s *Store) StartScan(ctx context.Context, sc *Scan) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO scans(id, project_id, status, safe_mode, started_at) VALUES (?, ?, ?, ?, ?)`,
		sc.ID, sc.ProjectID, StatusRunning, sc.SafeMode, sc.StartedAt.UTC().Format(time.RFC3339Nano))
	return err
}

// FinishScan 은 상태와 결과를 저장한다. res 가 nil 이면 결과 없이 상태만 바꾼다.
func (s *Store) FinishScan(ctx context.Context, id string, st Status, res *engine.Result, errMsg string) error {
	var resJSON sql.NullString
	summary := "{}"
	if res != nil {
		b, err := json.Marshal(res)
		if err != nil {
			return err
		}
		resJSON = sql.NullString{String: string(b), Valid: true}
		sb, _ := json.Marshal(summarize(res))
		summary = string(sb)
	}
	r, err := s.db.ExecContext(ctx, `UPDATE scans SET status = ?, finished_at = ?, error = ?, summary = ?, result = ? WHERE id = ?`,
		st, time.Now().UTC().Format(time.RFC3339Nano), errMsg, summary, resJSON, id)
	if err != nil {
		return err
	}
	return mustAffect(r)
}

func summarize(res *engine.Result) map[string]int {
	m := map[string]int{}
	for _, f := range res.Findings {
		m[string(f.Severity)]++
	}
	return m
}

const scanCols = `id, project_id, status, safe_mode, started_at, finished_at, error, summary`

func scanRow(sc interface{ Scan(...any) error }, withResult bool) (*Scan, error) {
	var s Scan
	var started string
	var finished sql.NullString
	var summary string
	var result sql.NullString
	dest := []any{&s.ID, &s.ProjectID, &s.Status, &s.SafeMode, &started, &finished, &s.Error, &summary}
	if withResult {
		dest = append(dest, &result)
	}
	if err := sc.Scan(dest...); err != nil {
		return nil, err
	}
	s.StartedAt, _ = time.Parse(time.RFC3339Nano, started)
	if finished.Valid {
		t, _ := time.Parse(time.RFC3339Nano, finished.String)
		s.FinishedAt = &t
	}
	_ = json.Unmarshal([]byte(summary), &s.Summary)
	if result.Valid {
		var r engine.Result
		if err := json.Unmarshal([]byte(result.String), &r); err != nil {
			return nil, fmt.Errorf("결과 JSON 손상 (%s): %w", s.ID, err)
		}
		s.Result = &r
	}
	return &s, nil
}

// ListScans 는 프로젝트의 점검 목록을 최신순으로 반환한다 (결과 본문 제외).
func (s *Store) ListScans(ctx context.Context, projectID int64) ([]Scan, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+scanCols+` FROM scans WHERE project_id = ? ORDER BY started_at DESC`, projectID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []Scan{}
	for rows.Next() {
		sc, err := scanRow(rows, false)
		if err != nil {
			return nil, err
		}
		out = append(out, *sc)
	}
	return out, rows.Err()
}

// GetScan 은 결과 본문을 포함해 점검 하나를 반환한다.
func (s *Store) GetScan(ctx context.Context, id string) (*Scan, error) {
	sc, err := scanRow(s.db.QueryRowContext(ctx, `SELECT `+scanCols+`, result FROM scans WHERE id = ?`, id), true)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return sc, err
}

func mustAffect(r sql.Result) error {
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
