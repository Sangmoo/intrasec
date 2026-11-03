// Package checks 는 점검 플러그인 인터페이스와 등록소를 정의한다.
package checks

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/Sangmoo/intrasec/internal/transport"
	"github.com/Sangmoo/intrasec/pkg/finding"
)

type Level int

const (
	Passive Level = iota
	Active
)

func (l Level) String() string {
	if l == Active {
		return "active"
	}
	return "passive"
}

// TagCommon 태그를 가진 점검은 대상의 태그와 무관하게 모든 대상에 실행된다.
const TagCommon = "common"

// Target 은 점검 대상 하나다.
type Target struct {
	Name    string
	BaseURL *url.URL
	Tags    []string
}

// Session 은 점검 실행 중 플러그인에 주어지는 공유 자원이다.
// 플러그인은 반드시 HTTP 로만 요청해야 하며 자체 클라이언트를 만들면 안 된다.
type Session struct {
	HTTP *transport.Client
	// Safe 는 운영 안전 모드 여부다. true 면 플러그인은 경로 탐색 등 부가 요청을 최소화해야 한다.
	// (요청 속도·상한·active 금지는 엔진과 transport 가 별도로 강제한다)
	Safe bool

	notFound sync.Map // 대상 base URL -> *Page (soft 404 기준선)
}

type Check interface {
	ID() string
	Name() string
	Level() Level
	Tags() []string
	Run(ctx context.Context, t Target, s *Session) ([]finding.Finding, error)
}

var (
	mu       sync.RWMutex
	registry = map[string]Check{}
)

// Register 는 init() 에서 호출한다. ID 중복 시 panic.
func Register(c Check) {
	mu.Lock()
	defer mu.Unlock()
	if _, dup := registry[c.ID()]; dup {
		panic(fmt.Sprintf("checks: 중복 ID %s", c.ID()))
	}
	registry[c.ID()] = c
}

// All 은 등록된 점검을 ID 순으로 반환한다.
func All() []Check {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Check, 0, len(registry))
	for _, c := range registry {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

// Select 는 --only 값(태그 또는 ID 접두사, 대소문자 무시)으로 점검을 고른다. 비어 있으면 전체.
func Select(only []string) []Check {
	all := All()
	if len(only) == 0 {
		return all
	}
	var out []Check
	for _, c := range all {
		if matchAny(c, only) {
			out = append(out, c)
		}
	}
	return out
}

func matchAny(c Check, only []string) bool {
	for _, o := range only {
		o = strings.ToLower(strings.TrimSpace(o))
		if o == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(c.ID()), o) {
			return true
		}
		for _, t := range c.Tags() {
			if strings.EqualFold(t, o) {
				return true
			}
		}
	}
	return false
}

// AppliesTo 는 점검이 대상에 적용되는지 판단한다.
func AppliesTo(c Check, t Target) bool {
	for _, ct := range c.Tags() {
		if ct == TagCommon {
			return true
		}
		for _, tt := range t.Tags {
			if strings.EqualFold(ct, tt) {
				return true
			}
		}
	}
	return false
}
