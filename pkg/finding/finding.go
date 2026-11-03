// Package finding 은 점검 결과(Finding) 모델을 정의한다. 외부 공개 API.
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"time"
)

type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// Rank 는 심각도 정렬용 순위를 반환한다 (높을수록 심각).
func (s Severity) Rank() int {
	switch s {
	case SevCritical:
		return 4
	case SevHigh:
		return 3
	case SevMedium:
		return 2
	case SevLow:
		return 1
	default:
		return 0
	}
}

// Severities 는 심각한 순서의 전체 심각도 목록이다.
var Severities = []Severity{SevCritical, SevHigh, SevMedium, SevLow, SevInfo}

type Finding struct {
	ID          string    `json:"id"`
	CheckID     string    `json:"check_id"`
	Title       string    `json:"title"`
	Severity    Severity  `json:"severity"`
	Target      string    `json:"target"`
	Evidence    Evidence  `json:"evidence"`
	CWE         []string  `json:"cwe,omitempty"`
	OWASP       []string  `json:"owasp,omitempty"`
	KISA        []string  `json:"kisa,omitempty"`
	Description string    `json:"description"`
	Remediation string    `json:"remediation"`
	FoundAt     time.Time `json:"found_at"`
}

type Evidence struct {
	Request  string `json:"request,omitempty"`
	Response string `json:"response,omitempty"`
	Note     string `json:"note,omitempty"`
}

// StableID 는 CheckID와 Target으로 결정적인 ID를 만든다.
// 동일 항목이 점검 간에 같은 ID를 가지므로 diff 비교에 사용할 수 있다.
func StableID(checkID, target string) string {
	sum := sha256.Sum256([]byte(checkID + "\x00" + target))
	return hex.EncodeToString(sum[:8])
}

// Sort 는 심각도 내림차순, CheckID, Target 순으로 정렬한다.
func Sort(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Severity.Rank() != fs[j].Severity.Rank() {
			return fs[i].Severity.Rank() > fs[j].Severity.Rank()
		}
		if fs[i].CheckID != fs[j].CheckID {
			return fs[i].CheckID < fs[j].CheckID
		}
		return fs[i].Target < fs[j].Target
	})
}

// CountBySeverity 는 심각도별 건수를 센다.
func CountBySeverity(fs []Finding) map[Severity]int {
	m := make(map[Severity]int, len(Severities))
	for _, f := range fs {
		m[f.Severity]++
	}
	return m
}
