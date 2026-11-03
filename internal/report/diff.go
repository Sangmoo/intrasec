package report

import (
	"github.com/Sangmoo/intrasec/internal/engine"
	"github.com/Sangmoo/intrasec/pkg/finding"
)

// Diff 는 두 점검 결과의 비교다. 발견 항목은 StableID(CheckID+Target)로 대응시킨다.
type Diff struct {
	Base      string            `json:"base"`      // 이전 점검 ID
	Head      string            `json:"head"`      // 이후 점검 ID
	New       []finding.Finding `json:"new"`       // 이후에만 있음 (신규)
	Resolved  []finding.Finding `json:"resolved"`  // 이전에만 있음 (조치됨)
	Unchanged []finding.Finding `json:"unchanged"` // 양쪽 모두 (미조치)
}

// DiffResults 는 base(이전) 대비 head(이후)의 변화를 계산한다.
func DiffResults(base, head *engine.Result) Diff {
	d := Diff{Base: base.ScanID, Head: head.ScanID, New: []finding.Finding{}, Resolved: []finding.Finding{}, Unchanged: []finding.Finding{}}
	key := func(f finding.Finding) string {
		if f.ID != "" {
			return f.ID
		}
		return finding.StableID(f.CheckID, f.Target)
	}
	before := map[string]bool{}
	for _, f := range base.Findings {
		before[key(f)] = true
	}
	after := map[string]bool{}
	for _, f := range head.Findings {
		after[key(f)] = true
		if before[key(f)] {
			d.Unchanged = append(d.Unchanged, f)
		} else {
			d.New = append(d.New, f)
		}
	}
	for _, f := range base.Findings {
		if !after[key(f)] {
			d.Resolved = append(d.Resolved, f)
		}
	}
	finding.Sort(d.New)
	finding.Sort(d.Resolved)
	finding.Sort(d.Unchanged)
	return d
}
