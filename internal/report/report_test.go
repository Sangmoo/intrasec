package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Sangmoo/intrasec/internal/engine"
	"github.com/Sangmoo/intrasec/pkg/finding"
)

func sampleResult() *engine.Result {
	return &engine.Result{
		ScanID: "s1", Engagement: "<script>x</script>", ApprovedBy: "a", ApprovalRef: "r",
		Targets: []string{"https://app.example.local/"}, StartedAt: time.Now(), FinishedAt: time.Now(),
		Findings: []finding.Finding{{
			ID: "1", CheckID: "COMMON-HDR-001", Title: "CSP 누락", Severity: finding.SevMedium,
			Target: "https://app.example.local/", CWE: []string{"CWE-693"},
			Evidence: finding.Evidence{Request: "GET / HTTP/1.1", Response: "HTTP/1.1 200 OK"},
		}},
	}
}

func TestAllFormats(t *testing.T) {
	for _, f := range []Format{FormatHTML, FormatJSON, FormatMarkdown, FormatSARIF} {
		var buf bytes.Buffer
		if err := Write(&buf, f, sampleResult()); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if !strings.Contains(buf.String(), "COMMON-HDR-001") {
			t.Errorf("%s: 발견 항목 누락", f)
		}
	}
}

func TestHTMLEscapes(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHTML(&buf, sampleResult()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "<script>x</script>") {
		t.Fatal("HTML 이스케이프 누락")
	}
}

func TestSARIFValid(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, sampleResult()); err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(buf.Bytes(), &v); err != nil || v["version"] != "2.1.0" {
		t.Fatalf("SARIF 형식 오류: %v", err)
	}
}

func TestDiffResults(t *testing.T) {
	f := func(id string) finding.Finding { return finding.Finding{ID: id, CheckID: id, Severity: finding.SevLow} }
	d := DiffResults(
		&engine.Result{ScanID: "a", Findings: []finding.Finding{f("x"), f("y")}},
		&engine.Result{ScanID: "b", Findings: []finding.Finding{f("y"), f("z")}},
	)
	if len(d.New) != 1 || d.New[0].ID != "z" || len(d.Resolved) != 1 || d.Resolved[0].ID != "x" || len(d.Unchanged) != 1 {
		t.Fatalf("diff 이상: %+v", d)
	}
}
