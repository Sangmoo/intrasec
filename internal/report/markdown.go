package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Sangmoo/intrasec/internal/engine"
	"github.com/Sangmoo/intrasec/pkg/finding"
)

func WriteMarkdown(w io.Writer, r *engine.Result) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# 보안 점검 결과: %s\n\n", r.Engagement)
	fmt.Fprintf(&b, "| 항목 | 값 |\n|---|---|\n")
	fmt.Fprintf(&b, "| 점검 ID | `%s` |\n", r.ScanID)
	fmt.Fprintf(&b, "| 승인자 | %s |\n", mdEscape(r.ApprovedBy))
	fmt.Fprintf(&b, "| 승인 근거 | %s |\n", mdEscape(r.ApprovalRef))
	fmt.Fprintf(&b, "| 점검 시각 | %s ~ %s |\n", r.StartedAt.Format(time.DateTime), r.FinishedAt.Format(time.DateTime))
	fmt.Fprintf(&b, "| 대상 | %s |\n\n", mdEscape(strings.Join(r.Targets, ", ")))

	counts := finding.CountBySeverity(r.Findings)
	b.WriteString("## 요약\n\n| 심각도 | 건수 |\n|---|---|\n")
	for _, s := range finding.Severities {
		fmt.Fprintf(&b, "| %s | %d |\n", s, counts[s])
	}
	b.WriteString("\n## 발견 항목\n\n")
	if len(r.Findings) == 0 {
		b.WriteString("발견된 항목이 없습니다.\n")
	}
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "### [%s] %s — %s\n\n", strings.ToUpper(string(f.Severity)), f.CheckID, mdEscape(f.Title))
		fmt.Fprintf(&b, "- 대상: `%s`\n", f.Target)
		if len(f.CWE)+len(f.OWASP)+len(f.KISA) > 0 {
			fmt.Fprintf(&b, "- 매핑: %s\n", strings.Join(append(append(append([]string{}, f.CWE...), f.OWASP...), f.KISA...), ", "))
		}
		fmt.Fprintf(&b, "\n%s\n\n**조치 방법**: %s\n\n", f.Description, f.Remediation)
		if f.Evidence.Note != "" {
			fmt.Fprintf(&b, "> %s\n\n", f.Evidence.Note)
		}
		if f.Evidence.Response != "" {
			fmt.Fprintf(&b, "<details><summary>근거</summary>\n\n```http\n%s\n%s\n```\n\n</details>\n\n",
				f.Evidence.Request, f.Evidence.Response)
		}
	}
	if len(r.Errors) > 0 {
		b.WriteString("## 실행 오류\n\n")
		for _, e := range r.Errors {
			fmt.Fprintf(&b, "- %s\n", mdEscape(e))
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func mdEscape(s string) string {
	return strings.NewReplacer("|", `\|`, "\n", " ").Replace(s)
}
