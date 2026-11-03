package report

import (
	"embed"
	"html/template"
	"io"
	"strings"
	"time"

	"github.com/Sangmoo/intrasec/internal/engine"
	"github.com/Sangmoo/intrasec/pkg/finding"
)

//go:embed templates/*.tmpl
var templateFS embed.FS

var htmlTmpl = template.Must(template.New("report.html.tmpl").Funcs(template.FuncMap{
	"upper": func(s finding.Severity) string { return strings.ToUpper(string(s)) },
	"dt":    func(t time.Time) string { return t.Format(time.DateTime) },
	"join":  strings.Join,
}).ParseFS(templateFS, "templates/report.html.tmpl"))

type sevCount struct {
	Severity finding.Severity
	Count    int
}

func WriteHTML(w io.Writer, r *engine.Result) error {
	counts := finding.CountBySeverity(r.Findings)
	summary := make([]sevCount, 0, len(finding.Severities))
	for _, s := range finding.Severities {
		summary = append(summary, sevCount{s, counts[s]})
	}
	return htmlTmpl.Execute(w, struct {
		R       *engine.Result
		Summary []sevCount
	}{r, summary})
}
