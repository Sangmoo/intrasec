package report

import (
	"encoding/json"
	"io"

	"github.com/Sangmoo/intrasec/internal/engine"
	"github.com/Sangmoo/intrasec/pkg/finding"
)

// SARIF 2.1.0 최소 구조. https://docs.oasis-open.org/sarif/sarif/v2.1.0/

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	ShortDescription sarifMessage `json:"shortDescription"`
	Help             sarifMessage `json:"help"`
	Properties       sarifProps   `json:"properties"`
}

type sarifProps struct {
	Tags []string `json:"tags,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
	} `json:"physicalLocation"`
}

func sarifLevel(s finding.Severity) string {
	switch s {
	case finding.SevCritical, finding.SevHigh:
		return "error"
	case finding.SevMedium:
		return "warning"
	default:
		return "note"
	}
}

func WriteSARIF(w io.Writer, r *engine.Result) error {
	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           "intrasec",
			InformationURI: "https://github.com/Sangmoo/intrasec",
		}},
		Results: []sarifResult{},
	}
	seen := map[string]bool{}
	for _, f := range r.Findings {
		if !seen[f.CheckID] {
			seen[f.CheckID] = true
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
				ID:               f.CheckID,
				ShortDescription: sarifMessage{f.Title},
				Help:             sarifMessage{f.Remediation},
				Properties:       sarifProps{Tags: append(append([]string{}, f.CWE...), f.OWASP...)},
			})
		}
		var loc sarifLocation
		loc.PhysicalLocation.ArtifactLocation.URI = f.Target
		run.Results = append(run.Results, sarifResult{
			RuleID:    f.CheckID,
			Level:     sarifLevel(f.Severity),
			Message:   sarifMessage{f.Title + ": " + f.Description},
			Locations: []sarifLocation{loc},
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	})
}
