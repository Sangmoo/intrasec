// Package report 는 점검 결과를 JSON / Markdown / HTML / SARIF 리포트로 출력한다.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Sangmoo/intrasec/internal/engine"
)

type Format string

const (
	FormatHTML     Format = "html"
	FormatJSON     Format = "json"
	FormatMarkdown Format = "md"
	FormatSARIF    Format = "sarif"
)

// ParseFormat 은 포맷 문자열을 검증한다.
func ParseFormat(s string) (Format, error) {
	switch f := Format(strings.ToLower(s)); f {
	case FormatHTML, FormatJSON, FormatMarkdown, FormatSARIF:
		return f, nil
	case "markdown":
		return FormatMarkdown, nil
	}
	return "", fmt.Errorf("지원하지 않는 리포트 형식: %q (html|json|md|sarif)", s)
}

// FormatFromPath 는 출력 파일 확장자로 형식을 추정한다. 알 수 없으면 html.
func FormatFromPath(p string) Format {
	switch strings.ToLower(filepath.Ext(p)) {
	case ".json":
		return FormatJSON
	case ".md":
		return FormatMarkdown
	case ".sarif":
		return FormatSARIF
	}
	return FormatHTML
}

func Write(w io.Writer, f Format, r *engine.Result) error {
	switch f {
	case FormatJSON:
		return WriteJSON(w, r)
	case FormatMarkdown:
		return WriteMarkdown(w, r)
	case FormatSARIF:
		return WriteSARIF(w, r)
	default:
		return WriteHTML(w, r)
	}
}

// WriteFile 은 path 에 리포트를 쓴다.
func WriteFile(path string, f Format, r *engine.Result) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	out, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := Write(out, f, r); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// LoadResult 는 저장된 결과 JSON 을 읽는다.
func LoadResult(path string) (*engine.Result, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r engine.Result
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &r, nil
}
