package report

import (
	"encoding/json"
	"io"

	"github.com/Sangmoo/intrasec/internal/engine"
)

func WriteJSON(w io.Writer, r *engine.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
