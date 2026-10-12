package reporters

import (
	"encoding/json"
	"io"

	"github.com/efekrbas/iso-guard/engine"
)

// JSONReporter outputs the scan report as pretty-printed JSON.
type JSONReporter struct{}

// NewJSONReporter creates a new JSONReporter.
func NewJSONReporter() *JSONReporter {
	return &JSONReporter{}
}

func (j *JSONReporter) Report(report *engine.ScanReport, w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
