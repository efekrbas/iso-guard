package reporters

import (
	"fmt"
	"io"
	"strings"

	"github.com/efekrbas/iso-guard/engine"
)

// Reporter defines the output generator interface.
type Reporter interface {
	Report(report *engine.ScanReport, w io.Writer) error
}

// GetReporter returns the requested reporter implementation by format name.
func GetReporter(format string, colorEnabled bool) (Reporter, error) {
	switch strings.ToLower(format) {
	case "console", "table", "term", "":
		return NewConsoleReporter(colorEnabled), nil
	case "json":
		return NewJSONReporter(), nil
	case "markdown", "md":
		return NewMarkdownReporter(), nil
	default:
		return nil, fmt.Errorf("unsupported report format %q. Supported formats: console, json, markdown", format)
	}
}
