package scanners

import (
	"context"
)

// Scanner defines the interface implemented by all target inspection modules.
type Scanner interface {
	// Name returns the unique identifier of the scanner.
	Name() string

	// Description returns a short human-readable summary of what the scanner inspects.
	Description() string

	// Scan performs discovery and data collection on the specified target.
	// Returns a structured artifact payload or an error.
	Scan(ctx context.Context, target string) (interface{}, error)
}
