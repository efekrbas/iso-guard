package engine

import (
	"context"
	"time"
)

// ScanContext provides scan-time context and collected artifacts to rules.
type ScanContext struct {
	Context   context.Context
	Target    string
	Artifacts map[string]interface{}
	Config    interface{}
	StartTime time.Time
}

// NewScanContext initializes a fresh ScanContext.
func NewScanContext(ctx context.Context, target string) *ScanContext {
	return &ScanContext{
		Context:   ctx,
		Target:    target,
		Artifacts: make(map[string]interface{}),
		StartTime: time.Now(),
	}
}

// RuleEvaluator is the function signature for executing a rule.
type RuleEvaluator func(ctx *ScanContext) RuleResult

// Rule represents a single ISO 27001 audit control check.
type Rule struct {
	ID             string        `json:"id"`              // e.g. "ISO-A.8.12-SECRETS"
	ControlID      string        `json:"control_id"`      // e.g. "A.8.12"
	Title          string        `json:"title"`           // Human readable title
	Description    string        `json:"description"`     // Explanation of the check
	Category       string        `json:"category"`        // e.g. "Technological Controls", "Organizational"
	Severity       Severity      `json:"severity"`        // CRITICAL, HIGH, MEDIUM, LOW, INFO
	DefaultEnabled bool          `json:"default_enabled"` // Enabled by default
	Tags           []string      `json:"tags"`            // e.g. ["credentials", "filesystem", "leakage"]
	Evaluate       RuleEvaluator `json:"-"`
}
