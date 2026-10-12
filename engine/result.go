package engine

import (
	"strings"
	"time"
)

// Severity represents the risk level of a finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Weight returns a numeric weight for severity sorting and scoring.
func (s Severity) Weight() int {
	switch strings.ToUpper(string(s)) {
	case string(SeverityCritical):
		return 5
	case string(SeverityHigh):
		return 4
	case string(SeverityMedium):
		return 3
	case string(SeverityLow):
		return 2
	case string(SeverityInfo):
		return 1
	default:
		return 0
	}
}

// Status represents the outcome of an evaluated rule.
type Status string

const (
	StatusPass Status = "PASS"
	StatusFail Status = "FAIL"
	StatusWarn Status = "WARN"
	StatusSkip Status = "SKIP"
)

// RuleResult holds the result of a single evaluated rule.
type RuleResult struct {
	RuleID      string                 `json:"rule_id"`
	ControlID   string                 `json:"control_id"` // e.g. "A.8.12"
	Title       string                 `json:"title"`
	Category    string                 `json:"category"`
	Severity    Severity               `json:"severity"`
	Status      Status                 `json:"status"`
	Message     string                 `json:"message"`
	Remediation string                 `json:"remediation,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
	Duration    time.Duration          `json:"duration"`
}

// ScanSummary aggregates metrics from a scan run.
type ScanSummary struct {
	TotalRules      int           `json:"total_rules"`
	Passed          int           `json:"passed"`
	Failed          int           `json:"failed"`
	Warnings        int           `json:"warnings"`
	Skipped         int           `json:"skipped"`
	CriticalCount   int           `json:"critical_count"`
	HighCount       int           `json:"high_count"`
	MediumCount     int           `json:"medium_count"`
	LowCount        int           `json:"low_count"`
	ComplianceScore float64       `json:"compliance_score"` // Percentage: 0.0 - 100.0%
	Duration        time.Duration `json:"duration"`
}

// ScanReport represents the final output of an audit scan.
type ScanReport struct {
	Target      string       `json:"target"`
	Profile     string       `json:"profile"`
	Timestamp   time.Time    `json:"timestamp"`
	Summary     ScanSummary  `json:"summary"`
	Results     []RuleResult `json:"results"`
	Environment Environment  `json:"environment"`
}

// Environment contains contextual runtime details of the scan.
type Environment struct {
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	Hostname    string `json:"hostname"`
	ToolVersion string `json:"tool_version"`
}
