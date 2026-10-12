package policy

import (
	"fmt"
	"strings"

	"github.com/efekrbas/iso-guard/engine"
)

// AssertionType defines the validation mechanism used in the policy.
type AssertionType string

const (
	AssertFileExists       AssertionType = "file_exists"
	AssertFileNotExists    AssertionType = "file_not_exists"
	AssertRegexMatch       AssertionType = "regex_match"
	AssertDisallowPatterns AssertionType = "disallow_patterns"
	AssertPermissionMax    AssertionType = "permission_max"
)

// Assertion defines a single declarative validation check.
type Assertion struct {
	Type        AssertionType `yaml:"type" json:"type"`
	Pattern     string        `yaml:"pattern,omitempty" json:"pattern,omitempty"`
	Patterns    []string      `yaml:"patterns,omitempty" json:"patterns,omitempty"`
	MinValue    *int          `yaml:"min_value,omitempty" json:"min_value,omitempty"`
	MaxValue    *int          `yaml:"max_value,omitempty" json:"max_value,omitempty"`
	MaxModeOctal string       `yaml:"max_mode_octal,omitempty" json:"max_mode_octal,omitempty"` // e.g. "0640"
	Message     string        `yaml:"message" json:"message"`
}

// PolicySpec describes the target matching criteria and assertions to run.
type PolicySpec struct {
	TargetType       string      `yaml:"target_type" json:"target_type"` // "file", "content", "git", "system"
	MatchFiles       []string    `yaml:"match_files,omitempty" json:"match_files,omitempty"`
	RequireFiles     []string    `yaml:"require_files,omitempty" json:"require_files,omitempty"`
	AlternativeFiles []string    `yaml:"alternative_files,omitempty" json:"alternative_files,omitempty"`
	ExcludeFiles     []string    `yaml:"exclude_files,omitempty" json:"exclude_files,omitempty"`
	Assertions       []Assertion `yaml:"assertions" json:"assertions"`
}

// Policy represents a declarative ISO 27001 audit rule defined in YAML.
type Policy struct {
	ID          string          `yaml:"id" json:"id"`                     // e.g. "ISO-A.9.4.2" or "ISO-A.5.17"
	ControlID   string          `yaml:"control_id" json:"control_id"`     // ISO 27001 Annex A control ID (e.g. "A.5.17")
	Title       string          `yaml:"title" json:"title"`               // Rule title
	Description string          `yaml:"description" json:"description"`   // Full description
	Category    string          `yaml:"category" json:"category"`         // e.g. "Technological Controls"
	Severity    engine.Severity `yaml:"severity" json:"severity"`         // CRITICAL, HIGH, MEDIUM, LOW
	Enabled     bool            `yaml:"enabled" json:"enabled"`           // Is active
	Tags        []string        `yaml:"tags,omitempty" json:"tags,omitempty"`
	Remediation string          `yaml:"remediation" json:"remediation"`   // Guided steps to fix
	Spec        PolicySpec      `yaml:"spec" json:"spec"`                 // Validation specs
}

// Validate checks that the policy contains all required fields.
func (p *Policy) Validate() error {
	if strings.TrimSpace(p.ID) == "" {
		return fmt.Errorf("policy id cannot be empty")
	}
	if strings.TrimSpace(p.ControlID) == "" {
		return fmt.Errorf("policy %s: control_id cannot be empty (must map to ISO 27001 Annex A clause)", p.ID)
	}
	if strings.TrimSpace(p.Title) == "" {
		return fmt.Errorf("policy %s: title cannot be empty", p.ID)
	}
	if p.Severity.Weight() == 0 {
		return fmt.Errorf("policy %s: invalid severity %q (allowed: CRITICAL, HIGH, MEDIUM, LOW, INFO)", p.ID, p.Severity)
	}
	if len(p.Spec.Assertions) == 0 {
		return fmt.Errorf("policy %s: at least one assertion must be defined in spec", p.ID)
	}
	return nil
}

// PolicyFile represents the root structure of a YAML policy definition file.
type PolicyFile struct {
	Version  string    `yaml:"version" json:"version"`
	Policies []Policy  `yaml:"policies" json:"policies"`
}
