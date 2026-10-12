package engine_test

import (
	"context"
	"testing"

	"github.com/efekrbas/iso-guard/config"
	"github.com/efekrbas/iso-guard/engine"
	"github.com/efekrbas/iso-guard/scanners"
)

func TestEngineEvaluation(t *testing.T) {
	reg := engine.NewRegistry()

	// Register a mock passing rule
	err := reg.Register(engine.Rule{
		ID:        "TEST-PASS-01",
		ControlID: "A.8.9",
		Title:     "Test Pass Rule",
		Severity:  engine.SeverityLow,
		Evaluate: func(ctx *engine.ScanContext) engine.RuleResult {
			return engine.RuleResult{
				Status:  engine.StatusPass,
				Message: "Passed successfully",
			}
		},
	})
	if err != nil {
		t.Fatalf("Failed to register rule: %v", err)
	}

	// Register a mock failing rule
	err = reg.Register(engine.Rule{
		ID:        "TEST-FAIL-01",
		ControlID: "A.8.12",
		Title:     "Test Fail Rule",
		Severity:  engine.SeverityHigh,
		Evaluate: func(ctx *engine.ScanContext) engine.RuleResult {
			return engine.RuleResult{
				Status:      engine.StatusFail,
				Message:     "Found secret violation",
				Remediation: "Remove secrets",
			}
		},
	})
	if err != nil {
		t.Fatalf("Failed to register rule: %v", err)
	}

	cfg := config.DefaultConfig()
	eng := engine.NewEngine(cfg, reg, []scanners.Scanner{})

	report, err := eng.Run(context.Background(), ".")
	if err != nil {
		t.Fatalf("Engine run failed: %v", err)
	}

	if report.Summary.TotalRules != 2 {
		t.Errorf("Expected 2 rules, got %d", report.Summary.TotalRules)
	}

	if report.Summary.Passed != 1 {
		t.Errorf("Expected 1 pass, got %d", report.Summary.Passed)
	}

	if report.Summary.Failed != 1 {
		t.Errorf("Expected 1 fail, got %d", report.Summary.Failed)
	}

	if report.Summary.HighCount != 1 {
		t.Errorf("Expected 1 high violation, got %d", report.Summary.HighCount)
	}

	if report.Summary.ComplianceScore != 50.0 {
		t.Errorf("Expected 50.0%% compliance score, got %.1f%%", report.Summary.ComplianceScore)
	}
}
