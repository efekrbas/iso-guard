package reporters_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/efekrbas/iso-guard/engine"
	"github.com/efekrbas/iso-guard/reporters"
)

func sampleReport() *engine.ScanReport {
	return &engine.ScanReport{
		Target:    "/path/to/project",
		Profile:   "iso-27001-2022",
		Timestamp: time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC),
		Environment: engine.Environment{
			OS:          "linux",
			Arch:        "amd64",
			Hostname:    "audit-host-01",
			ToolVersion: "v0.1.0",
		},
		Summary: engine.ScanSummary{
			TotalRules:      4,
			Passed:          2,
			Failed:          1,
			Warnings:        1,
			Skipped:         0,
			CriticalCount:   1,
			ComplianceScore: 62.5,
			Duration:        150 * time.Millisecond,
		},
		Results: []engine.RuleResult{
			{
				RuleID:      "ISO-A.8.12-SECRETS",
				ControlID:   "A.8.12",
				Title:       "Data Leakage Prevention: Plaintext Secrets",
				Category:    "Technological Controls",
				Severity:    engine.SeverityCritical,
				Status:      engine.StatusFail,
				Message:     "Detected unencrypted secret keys in .env",
				Remediation: "Remove .env from source control and store credentials in HashiCorp Vault.",
				Details: map[string]interface{}{
					"exposed_file": ".env",
				},
			},
			{
				RuleID:      "ISO-A.8.24-CRYPTOGRAPHY",
				ControlID:   "A.8.24",
				Title:       "Use of Cryptography: Weak Ciphers",
				Category:    "Technological Controls",
				Severity:    engine.SeverityHigh,
				Status:      engine.StatusWarn,
				Message:     "Legacy TLS 1.0 protocol enabled in config",
				Remediation: "Enforce TLS 1.3 or TLS 1.2 minimum with modern forward-secrecy ciphers.",
			},
			{
				RuleID:    "ISO-A.5.15-ACCESS-CONTROL",
				ControlID: "A.5.15",
				Title:     "Access Control: Least Privilege User",
				Category:  "Organizational Controls",
				Severity:  engine.SeverityLow,
				Status:    engine.StatusPass,
				Message:   "Application operates under non-privileged account",
			},
			{
				RuleID:    "ISO-A.8.9-CONFIG-MANAGEMENT",
				ControlID: "A.8.9",
				Title:     "Configuration Management: Restrict Permissions",
				Category:  "Technological Controls",
				Severity:  engine.SeverityMedium,
				Status:    engine.StatusPass,
				Message:   "File permissions conform to security baseline",
			},
		},
	}
}

func TestJSONReporter(t *testing.T) {
	rep := reporters.NewJSONReporter()
	report := sampleReport()

	var buf bytes.Buffer
	err := rep.Report(report, &buf)
	if err != nil {
		t.Fatalf("JSONReporter.Report failed: %v", err)
	}

	var parsed engine.ScanReport
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}

	if parsed.Summary.TotalRules != 4 {
		t.Errorf("Expected 4 total rules in JSON, got %d", parsed.Summary.TotalRules)
	}

	if parsed.Summary.ComplianceScore != 62.5 {
		t.Errorf("Expected compliance score 62.5%% in JSON, got %.1f%%", parsed.Summary.ComplianceScore)
	}

	// Verify remediation steps are serialized
	foundRemediation := false
	for _, res := range parsed.Results {
		if res.RuleID == "ISO-A.8.12-SECRETS" && strings.Contains(res.Remediation, "HashiCorp Vault") {
			foundRemediation = true
			break
		}
	}

	if !foundRemediation {
		t.Errorf("Remediation steps for failed control not found in JSON report")
	}
}

func TestMarkdownReporter(t *testing.T) {
	rep := reporters.NewMarkdownReporter()
	report := sampleReport()

	var buf bytes.Buffer
	err := rep.Report(report, &buf)
	if err != nil {
		t.Fatalf("MarkdownReporter.Report failed: %v", err)
	}

	output := buf.String()

	// Check Title and Executive Summary
	if !strings.Contains(output, "ISO/IEC 27001:2022 Technical Security Controls Audit Report") {
		t.Errorf("Markdown report missing main header")
	}

	// Check Compliance Score KPI
	if !strings.Contains(output, "62.5%") {
		t.Errorf("Markdown report missing compliance score 62.5%%")
	}

	// Check Total Controls count
	if !strings.Contains(output, "**Total Controls Evaluated** | **4**") {
		t.Errorf("Markdown report missing total controls count table row")
	}

	// Check Remediation Section & Steps
	if !strings.Contains(output, "Remediation Action Plan") {
		t.Errorf("Markdown report missing Remediation Action Plan section")
	}

	if !strings.Contains(output, "HashiCorp Vault") {
		t.Errorf("Markdown report missing concrete remediation text for ISO-A.8.12-SECRETS")
	}

	if !strings.Contains(output, "Auditor Sign-Off & Verification") {
		t.Errorf("Markdown report missing Auditor Sign-Off section")
	}
}

func TestGetReporter(t *testing.T) {
	_, err := reporters.GetReporter("json", false)
	if err != nil {
		t.Errorf("Expected json reporter, got error: %v", err)
	}

	_, err = reporters.GetReporter("markdown", false)
	if err != nil {
		t.Errorf("Expected markdown reporter, got error: %v", err)
	}

	_, err = reporters.GetReporter("console", true)
	if err != nil {
		t.Errorf("Expected console reporter, got error: %v", err)
	}

	_, err = reporters.GetReporter("unknown-format", false)
	if err == nil {
		t.Errorf("Expected error for unknown format, got nil")
	}
}
