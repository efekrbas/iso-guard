package policy_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/efekrbas/iso-guard/engine"
	"github.com/efekrbas/iso-guard/engine/policy"
)

func TestLoadPoliciesFromFile(t *testing.T) {
	samplePath := filepath.Join("..", "..", "policies", "iso27001-sample-rules.yaml")
	eng := policy.NewPolicyEngine(nil)

	policies, err := eng.LoadFromFile(samplePath)
	if err != nil {
		t.Fatalf("Failed to load policy file: %v", err)
	}

	if len(policies) != 2 {
		t.Fatalf("Expected 2 policies, got %d", len(policies))
	}

	p1 := policies[0]
	if p1.ID != "ISO-A.9.4.2" {
		t.Errorf("Expected ID 'ISO-A.9.4.2', got %q", p1.ID)
	}
	if p1.ControlID != "A.5.17" {
		t.Errorf("Expected ControlID 'A.5.17', got %q", p1.ControlID)
	}
	if p1.Severity != engine.SeverityHigh {
		t.Errorf("Expected Severity HIGH, got %v", p1.Severity)
	}

	p2 := policies[1]
	if p2.ID != "ISO-A.8.28-BRANCH-PROTECTION" {
		t.Errorf("Expected ID 'ISO-A.8.28-BRANCH-PROTECTION', got %q", p2.ID)
	}
	if p2.ControlID != "A.8.28" {
		t.Errorf("Expected ControlID 'A.8.28', got %q", p2.ControlID)
	}
}

func TestPolicyEvaluationPasswordPolicy(t *testing.T) {
	tempDir := t.TempDir()

	// Create tsconfig.json to verify it is NOT falsely flagged as a password policy failure
	_ = os.WriteFile(filepath.Join(tempDir, "tsconfig.json"), []byte("{\"compilerOptions\": {\"target\": \"ES6\"}}\n"), 0644)

	// Create a test security config file with insecure password policy
	insecureConfig := "min_password_len: 6\npassword: 'admin'\n"
	err := os.WriteFile(filepath.Join(tempDir, "security.yaml"), []byte(insecureConfig), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	samplePath := filepath.Join("..", "..", "policies", "iso27001-sample-rules.yaml")
	eng := policy.NewPolicyEngine(nil)
	policies, err := eng.LoadFromFile(samplePath)
	if err != nil {
		t.Fatalf("Failed to load sample policies: %v", err)
	}

	scanCtx := engine.NewScanContext(context.Background(), tempDir)
	evaluator := policy.NewDefaultEvaluator()

	// Evaluate Password rule (first rule)
	res := evaluator.Evaluate(scanCtx, policies[0])
	if res.Status != engine.StatusFail {
		t.Errorf("Expected password rule to FAIL on insecure config, got %v", res.Status)
	}

	// Now fix the config to be compliant
	compliantConfig := "min_password_len: 16\n"
	err = os.WriteFile(filepath.Join(tempDir, "security.yaml"), []byte(compliantConfig), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	resCompliant := evaluator.Evaluate(scanCtx, policies[0])
	if resCompliant.Status != engine.StatusPass {
		t.Errorf("Expected password rule to PASS on compliant config, got %v (msg: %s)", resCompliant.Status, resCompliant.Message)
	}
}

func TestPolicyEvaluationBranchProtection(t *testing.T) {
	tempDir := t.TempDir()

	samplePath := filepath.Join("..", "..", "policies", "iso27001-sample-rules.yaml")
	eng := policy.NewPolicyEngine(nil)
	policies, err := eng.LoadFromFile(samplePath)
	if err != nil {
		t.Fatalf("Failed to load sample policies: %v", err)
	}

	scanCtx := engine.NewScanContext(context.Background(), tempDir)
	evaluator := policy.NewDefaultEvaluator()

	// Should fail initially because no CODEOWNERS or workflow exists
	res := evaluator.Evaluate(scanCtx, policies[1])
	if res.Status != engine.StatusFail {
		t.Errorf("Expected branch protection rule to FAIL when CODEOWNERS is missing, got %v", res.Status)
	}

	// Add CODEOWNERS file
	err = os.WriteFile(filepath.Join(tempDir, "CODEOWNERS"), []byte("* @security-team\n"), 0644)
	if err != nil {
		t.Fatalf("Failed to write CODEOWNERS: %v", err)
	}

	resPassing := evaluator.Evaluate(scanCtx, policies[1])
	if resPassing.Status != engine.StatusPass {
		t.Errorf("Expected branch protection rule to PASS after adding CODEOWNERS, got %v", resPassing.Status)
	}
}
