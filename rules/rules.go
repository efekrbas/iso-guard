package rules

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/efekrbas/iso-guard/engine"
	"github.com/efekrbas/iso-guard/scanners/file"
	"github.com/efekrbas/iso-guard/scanners/network"
	"github.com/efekrbas/iso-guard/scanners/system"
)

// InitDefaultRules registers all standard ISO/IEC 27001:2022 rules into the default registry.
func InitDefaultRules() {
	reg := engine.DefaultRegistry()

	// A.8.12 - Data Leakage Prevention
	reg.MustRegister(engine.Rule{
		ID:             "ISO-A.8.12-SECRETS",
		ControlID:      "A.8.12",
		Title:          "Data Leakage Prevention: Detect Plaintext Secrets & Credentials",
		Description:    "Prevents leakage of sensitive credentials, API keys, and environment files in target directory.",
		Category:       "Technological Controls",
		Severity:       engine.SeverityCritical,
		DefaultEnabled: true,
		Tags:           []string{"leakage", "secrets", "credentials", "filesystem"},
		Evaluate:       evaluateSensitiveFiles,
	})

	// A.8.24 - Use of Cryptography (Private Keys)
	reg.MustRegister(engine.Rule{
		ID:             "ISO-A.8.24-PRIVATE-KEYS",
		ControlID:      "A.8.24",
		Title:          "Use of Cryptography: Unencrypted Private Keys in Storage",
		Description:    "Validates that cryptographic private keys (.pem, .key, id_rsa) are not left unprotected.",
		Category:       "Technological Controls",
		Severity:       engine.SeverityHigh,
		DefaultEnabled: true,
		Tags:           []string{"cryptography", "keys", "pki"},
		Evaluate:       evaluatePrivateKeys,
	})

	// A.8.9 - Configuration Management (Permissive File Modes)
	reg.MustRegister(engine.Rule{
		ID:             "ISO-A.8.9-PERMISSIONS",
		ControlID:      "A.8.9",
		Title:          "Configuration Management: Insecure File Permissions",
		Description:    "Ensures files and configuration templates do not have world-writable or overly permissive access flags.",
		Category:       "Technological Controls",
		Severity:       engine.SeverityMedium,
		DefaultEnabled: true,
		Tags:           []string{"configuration", "permissions", "filesystem"},
		Evaluate:       evaluateInsecurePermissions,
	})

	// A.8.9 - Configuration Management (Exposed Secrets in Env)
	reg.MustRegister(engine.Rule{
		ID:             "ISO-A.8.9-ENV-SECRETS",
		ControlID:      "A.8.9",
		Title:          "Configuration Management: Environment Variable Hygiene",
		Description:    "Detects dangerous secret variables loaded into the active process environment.",
		Category:       "Technological Controls",
		Severity:       engine.SeverityHigh,
		DefaultEnabled: true,
		Tags:           []string{"configuration", "environment", "system"},
		Evaluate:       evaluateEnvSecrets,
	})

	// A.5.15 - Access Control (Privileged User Separation)
	reg.MustRegister(engine.Rule{
		ID:             "ISO-A.5.15-PRIVILEGES",
		ControlID:      "A.5.15",
		Title:          "Access Control: Least Privilege User Context",
		Description:    "Verifies audit and operational workloads respect least-privilege principles and do not run as root unnecessarily.",
		Category:       "Organizational Controls",
		Severity:       engine.SeverityLow,
		DefaultEnabled: true,
		Tags:           []string{"access_control", "privilege", "system"},
		Evaluate:       evaluatePrivilegeContext,
	})

	// A.8.20 / A.8.24 - Network Security & Cryptography (Insecure Protocols)
	reg.MustRegister(engine.Rule{
		ID:             "ISO-A.8.20-CLEARTEXT-PORTS",
		ControlID:      "A.8.20",
		Title:          "Network Security: Cleartext & Insecure Protocol Ports",
		Description:    "Checks for listening services running obsolete or unencrypted communication protocols (e.g. Telnet, FTP).",
		Category:       "Technological Controls",
		Severity:       engine.SeverityHigh,
		DefaultEnabled: true,
		Tags:           []string{"network", "ports", "cleartext"},
		Evaluate:       evaluateInsecureNetworkPorts,
	})

	// A.8.7 - Protection Against Malware (Stray Executables)
	reg.MustRegister(engine.Rule{
		ID:             "ISO-A.8.7-UNEXPECTED-BINARIES",
		ControlID:      "A.8.7",
		Title:          "Protection Against Malware: Unexpected Executable Binaries",
		Description:    "Audits target workspace for unexpected binary executables (.exe, .dll, .so) in source directories.",
		Category:       "Technological Controls",
		Severity:       engine.SeverityMedium,
		DefaultEnabled: true,
		Tags:           []string{"malware", "binaries", "filesystem"},
		Evaluate:       evaluateUnexpectedBinaries,
	})
}

// evaluateSensitiveFiles evaluates A.8.12
func evaluateSensitiveFiles(ctx *engine.ScanContext) engine.RuleResult {
	artifactRaw, ok := ctx.Artifacts["filesystem"]
	if !ok {
		return engine.RuleResult{
			Status:  engine.StatusSkip,
			Message: "Filesystem scanner artifact not found",
		}
	}

	artifact, ok := artifactRaw.(*file.FileArtifact)
	if !ok {
		return engine.RuleResult{
			Status:  engine.StatusSkip,
			Message: "Invalid filesystem artifact format",
		}
	}

	var found []string
	for _, f := range artifact.SensitiveFiles {
		// Filter out cryptographic keys handled by A.8.24
		for _, tag := range f.Tags {
			if tag == "sensitive_name" {
				found = append(found, f.RelPath)
				break
			}
		}
	}

	if len(found) > 0 {
		return engine.RuleResult{
			Status:      engine.StatusFail,
			Message:     fmt.Sprintf("Found %d sensitive credential/config files that may lead to data leakage", len(found)),
			Remediation: "Remove secrets from repository, add files to .gitignore, and use a secret manager (e.g., Vault, AWS Secrets Manager).",
			Details: map[string]interface{}{
				"sensitive_files": found,
			},
		}
	}

	return engine.RuleResult{
		Status:  engine.StatusPass,
		Message: fmt.Sprintf("No exposed credential files found in %d scanned files", artifact.TotalFilesScanned),
	}
}

// evaluatePrivateKeys evaluates A.8.24
func evaluatePrivateKeys(ctx *engine.ScanContext) engine.RuleResult {
	artifactRaw, ok := ctx.Artifacts["filesystem"]
	if !ok {
		return engine.RuleResult{
			Status:  engine.StatusSkip,
			Message: "Filesystem scanner artifact not available",
		}
	}

	artifact, ok := artifactRaw.(*file.FileArtifact)
	if !ok {
		return engine.RuleResult{
			Status:  engine.StatusSkip,
			Message: "Invalid filesystem artifact format",
		}
	}

	var keys []string
	for _, f := range artifact.SensitiveFiles {
		for _, tag := range f.Tags {
			if tag == "crypto_key" {
				keys = append(keys, f.RelPath)
				break
			}
		}
	}

	if len(keys) > 0 {
		return engine.RuleResult{
			Status:      engine.StatusFail,
			Message:     fmt.Sprintf("Found %d unencrypted private key files stored in target directory", len(keys)),
			Remediation: "Do not store private keys in codebase or shared directories. Store them in Hardware Security Modules (HSM) or secure key vaults.",
			Details: map[string]interface{}{
				"key_files": keys,
			},
		}
	}

	return engine.RuleResult{
		Status:  engine.StatusPass,
		Message: "No unprotected cryptographic private keys detected in target",
	}
}

// evaluateInsecurePermissions evaluates A.8.9
func evaluateInsecurePermissions(ctx *engine.ScanContext) engine.RuleResult {
	artifactRaw, ok := ctx.Artifacts["filesystem"]
	if !ok {
		return engine.RuleResult{
			Status:  engine.StatusSkip,
			Message: "Filesystem scanner artifact not available",
		}
	}

	artifact, ok := artifactRaw.(*file.FileArtifact)
	if !ok {
		return engine.RuleResult{
			Status:  engine.StatusSkip,
			Message: "Invalid filesystem artifact format",
		}
	}

	if len(artifact.PermissiveFiles) > 0 {
		var list []string
		for _, f := range artifact.PermissiveFiles {
			list = append(list, fmt.Sprintf("%s (%s)", f.RelPath, f.ModeString))
		}

		return engine.RuleResult{
			Status:      engine.StatusFail,
			Message:     fmt.Sprintf("Detected %d files with world-writable permissions", len(list)),
			Remediation: "Restrict file permissions using chmod 640 or 600 (or restrict ACLs) to enforce secure configuration management.",
			Details: map[string]interface{}{
				"permissive_files": list,
			},
		}
	}

	return engine.RuleResult{
		Status:  engine.StatusPass,
		Message: "File permissions comply with configuration baseline standards",
	}
}

// evaluateEnvSecrets evaluates A.8.9 (Environment hygiene)
func evaluateEnvSecrets(ctx *engine.ScanContext) engine.RuleResult {
	artifactRaw, ok := ctx.Artifacts["system"]
	if !ok {
		return engine.RuleResult{
			Status:  engine.StatusSkip,
			Message: "System scanner artifact not available",
		}
	}

	artifact, ok := artifactRaw.(*system.SystemArtifact)
	if !ok {
		return engine.RuleResult{
			Status:  engine.StatusSkip,
			Message: "Invalid system artifact format",
		}
	}

	if len(artifact.ExposedEnvVars) > 0 {
		return engine.RuleResult{
			Status:      engine.StatusWarn,
			Message:     fmt.Sprintf("Detected %d environment variables that appear to contain sensitive secret values", len(artifact.ExposedEnvVars)),
			Remediation: "Ensure environment variables are loaded dynamically from a secret store or masked from process inspections.",
			Details: map[string]interface{}{
				"variables": artifact.ExposedEnvVars,
			},
		}
	}

	return engine.RuleResult{
		Status:  engine.StatusPass,
		Message: "No high-risk secret keys exposed in system environment variables",
	}
}

// evaluatePrivilegeContext evaluates A.5.15
func evaluatePrivilegeContext(ctx *engine.ScanContext) engine.RuleResult {
	artifactRaw, ok := ctx.Artifacts["system"]
	if !ok {
		return engine.RuleResult{
			Status:  engine.StatusSkip,
			Message: "System scanner artifact not available",
		}
	}

	artifact, ok := artifactRaw.(*system.SystemArtifact)
	if !ok {
		return engine.RuleResult{
			Status:  engine.StatusSkip,
			Message: "Invalid system artifact format",
		}
	}

	if artifact.IsRoot {
		return engine.RuleResult{
			Status:      engine.StatusWarn,
			Message:     fmt.Sprintf("Process running as privileged administrative user (%s)", artifact.CurrentUser),
			Remediation: "Run applications and scan utilities under a dedicated non-root service account in adherence to least privilege.",
			Details: map[string]interface{}{
				"current_user": artifact.CurrentUser,
			},
		}
	}

	return engine.RuleResult{
		Status:  engine.StatusPass,
		Message: fmt.Sprintf("Process running under non-root account: %s", artifact.CurrentUser),
	}
}

// evaluateInsecureNetworkPorts evaluates A.8.20 / A.8.24
func evaluateInsecureNetworkPorts(ctx *engine.ScanContext) engine.RuleResult {
	artifactRaw, ok := ctx.Artifacts["network"]
	if !ok {
		return engine.RuleResult{
			Status:  engine.StatusSkip,
			Message: "Network scanner disabled in current profile",
		}
	}

	artifact, ok := artifactRaw.(*network.NetworkArtifact)
	if !ok {
		return engine.RuleResult{
			Status:  engine.StatusSkip,
			Message: "Invalid network artifact format",
		}
	}

	var insecure []string
	for _, p := range artifact.OpenPorts {
		if p.IsInsecure {
			insecure = append(insecure, fmt.Sprintf("%d/%s (%s)", p.Port, p.Protocol, p.Service))
		}
	}

	if len(insecure) > 0 {
		return engine.RuleResult{
			Status:      engine.StatusFail,
			Message:     fmt.Sprintf("Found %d open ports transmitting cleartext protocols or without boundary protection", len(insecure)),
			Remediation: "Disable cleartext protocols (Telnet, FTP, unencrypted HTTP) and enforce encrypted transport protocols (SSH, HTTPS, TLS).",
			Details: map[string]interface{}{
				"insecure_open_ports": insecure,
			},
		}
	}

	return engine.RuleResult{
		Status:  engine.StatusPass,
		Message: "No high-risk cleartext network service ports detected",
	}
}

// evaluateUnexpectedBinaries evaluates A.8.7
func evaluateUnexpectedBinaries(ctx *engine.ScanContext) engine.RuleResult {
	artifactRaw, ok := ctx.Artifacts["filesystem"]
	if !ok {
		return engine.RuleResult{
			Status:  engine.StatusSkip,
			Message: "Filesystem scanner artifact not available",
		}
	}

	artifact, ok := artifactRaw.(*file.FileArtifact)
	if !ok {
		return engine.RuleResult{
			Status:  engine.StatusSkip,
			Message: "Invalid filesystem artifact format",
		}
	}

	var binaries []string
	binaryExts := []string{".exe", ".dll", ".so", ".bin", ".bat", ".vbs"}

	for _, f := range artifact.AllFiles {
		ext := strings.ToLower(filepath.Ext(f.Path))
		for _, bExt := range binaryExts {
			if ext == bExt {
				binaries = append(binaries, f.RelPath)
				break
			}
		}
	}

	if len(binaries) > 0 {
		return engine.RuleResult{
			Status:      engine.StatusWarn,
			Message:     fmt.Sprintf("Detected %d compiled binary or script files in target workspace", len(binaries)),
			Remediation: "Verify source integrity, prevent committing binary blobs into repositories, and scan with endpoint protection.",
			Details: map[string]interface{}{
				"binary_files": binaries,
			},
		}
	}

	return engine.RuleResult{
		Status:  engine.StatusPass,
		Message: "No unexpected binary executables found in target workspace",
	}
}
