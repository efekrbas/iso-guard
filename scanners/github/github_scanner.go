package github

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/efekrbas/iso-guard/scanners"
)

// Scanner implements scanners.Scanner for GitHub repository and organization audits.
type Scanner struct {
	Client         *APIClient
	MaxFilesToRead int
}

// NewScanner creates a new GitHub Scanner.
func NewScanner(token string) *Scanner {
	return &Scanner{
		Client:         NewAPIClient(token),
		MaxFilesToRead: 30, // Default limit to conserve API rate limits
	}
}

func (s *Scanner) Name() string {
	return "github"
}

func (s *Scanner) Description() string {
	return "Audits GitHub repository branch protection rules (ISO A.12.1.2/A.14.2.1) and sensitive data leaks (ISO A.12.6.1)"
}

// BranchProtectionFinding represents the audit outcome of a branch's protection policies.
type BranchProtectionFinding struct {
	Branch            string   `json:"branch"`
	ProtectionEnabled bool     `json:"protection_enabled"`
	RequiredReviews   int      `json:"required_reviews"`
	EnforceAdmins     bool     `json:"enforce_admins"`
	RequireCodeOwners bool     `json:"require_code_owners"`
	DismissStale      bool     `json:"dismiss_stale"`
	StatusChecks      bool     `json:"status_checks"`
	Status            string   `json:"status"` // PASS, FAIL, WARN
	Message           string   `json:"message"`
	Remediation       string   `json:"remediation,omitempty"`
	Details           []string `json:"details,omitempty"`
}

// SecretLeakFinding represents detected secrets or sensitive files in the repository.
type SecretLeakFinding struct {
	Path        string `json:"path"`
	Type        string `json:"type"` // "sensitive_filename", "secret_regex"
	Description string `json:"description"`
	LineSnippet string `json:"line_snippet,omitempty"`
}

// SecretScanFinding represents the overall secret scanning outcome.
type SecretScanFinding struct {
	FilesScanned int                 `json:"files_scanned"`
	Findings     []SecretLeakFinding `json:"findings"`
	Status       string              `json:"status"` // PASS, FAIL, WARN
	Message      string              `json:"message"`
	Remediation  string              `json:"remediation,omitempty"`
}

// RepoAuditResult aggregates all ISO 27001 checks for a specific GitHub repository.
type RepoAuditResult struct {
	Owner            string                  `json:"owner"`
	Repo             string                  `json:"repo"`
	DefaultBranch    string                  `json:"default_branch"`
	IsPrivate        bool                    `json:"is_private"`
	BranchProtection BranchProtectionFinding `json:"branch_protection"`
	SecretScan       SecretScanFinding       `json:"secret_scan"`
	Duration         time.Duration           `json:"duration"`
	Error            string                  `json:"error,omitempty"`
}

// GitHubArtifact is the final output payload returned by the scanner.
type GitHubArtifact struct {
	Target       string            `json:"target"`
	IsOrg        bool              `json:"is_org"`
	Repositories []RepoAuditResult `json:"repositories"`
	ScanDuration time.Duration     `json:"scan_duration"`
}

// Regex patterns for secret detection
var secretPatterns = []struct {
	Name    string
	Pattern *regexp.Regexp
}{
	{
		Name:    "AWS Access Key ID",
		Pattern: regexp.MustCompile(`(?i)\b(AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b`),
	},
	{
		Name:    "GitHub Personal Access Token",
		Pattern: regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9_]{36,}\b`),
	},
	{
		Name:    "Private Cryptographic Key",
		Pattern: regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`),
	},
	{
		Name:    "Generic API Key / Secret Token",
		Pattern: regexp.MustCompile(`(?i)\b(api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token)\s*[:=]\s*['"][a-zA-Z0-9_\-.~!@#$%^&*()+=]{12,}['"]`),
	},
	{
		Name:    "Hardcoded Password in Config",
		Pattern: regexp.MustCompile(`(?i)\b(password|passwd|pwd)\s*[:=]\s*['"][^'"]{6,}['"]`),
	},
}

// Sensitive file names
var sensitiveFileNames = []string{
	".env",
	".env.local",
	".env.production",
	".env.staging",
	"id_rsa",
	"id_ed25519",
	"credentials.json",
	"service-account.json",
	"client_secret.json",
	".htpasswd",
	"secrets.yaml",
	"secrets.json",
}

// Scan audits the given target (e.g. "owner/repo", "https://github.com/owner/repo", or "org:name").
func (s *Scanner) Scan(ctx context.Context, target string) (interface{}, error) {
	startTime := time.Now()
	artifact := &GitHubArtifact{
		Target:       target,
		Repositories: make([]RepoAuditResult, 0),
	}

	owner, repo, isOrg, err := parseGitHubTarget(target)
	if err != nil {
		return artifact, err
	}
	artifact.IsOrg = isOrg

	if isOrg {
		repos, err := s.Client.ListOrgRepositories(ctx, owner)
		if err != nil {
			return artifact, fmt.Errorf("failed to list repositories for organization %s: %w", owner, err)
		}

		for _, r := range repos {
			if r.Archived {
				continue // Skip archived repos
			}
			repoResult := s.auditSingleRepo(ctx, owner, r.Name, r.DefaultBranch, r.Private)
			artifact.Repositories = append(artifact.Repositories, repoResult)
		}
	} else {
		repoMeta, err := s.Client.GetRepository(ctx, owner, repo)
		if err != nil {
			return artifact, err
		}
		repoResult := s.auditSingleRepo(ctx, owner, repo, repoMeta.DefaultBranch, repoMeta.Private)
		artifact.Repositories = append(artifact.Repositories, repoResult)
	}

	artifact.ScanDuration = time.Since(startTime)
	return artifact, nil
}

func (s *Scanner) auditSingleRepo(ctx context.Context, owner, repo, defaultBranch string, isPrivate bool) RepoAuditResult {
	start := time.Now()
	if defaultBranch == "" {
		defaultBranch = "main"
	}

	result := RepoAuditResult{
		Owner:         owner,
		Repo:          repo,
		DefaultBranch: defaultBranch,
		IsPrivate:     isPrivate,
	}

	// 1. Audit Branch Protection (ISO A.12.1.2 / A.14.2.1 / A.8.28)
	bpFinding := s.auditBranchProtection(ctx, owner, repo, defaultBranch)
	result.BranchProtection = bpFinding

	// 2. Audit Sensitive Data & Secrets (ISO A.12.6.1 / A.8.12)
	secFinding := s.auditSecrets(ctx, owner, repo, defaultBranch)
	result.SecretScan = secFinding

	result.Duration = time.Since(start)
	return result
}

func (s *Scanner) auditBranchProtection(ctx context.Context, owner, repo, branch string) BranchProtectionFinding {
	finding := BranchProtectionFinding{
		Branch: branch,
	}

	bp, err := s.Client.GetBranchProtection(ctx, owner, repo, branch)
	if err != nil {
		if rateErr, ok := err.(*RateLimitError); ok {
			finding.Status = "WARN"
			finding.Message = rateErr.Error()
			return finding
		}
		if strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "403") {
			finding.Status = "WARN"
			finding.Message = "Branch protection verification requires a GitHub token with repository administration/read permissions."
			finding.Remediation = "Provide a Personal Access Token via --token or GITHUB_TOKEN env var (requires 'repo' or 'administration:read' scope)."
			return finding
		}
		finding.Status = "WARN"
		finding.Message = fmt.Sprintf("Could not verify branch protection: %v", err)
		return finding
	}

	if bp == nil {
		// HTTP 404: Branch protection not configured at all
		finding.ProtectionEnabled = false
		finding.Status = "FAIL"
		finding.Message = fmt.Sprintf("Branch protection is NOT enabled on default branch %q (Violation of ISO A.12.1.2 / A.14.2.1).", branch)
		finding.Remediation = fmt.Sprintf("Enable branch protection for %q in GitHub Settings -> Branches. Enforce at least 1 approving pull request review before merging.", branch)
		return finding
	}

	finding.ProtectionEnabled = true
	var details []string

	// Check Pull Request Reviews
	if bp.RequiredReviews != nil {
		finding.RequiredReviews = bp.RequiredReviews.RequiredApprovingReviewCount
		finding.RequireCodeOwners = bp.RequiredReviews.RequireCodeOwnerReviews
		finding.DismissStale = bp.RequiredReviews.DismissStaleReviews

		details = append(details, fmt.Sprintf("Required PR Approvals: %d", finding.RequiredReviews))
		if finding.RequireCodeOwners {
			details = append(details, "Code Owners review required: YES")
		} else {
			details = append(details, "Code Owners review required: NO")
		}
		if finding.DismissStale {
			details = append(details, "Dismiss stale reviews on push: YES")
		}
	} else {
		details = append(details, "Required PR Approvals: 0 (No review required)")
	}

	// Check Admin enforcement
	if bp.EnforceAdmins != nil && bp.EnforceAdmins.Enabled {
		finding.EnforceAdmins = true
		details = append(details, "Include administrators: ENFORCED")
	} else {
		finding.EnforceAdmins = false
		details = append(details, "Include administrators: NOT ENFORCED (Admins can bypass rules)")
	}

	// Check CI status checks
	if bp.RequiredStatusCheck != nil && len(bp.RequiredStatusCheck.Contexts) > 0 {
		finding.StatusChecks = true
		details = append(details, fmt.Sprintf("Required status checks: %d checks active", len(bp.RequiredStatusCheck.Contexts)))
	} else {
		finding.StatusChecks = false
	}

	finding.Details = details

	// Evaluate status
	if finding.RequiredReviews >= 1 {
		if !finding.EnforceAdmins {
			finding.Status = "WARN"
			finding.Message = fmt.Sprintf("Branch protection active on %q (%d PR approvals required), but administrator bypass is not prevented.", branch, finding.RequiredReviews)
			finding.Remediation = "Check 'Do not allow bypassing the above settings' (Enforce Admins) in branch protection settings to maintain strict separation of duties."
		} else {
			finding.Status = "PASS"
			finding.Message = fmt.Sprintf("Branch protection fully compliant on %q with %d required PR approvals and admin enforcement.", branch, finding.RequiredReviews)
		}
	} else {
		finding.Status = "FAIL"
		finding.Message = fmt.Sprintf("Branch protection is enabled on %q, but requires 0 PR approvals. Direct merges or unreviewed commits are permitted.", branch)
		finding.Remediation = "Configure 'Require a pull request before merging' and set 'Require approvals' to at least 1 in branch protection settings."
	}

	return finding
}

func (s *Scanner) auditSecrets(ctx context.Context, owner, repo, branch string) SecretScanFinding {
	finding := SecretScanFinding{
		Findings: make([]SecretLeakFinding, 0),
	}

	// Fetch recursive Git Tree
	treeResp, err := s.Client.GetTree(ctx, owner, repo, branch)
	if err != nil {
		if rateErr, ok := err.(*RateLimitError); ok {
			finding.Status = "WARN"
			finding.Message = rateErr.Error()
			return finding
		}
		finding.Status = "WARN"
		finding.Message = fmt.Sprintf("Failed to retrieve file tree: %v", err)
		return finding
	}

	// 1. Inspect file names for sensitive credential artifacts
	filesToInspectContent := make([]string, 0)
	for _, entry := range treeResp.Tree {
		if entry.Type != "blob" {
			continue
		}
		finding.FilesScanned++

		baseName := filepath.Base(entry.Path)
		baseLower := strings.ToLower(baseName)

		// Check sensitive file names
		for _, sens := range sensitiveFileNames {
			if strings.EqualFold(baseLower, sens) {
				finding.Findings = append(finding.Findings, SecretLeakFinding{
					Path:        entry.Path,
					Type:        "sensitive_filename",
					Description: fmt.Sprintf("Exposed sensitive file: %s", baseName),
				})
				break
			}
		}

		// Collect text/config files for regex inspection (filter by extension & size < 100KB)
		if isScannableExtension(entry.Path) && entry.Size > 0 && entry.Size < 100*1024 {
			if len(filesToInspectContent) < s.MaxFilesToRead {
				filesToInspectContent = append(filesToInspectContent, entry.Path)
			}
		}
	}

	// 2. Perform regex pattern scanning on selected candidate files
	for _, filePath := range filesToInspectContent {
		select {
		case <-ctx.Done():
			break
		default:
		}

		content, err := s.Client.GetFileContent(ctx, owner, repo, filePath, branch)
		if err != nil {
			continue // Gracefully skip unreadable files
		}

		lines := strings.Split(string(content), "\n")
		for lineIdx, line := range lines {
			trimmed := strings.TrimSpace(line)
			if len(trimmed) == 0 || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
				continue
			}

			for _, p := range secretPatterns {
				if loc := p.Pattern.FindStringIndex(trimmed); loc != nil {
					snippet := trimmed
					if len(snippet) > 80 {
						snippet = snippet[:77] + "..."
					}
					// Mask middle characters of snippet for safety
					masked := maskSecretInSnippet(snippet)

					finding.Findings = append(finding.Findings, SecretLeakFinding{
						Path:        fmt.Sprintf("%s:%d", filePath, lineIdx+1),
						Type:        "secret_regex",
						Description: fmt.Sprintf("Detected %s", p.Name),
						LineSnippet: masked,
					})
					break
				}
			}
		}
	}

	if len(finding.Findings) > 0 {
		finding.Status = "FAIL"
		finding.Message = fmt.Sprintf("Found %d sensitive file or secret token leaks in repository (Violation of ISO A.12.6.1 / A.8.12).", len(finding.Findings))
		finding.Remediation = "Revoke exposed API keys and credentials immediately, rotate tokens, purge sensitive files from git history using git-filter-repo, and add files to .gitignore."
	} else {
		finding.Status = "PASS"
		finding.Message = fmt.Sprintf("No exposed sensitive files or secret patterns detected across %d scanned files.", finding.FilesScanned)
	}

	return finding
}

func isScannableExtension(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	scannable := map[string]bool{
		".env":        true,
		".yaml":       true,
		".yml":        true,
		".json":       true,
		".toml":       true,
		".properties": true,
		".conf":       true,
		".config":     true,
		".sh":         true,
		".py":         true,
		".js":         true,
		".ts":         true,
		".go":         true,
	}
	return scannable[ext] || strings.Contains(strings.ToLower(path), ".env")
}

func maskSecretInSnippet(s string) string {
	if len(s) <= 12 {
		return "***"
	}
	return s[:6] + "..." + s[len(s)-4:]
}

func parseGitHubTarget(target string) (owner string, repo string, isOrg bool, err error) {
	trimmed := strings.TrimSpace(target)
	trimmed = strings.TrimPrefix(trimmed, "https://github.com/")
	trimmed = strings.TrimPrefix(trimmed, "http://github.com/")
	trimmed = strings.TrimPrefix(trimmed, "git@github.com:")
	trimmed = strings.TrimSuffix(trimmed, ".git")
	trimmed = strings.Trim(trimmed, "/")

	if strings.HasPrefix(strings.ToLower(trimmed), "org:") {
		orgName := strings.TrimPrefix(trimmed, "org:")
		orgName = strings.TrimPrefix(orgName, "ORG:")
		return orgName, "", true, nil
	}

	parts := strings.Split(trimmed, "/")
	if len(parts) == 1 {
		// Single name: assume organization or user
		return parts[0], "", true, nil
	}
	if len(parts) == 2 {
		return parts[0], parts[1], false, nil
	}

	return "", "", false, fmt.Errorf("invalid GitHub target format %q. Expected 'owner/repo', 'https://github.com/owner/repo', or 'org:<name>'", target)
}

var _ scanners.Scanner = (*Scanner)(nil)
