package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/efekrbas/iso-guard/scanners/github"
	"github.com/spf13/cobra"
)

var (
	githubToken    string
	maxFilesToRead int
	githubFormat   string
	githubOutput   string
)

var scanGitHubCmd = &cobra.Command{
	Use:   "scan-github [target]",
	Short: "Audit a GitHub repository or organization against ISO 27001 technical controls",
	Long: `Audits GitHub repository settings and code trees against ISO 27001 controls:
  - ISO A.12.1.2 / A.14.2.1: Branch Protection & Required PR Reviews
  - ISO A.12.6.1 / A.8.12: Sensitive Data and Secret Token Leakage Prevention

Examples:
  iso-guard scan-github owner/repository
  iso-guard scan-github https://github.com/owner/repository --token ghp_xxxx
  iso-guard scan-github org:my-organization
  iso-guard scan-github owner/repo --format json --output gh-audit.json
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("target is required (e.g. 'owner/repo', 'https://github.com/owner/repo', or 'org:<name>')")
		}

		target := args[0]
		scanner := github.NewScanner(githubToken)
		if maxFilesToRead > 0 {
			scanner.MaxFilesToRead = maxFilesToRead
		}

		fmt.Printf("\nConnecting to GitHub and initializing ISO 27001 audit on %q...\n", target)

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()

		rawArtifact, err := scanner.Scan(ctx, target)
		if err != nil {
			return fmt.Errorf("GitHub scan failed: %w", err)
		}

		artifact, ok := rawArtifact.(*github.GitHubArtifact)
		if !ok {
			return fmt.Errorf("unexpected artifact type from scanner")
		}

		// Handle JSON output if requested
		if strings.ToLower(githubFormat) == "json" {
			var writer io.Writer = os.Stdout
			if githubOutput != "" {
				f, err := os.Create(githubOutput)
				if err != nil {
					return err
				}
				defer f.Close()
				writer = f
			}
			enc := json.NewEncoder(writer)
			enc.SetIndent("", "  ")
			return enc.Encode(artifact)
		}

		// Console output
		renderGitHubConsoleReport(artifact)

		if githubOutput != "" {
			f, err := os.Create(githubOutput)
			if err != nil {
				return err
			}
			defer f.Close()
			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			_ = enc.Encode(artifact)
			fmt.Printf("Audit report exported to %s\n", githubOutput)
		}

		return nil
	},
}

func renderGitHubConsoleReport(artifact *github.GitHubArtifact) {
	bold := "\033[1m"
	reset := "\033[0m"
	green := "\033[32m"
	red := "\033[31m"
	yellow := "\033[33m"
	cyan := "\033[36m"
	dim := "\033[2m"

	passedCount := 0
	failedCount := 0
	warningCount := 0

	fmt.Printf("\n%s=================== GITHUB ISO 27001 AUDIT REPORT ===================%s\n", bold, reset)
	fmt.Printf("Target        : %s\n", cyan+artifact.Target+reset)
	fmt.Printf("Repositories  : %d\n", len(artifact.Repositories))
	fmt.Printf("Scan Duration : %s\n\n", artifact.ScanDuration.Round(time.Millisecond))

	for idx, repo := range artifact.Repositories {
		visibility := "Public"
		if repo.IsPrivate {
			visibility = "Private"
		}

		fmt.Printf("%s[%d/%d] Repository: %s/%s (%s | Default Branch: %s)%s\n",
			bold, idx+1, len(artifact.Repositories), repo.Owner, repo.Repo, visibility, repo.DefaultBranch, reset)
		fmt.Println(strings.Repeat("-", 80))

		// 1. Branch Protection Check
		bp := repo.BranchProtection
		bpBadge := formatStatusBadge(bp.Status, green, red, yellow, reset, bold)
		switch bp.Status {
		case "PASS":
			passedCount++
		case "FAIL":
			failedCount++
		case "WARN":
			warningCount++
		}

		fmt.Printf("  %s %sISO A.12.1.2 / A.14.2.1%s: Branch Protection (%s)\n",
			bpBadge, cyan, reset, bp.Branch)
		fmt.Printf("      %s%s%s\n", dim, bp.Message, reset)

		for _, d := range bp.Details {
			fmt.Printf("         • %s\n", d)
		}
		if bp.Remediation != "" {
			fmt.Printf("      %s Remediation: %s\n", yellow+"->"+reset, bp.Remediation)
		}

		// 2. Secret Leakage Check
		sec := repo.SecretScan
		secBadge := formatStatusBadge(sec.Status, green, red, yellow, reset, bold)
		switch sec.Status {
		case "PASS":
			passedCount++
		case "FAIL":
			failedCount++
		case "WARN":
			warningCount++
		}

		fmt.Printf("\n  %s %sISO A.12.6.1 / A.8.12%s: Sensitive Data & Secret Leakage Prevention\n",
			secBadge, cyan, reset)
		fmt.Printf("      %s%s%s\n", dim, sec.Message, reset)

		if len(sec.Findings) > 0 {
			fmt.Printf("      %sDetected Violations:%s\n", red+bold, reset)
			for _, f := range sec.Findings {
				snippet := ""
				if f.LineSnippet != "" {
					snippet = fmt.Sprintf(" [Snippet: %s]", f.LineSnippet)
				}
				fmt.Printf("         • %s: %s%s\n", f.Path, f.Description, snippet)
			}
		}

		if sec.Remediation != "" {
			fmt.Printf("      %s Remediation: %s\n", yellow+"->"+reset, sec.Remediation)
		}

		fmt.Println()
	}

	totalChecks := passedCount + failedCount + warningCount
	score := 100.0
	if totalChecks > 0 {
		score = (float64(passedCount) + 0.5*float64(warningCount)) / float64(totalChecks) * 100.0
	}

	scoreColor := green
	if score < 70 {
		scoreColor = red
	} else if score < 90 {
		scoreColor = yellow
	}

	fmt.Printf("%s========================== COMPLIANCE SUMMARY ==========================%s\n", bold, reset)
	fmt.Printf("Total Checks Evaluated : %d\n", totalChecks)
	fmt.Printf("Passed Checks          : %s%d%s\n", green, passedCount, reset)
	fmt.Printf("Failed Checks          : %s%d%s\n", red, failedCount, reset)
	fmt.Printf("Warnings               : %s%d%s\n", yellow, warningCount, reset)
	fmt.Printf("------------------------------------------------------------------------\n")
	fmt.Printf("ISO 27001 Compliance Score: %s%.1f%%%s\n", bold+scoreColor, score, reset)
	fmt.Printf("%s========================================================================%s\n\n", bold, reset)
}

func formatStatusBadge(status, green, red, yellow, reset, bold string) string {
	switch status {
	case "PASS":
		return fmt.Sprintf("%s\033[42m PASSED %s", bold, reset)
	case "FAIL":
		return fmt.Sprintf("%s\033[41m FAILED %s", bold, reset)
	case "WARN":
		return fmt.Sprintf("%s\033[43m WARNING %s", bold, reset)
	default:
		return fmt.Sprintf("[%s]", status)
	}
}

func init() {
	scanGitHubCmd.Flags().StringVarP(&githubToken, "token", "t", "", "GitHub Personal Access Token (defaults to GITHUB_TOKEN env var)")
	scanGitHubCmd.Flags().IntVar(&maxFilesToRead, "max-files", 30, "Maximum candidate files to fetch and scan for secrets")
	scanGitHubCmd.Flags().StringVarP(&githubFormat, "format", "f", "console", "Output format: console, json")
	scanGitHubCmd.Flags().StringVarP(&githubOutput, "output", "o", "", "Export results to a file")

	rootCmd.AddCommand(scanGitHubCmd)
}
