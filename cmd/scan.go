package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/efekrbas/iso-guard/engine"
	"github.com/efekrbas/iso-guard/reporters"
	"github.com/efekrbas/iso-guard/scanners"
	"github.com/efekrbas/iso-guard/scanners/file"
	"github.com/efekrbas/iso-guard/scanners/network"
	"github.com/efekrbas/iso-guard/scanners/system"
	"github.com/spf13/cobra"
)

var (
	targetFlag    string
	formatFlag    string
	outputFile    string
	severityFlag  string
	enableNetwork bool
	failOnFlag    string
	timeoutSec    int
)

var scanCmd = &cobra.Command{
	Use:   "scan [target]",
	Short: "Perform an ISO/IEC 27001 technical controls audit on a target",
	Long: `Scans the specified target directory or system against ISO/IEC 27001:2022
technical controls (e.g., A.8.12 Data Leakage, A.8.24 Cryptography, A.8.9 Configuration).

Examples:
  iso-guard scan .
  iso-guard scan ./my-project --format markdown --output audit-report.md
  iso-guard scan . --fail-on HIGH
  iso-guard scan . --format json
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		target := "."
		if len(args) > 0 {
			target = args[0]
		} else if targetFlag != "" {
			target = targetFlag
		} else if AppConfig.Target.Path != "" {
			target = AppConfig.Target.Path
		}

		// Apply flag overrides to configuration
		if formatFlag != "" {
			AppConfig.Report.Format = formatFlag
		}
		if outputFile != "" {
			lowerOut := strings.ToLower(outputFile)
			if lowerOut == "json" {
				AppConfig.Report.Format = "json"
				AppConfig.Report.OutputFile = "" // write JSON to stdout
			} else if lowerOut == "markdown" || lowerOut == "md" {
				AppConfig.Report.Format = "markdown"
				AppConfig.Report.OutputFile = "" // write Markdown to stdout
			} else if strings.HasSuffix(lowerOut, ".json") {
				if formatFlag == "" || formatFlag == "console" {
					AppConfig.Report.Format = "json"
				}
				AppConfig.Report.OutputFile = outputFile
			} else if strings.HasSuffix(lowerOut, ".md") || strings.HasSuffix(lowerOut, ".markdown") {
				if formatFlag == "" || formatFlag == "console" {
					AppConfig.Report.Format = "markdown"
				}
				AppConfig.Report.OutputFile = outputFile
			} else {
				AppConfig.Report.OutputFile = outputFile
			}
		}
		if severityFlag != "" {
			AppConfig.Rules.MinSeverity = strings.ToUpper(severityFlag)
		}
		if failOnFlag != "" {
			AppConfig.Rules.FailOnSeverity = strings.ToUpper(failOnFlag)
		}
		if enableNetwork {
			AppConfig.Scanners.EnableNetwork = true
		}

		// Configure active scanners
		var activeScanners []scanners.Scanner
		if AppConfig.Scanners.EnableFileSystem {
			activeScanners = append(activeScanners, file.NewScanner(AppConfig.Target.ExcludeDirs))
		}
		if AppConfig.Scanners.EnableSystem {
			activeScanners = append(activeScanners, system.NewScanner())
		}
		if AppConfig.Scanners.EnableNetwork {
			activeScanners = append(activeScanners, network.NewScanner(300*time.Millisecond))
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
		defer cancel()

		auditEngine := engine.NewEngine(AppConfig, engine.DefaultRegistry(), activeScanners)

		if AppConfig.Report.Verbose {
			fmt.Printf("Starting audit against target: %s\n", target)
		}

		report, err := auditEngine.Run(ctx, target)
		if err != nil {
			return fmt.Errorf("audit execution failed: %w", err)
		}

		// Select reporter
		reporter, err := reporters.GetReporter(AppConfig.Report.Format, AppConfig.Report.Color)
		if err != nil {
			return err
		}

		// Prepare output stream
		var writer io.Writer = os.Stdout
		if AppConfig.Report.OutputFile != "" {
			f, err := os.Create(AppConfig.Report.OutputFile)
			if err != nil {
				return fmt.Errorf("could not create output file: %w", err)
			}
			defer f.Close()
			writer = f
		}

		if err := reporter.Report(report, writer); err != nil {
			return fmt.Errorf("reporting failed: %w", err)
		}

		if AppConfig.Report.OutputFile != "" {
			fmt.Printf("Audit report written successfully to: %s\n", AppConfig.Report.OutputFile)
		}

		// Check failure threshold for CI/CD gates
		if AppConfig.Rules.FailOnSeverity != "" {
			failWeight := engine.Severity(AppConfig.Rules.FailOnSeverity).Weight()
			if failWeight > 0 {
				for _, res := range report.Results {
					if res.Status == engine.StatusFail && res.Severity.Weight() >= failWeight {
						return fmt.Errorf("audit check failed: violation with severity %s found (%s: %s)", res.Severity, res.RuleID, res.Title)
					}
				}
			}
		}

		return nil
	},
}

func init() {
	scanCmd.Flags().StringVarP(&targetFlag, "target", "t", "", "Target directory or system to scan (default: current directory)")
	scanCmd.Flags().StringVarP(&formatFlag, "format", "f", "console", "Output format: console, json, markdown")
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write output report to file instead of stdout")
	scanCmd.Flags().StringVarP(&severityFlag, "severity", "s", "", "Minimum severity to evaluate (CRITICAL, HIGH, MEDIUM, LOW)")
	scanCmd.Flags().StringVar(&failOnFlag, "fail-on", "", "Exit with error if findings at or above this severity are detected")
	scanCmd.Flags().BoolVar(&enableNetwork, "network", false, "Enable network port scanner for boundary checking")
	scanCmd.Flags().IntVar(&timeoutSec, "timeout", 60, "Scan timeout in seconds")

	rootCmd.AddCommand(scanCmd)
}
