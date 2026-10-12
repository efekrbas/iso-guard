package cmd

import (
	"fmt"
	"os"

	"github.com/efekrbas/iso-guard/config"
	"github.com/efekrbas/iso-guard/engine"
	"github.com/efekrbas/iso-guard/engine/policy"
	"github.com/efekrbas/iso-guard/rules"
	"github.com/spf13/cobra"
)

var (
	cfgFile      string
	policiesPath string
	verbose      bool
	noColor      bool

	// AppConfig stores loaded configuration
	AppConfig *config.Config

	// rootCmd represents the base command
	rootCmd = &cobra.Command{
		Use:   "iso-guard",
		Short: "iso-guard is an automated ISO/IEC 27001 technical controls auditor",
		Long: `iso-guard is a modular CLI security tool designed to audit, verify,
and report on ISO/IEC 27001:2022 technical & organizational controls across
codebases, configuration files, and system environments.

Example:
  iso-guard scan .
  iso-guard scan --policies policies/
  iso-guard scan --format markdown --output audit-report.md
  iso-guard list-rules --severity HIGH
`,
	}
)

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.SilenceUsage = true

	// Global persistent flags
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "Path to configuration file (default: iso-guard.yaml)")
	rootCmd.PersistentFlags().StringVarP(&policiesPath, "policies", "p", "", "Path to YAML policy file or directory (default: policies/)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "Disable color output")
}

func initConfig() {
	// Initialize default ISO 27001 rules
	rules.InitDefaultRules()

	// Load configuration
	cfg, err := config.LoadConfig(cfgFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not load config file: %v\n", err)
		AppConfig = config.DefaultConfig()
	} else {
		AppConfig = cfg
	}

	if verbose {
		AppConfig.Report.Verbose = true
	}
	if noColor {
		AppConfig.Report.Color = false
	}

	// Auto-load YAML policies
	loadYAMLPolicies()
}

func loadYAMLPolicies() {
	pDir := policiesPath
	if pDir == "" && AppConfig != nil {
		pDir = AppConfig.Rules.PoliciesPath
	}
	if pDir == "" {
		pDir = "policies"
	}

	if stat, err := os.Stat(pDir); err == nil {
		policyEng := policy.NewPolicyEngine(nil)
		var loaded []*policy.Policy
		if stat.IsDir() {
			loaded, err = policyEng.LoadFromDir(pDir)
		} else {
			loaded, err = policyEng.LoadFromFile(pDir)
		}
		if err == nil && len(loaded) > 0 {
			_ = policyEng.RegisterToEngineRegistry(engine.DefaultRegistry())
			if verbose {
				fmt.Printf("Loaded %d YAML policies from %s\n", len(loaded), pDir)
			}
		}
	}
}
