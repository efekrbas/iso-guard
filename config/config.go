package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Config represents the complete configuration structure for iso-guard.
type Config struct {
	Profile  string         `mapstructure:"profile" yaml:"profile"`
	Target   TargetConfig   `mapstructure:"target" yaml:"target"`
	Rules    RulesConfig    `mapstructure:"rules" yaml:"rules"`
	Scanners ScannersConfig `mapstructure:"scanners" yaml:"scanners"`
	Report   ReportConfig   `mapstructure:"report" yaml:"report"`
}

// TargetConfig specifies the audit target parameters.
type TargetConfig struct {
	Path        string   `mapstructure:"path" yaml:"path"`
	Type        string   `mapstructure:"type" yaml:"type"` // local, directory, system
	ExcludeDirs []string `mapstructure:"exclude_dirs" yaml:"exclude_dirs"`
}

// RulesConfig specifies rule inclusion, exclusion, and severity thresholds.
type RulesConfig struct {
	PoliciesPath      string   `mapstructure:"policies_path" yaml:"policies_path"`
	Include           []string `mapstructure:"include" yaml:"include"`
	Exclude           []string `mapstructure:"exclude" yaml:"exclude"`
	MinSeverity       string   `mapstructure:"min_severity" yaml:"min_severity"`
	FailOnSeverity    string   `mapstructure:"fail_on_severity" yaml:"fail_on_severity"`
	IncludeCategories []string `mapstructure:"include_categories" yaml:"include_categories"`
}

// ScannersConfig toggles individual scanner modules.
type ScannersConfig struct {
	EnableFileSystem bool `mapstructure:"enable_filesystem" yaml:"enable_filesystem"`
	EnableSystem     bool `mapstructure:"enable_system" yaml:"enable_system"`
	EnableNetwork    bool `mapstructure:"enable_network" yaml:"enable_network"`
}

// ReportConfig controls report formatting and output destination.
type ReportConfig struct {
	Format     string `mapstructure:"format" yaml:"format"` // console, json, markdown
	OutputFile string `mapstructure:"output_file" yaml:"output_file"`
	Color      bool   `mapstructure:"color" yaml:"color"`
	Verbose    bool   `mapstructure:"verbose" yaml:"verbose"`
}

// DefaultConfig provides sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Profile: "iso-27001-2022",
		Target: TargetConfig{
			Path: ".",
			Type: "directory",
			ExcludeDirs: []string{
				".git",
				"node_modules",
				"vendor",
				".idea",
				".vscode",
			},
		},
		Rules: RulesConfig{
			PoliciesPath:   "policies",
			MinSeverity:    "LOW",
			FailOnSeverity: "HIGH",
		},
		Scanners: ScannersConfig{
			EnableFileSystem: true,
			EnableSystem:     true,
			EnableNetwork:    false,
		},
		Report: ReportConfig{
			Format:  "console",
			Color:   true,
			Verbose: false,
		},
	}
}

// LoadConfig reads configuration from the given file path or default search paths.
func LoadConfig(cfgFile string) (*Config, error) {
	v := viper.New()

	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		v.SetConfigName("iso-guard")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("$HOME/.iso-guard")
	}

	// Environment variable overrides
	v.SetEnvPrefix("ISOGUARD")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	// Set default values in viper
	defaults := DefaultConfig()
	v.SetDefault("profile", defaults.Profile)
	v.SetDefault("target.path", defaults.Target.Path)
	v.SetDefault("target.type", defaults.Target.Type)
	v.SetDefault("target.exclude_dirs", defaults.Target.ExcludeDirs)
	v.SetDefault("rules.policies_path", defaults.Rules.PoliciesPath)
	v.SetDefault("rules.min_severity", defaults.Rules.MinSeverity)
	v.SetDefault("rules.fail_on_severity", defaults.Rules.FailOnSeverity)
	v.SetDefault("scanners.enable_filesystem", defaults.Scanners.EnableFileSystem)
	v.SetDefault("scanners.enable_system", defaults.Scanners.EnableSystem)
	v.SetDefault("scanners.enable_network", defaults.Scanners.EnableNetwork)
	v.SetDefault("report.format", defaults.Report.Format)
	v.SetDefault("report.color", defaults.Report.Color)
	v.SetDefault("report.verbose", defaults.Report.Verbose)

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok && cfgFile != "" {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}
