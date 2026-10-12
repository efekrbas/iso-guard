package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/efekrbas/iso-guard/engine"
	"github.com/spf13/cobra"
)

var (
	filterCategory string
	filterSeverity string
	outputFormat   string
)

var listRulesCmd = &cobra.Command{
	Use:   "list-rules",
	Short: "List all registered ISO/IEC 27001 audit rules and controls",
	Long:  "Displays all built-in and configured ISO/IEC 27001 controls with their IDs, severities, and descriptions.",
	RunE: func(cmd *cobra.Command, args []string) error {
		reg := engine.DefaultRegistry()

		var minSev engine.Severity
		if filterSeverity != "" {
			minSev = engine.Severity(strings.ToUpper(filterSeverity))
		}

		rules := reg.Filter(filterCategory, minSev, nil)

		if strings.ToLower(outputFormat) == "json" {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(rules)
		}

		fmt.Println("Available ISO/IEC 27001:2022 Technical Controls:")
		fmt.Printf("%-10s %-28s %-10s %-25s %s\n", "CONTROL", "RULE ID", "SEVERITY", "CATEGORY", "TITLE")
		fmt.Println(strings.Repeat("-", 100))

		for _, r := range rules {
			fmt.Printf("%-10s %-28s %-10s %-25s %s\n",
				r.ControlID,
				r.ID,
				r.Severity,
				truncate(r.Category, 24),
				r.Title,
			)
			if verbose {
				fmt.Printf("   Description: %s\n", r.Description)
				if len(r.Tags) > 0 {
					fmt.Printf("   Tags: [%s]\n", strings.Join(r.Tags, ", "))
				}
				fmt.Println()
			}
		}

		fmt.Printf("\nTotal Rules: %d\n", len(rules))
		return nil
	},
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max-3] + "..."
	}
	return s
}

func init() {
	listRulesCmd.Flags().StringVarP(&filterCategory, "category", "C", "", "Filter rules by category")
	listRulesCmd.Flags().StringVarP(&filterSeverity, "severity", "s", "", "Filter rules by minimum severity (CRITICAL, HIGH, MEDIUM, LOW)")
	listRulesCmd.Flags().StringVarP(&outputFormat, "format", "f", "table", "Output format (table, json)")

	rootCmd.AddCommand(listRulesCmd)
}
