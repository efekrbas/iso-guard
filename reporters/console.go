package reporters

import (
	"fmt"
	"io"

	"github.com/efekrbas/iso-guard/engine"
)

// ConsoleReporter produces formatted terminal output.
type ConsoleReporter struct {
	EnableColor bool
}

// NewConsoleReporter creates a new ConsoleReporter.
func NewConsoleReporter(enableColor bool) *ConsoleReporter {
	return &ConsoleReporter{EnableColor: enableColor}
}

// ANSI color codes
const (
	resetBold = "\033[0m"
	bold      = "\033[1m"
	dim       = "\033[2m"
	red       = "\033[31m"
	green     = "\033[32m"
	yellow    = "\033[33m"
	blue      = "\033[34m"
	magenta   = "\033[35m"
	cyan      = "\033[36m"
	white     = "\033[37m"
	bgRed     = "\033[41m"
	bgGreen   = "\033[42m"
	bgYellow  = "\033[43m"
)

func (c *ConsoleReporter) colorize(text, code string) string {
	if !c.EnableColor {
		return text
	}
	return code + text + resetBold
}

func (c *ConsoleReporter) statusBadge(status engine.Status) string {
	if !c.EnableColor {
		return fmt.Sprintf("[%s]", status)
	}
	switch status {
	case engine.StatusPass:
		return fmt.Sprintf("%s%s PASS %s", bold, bgGreen, resetBold)
	case engine.StatusFail:
		return fmt.Sprintf("%s%s FAIL %s", bold, bgRed, resetBold)
	case engine.StatusWarn:
		return fmt.Sprintf("%s%s WARN %s", bold, bgYellow, resetBold)
	case engine.StatusSkip:
		return fmt.Sprintf("%s[SKIP]%s", dim, resetBold)
	default:
		return string(status)
	}
}

func (c *ConsoleReporter) severityBadge(sev engine.Severity) string {
	s := string(sev)
	if !c.EnableColor {
		return fmt.Sprintf("(%s)", s)
	}
	switch sev {
	case engine.SeverityCritical:
		return fmt.Sprintf("%s%s[%s]%s", bold, red, s, resetBold)
	case engine.SeverityHigh:
		return fmt.Sprintf("%s[%s]%s", red, s, resetBold)
	case engine.SeverityMedium:
		return fmt.Sprintf("%s[%s]%s", yellow, s, resetBold)
	case engine.SeverityLow:
		return fmt.Sprintf("%s[%s]%s", cyan, s, resetBold)
	default:
		return fmt.Sprintf("%s[%s]%s", dim, s, resetBold)
	}
}

func (c *ConsoleReporter) Report(report *engine.ScanReport, w io.Writer) error {
	fmt.Fprintf(w, "\n%s=== ISO 27001 AUDIT REPORT ===%s\n", bold, resetBold)
	fmt.Fprintf(w, "Target    : %s\n", c.colorize(report.Target, cyan))
	fmt.Fprintf(w, "Profile   : %s\n", report.Profile)
	fmt.Fprintf(w, "Timestamp : %s\n", report.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "Duration  : %s\n\n", report.Summary.Duration.Round(100*1000))

	fmt.Fprintf(w, "%s--- EVALUATED CONTROLS ---%s\n", bold, resetBold)

	for _, res := range report.Results {
		badge := c.statusBadge(res.Status)
		sev := c.severityBadge(res.Severity)

		fmt.Fprintf(w, "%s %s %-10s %s %s\n",
			badge,
			sev,
			c.colorize(res.ControlID, blue),
			res.Title,
			c.colorize(fmt.Sprintf("(%s)", res.RuleID), dim),
		)

		if res.Message != "" {
			prefix := "      "
			fmt.Fprintf(w, "%s%s\n", prefix, c.colorize(res.Message, dim))
		}

		if res.Status == engine.StatusFail && res.Remediation != "" {
			fmt.Fprintf(w, "      %s Remediation: %s\n", c.colorize("->", yellow), res.Remediation)
		}

		if len(res.Details) > 0 && res.Status != engine.StatusPass {
			for k, v := range res.Details {
				fmt.Fprintf(w, "         • %s: %v\n", c.colorize(k, dim), v)
			}
		}
	}

	// Print Summary
	sum := report.Summary
	scoreColor := green
	if sum.ComplianceScore < 70 {
		scoreColor = red
	} else if sum.ComplianceScore < 90 {
		scoreColor = yellow
	}

	fmt.Fprintf(w, "\n%s==================== COMPLIANCE SUMMARY ====================%s\n", bold, resetBold)
	fmt.Fprintf(w, "Total Controls : %d\n", sum.TotalRules)
	fmt.Fprintf(w, "Passed         : %s\n", c.colorize(fmt.Sprintf("%d", sum.Passed), green))
	fmt.Fprintf(w, "Failed         : %s (Critical: %d, High: %d, Medium: %d, Low: %d)\n",
		c.colorize(fmt.Sprintf("%d", sum.Failed), red),
		sum.CriticalCount, sum.HighCount, sum.MediumCount, sum.LowCount,
	)
	fmt.Fprintf(w, "Warnings       : %s\n", c.colorize(fmt.Sprintf("%d", sum.Warnings), yellow))
	fmt.Fprintf(w, "Skipped        : %d\n", sum.Skipped)
	fmt.Fprintf(w, "------------------------------------------------------------\n")
	fmt.Fprintf(w, "Compliance Score: %s\n",
		c.colorize(fmt.Sprintf("%.1f%%", sum.ComplianceScore), bold+scoreColor),
	)
	fmt.Fprintf(w, "%s============================================================%s\n\n", bold, resetBold)

	return nil
}
