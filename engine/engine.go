package engine

import (
	"context"
	"math"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/efekrbas/iso-guard/config"
	"github.com/efekrbas/iso-guard/scanners"
)

// Engine orchestrates the target scanning and rule evaluation process.
type Engine struct {
	Config   *config.Config
	Registry *Registry
	Scanners []scanners.Scanner
}

// NewEngine creates a new Engine instance.
func NewEngine(cfg *config.Config, reg *Registry, activeScanners []scanners.Scanner) *Engine {
	if reg == nil {
		reg = DefaultRegistry()
	}
	return &Engine{
		Config:   cfg,
		Registry: reg,
		Scanners: activeScanners,
	}
}

// Run executes the complete audit scan on the provided target.
func (e *Engine) Run(ctx context.Context, target string) (*ScanReport, error) {
	startTime := time.Now()

	scanCtx := NewScanContext(ctx, target)
	scanCtx.Config = e.Config

	// 1. Run scanners in parallel to collect artifacts
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, sc := range e.Scanners {
		wg.Add(1)
		go func(s scanners.Scanner) {
			defer wg.Done()
			data, err := s.Scan(ctx, target)
			if err == nil && data != nil {
				mu.Lock()
				scanCtx.Artifacts[s.Name()] = data
				mu.Unlock()
			}
		}(sc)
	}

	wg.Wait()

	// Check if context canceled
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// 2. Select eligible rules from registry
	allRules := e.Registry.GetAll()
	eligibleRules := e.filterRules(allRules)

	// 3. Evaluate rules
	results := make([]RuleResult, 0, len(eligibleRules))
	var summary ScanSummary
	summary.TotalRules = len(eligibleRules)

	for _, rule := range eligibleRules {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		ruleStart := time.Now()
		var res RuleResult

		if rule.Evaluate != nil {
			res = rule.Evaluate(scanCtx)
		} else {
			res = RuleResult{
				RuleID:    rule.ID,
				ControlID: rule.ControlID,
				Title:     rule.Title,
				Category:  rule.Category,
				Severity:  rule.Severity,
				Status:    StatusSkip,
				Message:   "No evaluation function defined",
			}
		}

		res.Duration = time.Since(ruleStart)
		if res.RuleID == "" {
			res.RuleID = rule.ID
		}
		if res.ControlID == "" {
			res.ControlID = rule.ControlID
		}
		if res.Title == "" {
			res.Title = rule.Title
		}
		if res.Category == "" {
			res.Category = rule.Category
		}
		if res.Severity == "" {
			res.Severity = rule.Severity
		}

		// Aggregate metrics
		switch res.Status {
		case StatusPass:
			summary.Passed++
		case StatusFail:
			summary.Failed++
			switch res.Severity {
			case SeverityCritical:
				summary.CriticalCount++
			case SeverityHigh:
				summary.HighCount++
			case SeverityMedium:
				summary.MediumCount++
			case SeverityLow:
				summary.LowCount++
			}
		case StatusWarn:
			summary.Warnings++
		case StatusSkip:
			summary.Skipped++
		}

		results = append(results, res)
	}

	// 4. Calculate compliance score
	evaluated := summary.Passed + summary.Failed + summary.Warnings
	if evaluated > 0 {
		// Passed gets 1.0, Warn gets 0.5, Failed gets 0.0
		score := (float64(summary.Passed) + 0.5*float64(summary.Warnings)) / float64(evaluated) * 100.0
		summary.ComplianceScore = math.Round(score*10) / 10
	} else {
		summary.ComplianceScore = 100.0
	}

	summary.Duration = time.Since(startTime)

	// Build Environment metadata
	hostname, _ := os.Hostname()
	env := Environment{
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		Hostname:    hostname,
		ToolVersion: "v0.1.0",
	}

	report := &ScanReport{
		Target:      target,
		Profile:     e.Config.Profile,
		Timestamp:   startTime,
		Summary:     summary,
		Results:     results,
		Environment: env,
	}

	return report, nil
}

// filterRules filters rules against include/exclude lists and minimum severity.
func (e *Engine) filterRules(rules []Rule) []Rule {
	var filtered []Rule
	minWeight := Severity(e.Config.Rules.MinSeverity).Weight()

	includeMap := make(map[string]bool)
	for _, id := range e.Config.Rules.Include {
		includeMap[strings.ToUpper(id)] = true
	}

	excludeMap := make(map[string]bool)
	for _, id := range e.Config.Rules.Exclude {
		excludeMap[strings.ToUpper(id)] = true
	}

	for _, r := range rules {
		// Check explicit exclusion
		if excludeMap[strings.ToUpper(r.ID)] || excludeMap[strings.ToUpper(r.ControlID)] {
			continue
		}

		// Check explicit inclusion
		if len(includeMap) > 0 {
			if !includeMap[strings.ToUpper(r.ID)] && !includeMap[strings.ToUpper(r.ControlID)] {
				continue
			}
		}

		// Check minimum severity
		if minWeight > 0 && r.Severity.Weight() < minWeight {
			continue
		}

		// Check category filter
		if len(e.Config.Rules.IncludeCategories) > 0 {
			matched := false
			for _, cat := range e.Config.Rules.IncludeCategories {
				if strings.EqualFold(cat, r.Category) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		filtered = append(filtered, r)
	}

	return filtered
}
