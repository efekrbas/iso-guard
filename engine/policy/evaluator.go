package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/efekrbas/iso-guard/engine"
	"github.com/efekrbas/iso-guard/scanners/file"
)

// Evaluator is the interface responsible for evaluating a YAML-defined Policy against target state.
type Evaluator interface {
	Evaluate(ctx *engine.ScanContext, policy *Policy) engine.RuleResult
}

// DefaultEvaluator implements the standard declarative policy evaluation logic.
type DefaultEvaluator struct {
	MaxFileReadBytes int64
}

// NewDefaultEvaluator creates a new DefaultEvaluator.
func NewDefaultEvaluator() *DefaultEvaluator {
	return &DefaultEvaluator{
		MaxFileReadBytes: 1024 * 1024, // 1 MB limit per file content check
	}
}

// Evaluate runs all assertions in policy.Spec against the scan context.
func (e *DefaultEvaluator) Evaluate(ctx *engine.ScanContext, p *Policy) engine.RuleResult {
	if !p.Enabled {
		return engine.RuleResult{
			RuleID:    p.ID,
			ControlID: p.ControlID,
			Title:     p.Title,
			Category:  p.Category,
			Severity:  p.Severity,
			Status:    engine.StatusSkip,
			Message:   "Policy disabled in specification",
		}
	}

	targetDir := ctx.Target
	if targetDir == "" {
		targetDir = "."
	}

	failures := make([]string, 0)
	evidence := make(map[string]interface{})

	// 1. Handle file existence requirements (require_files or alternative_files)
	if len(p.Spec.RequireFiles) > 0 {
		for _, req := range p.Spec.RequireFiles {
			fullPath := filepath.Join(targetDir, filepath.FromSlash(req))
			if _, err := os.Stat(fullPath); os.IsNotExist(err) {
				failures = append(failures, fmt.Sprintf("Required file missing: %s", req))
			}
		}
	}

	if len(p.Spec.AlternativeFiles) > 0 {
		foundAny := false
		var checked []string
		for _, alt := range p.Spec.AlternativeFiles {
			fullPath := filepath.Join(targetDir, filepath.FromSlash(alt))
			checked = append(checked, alt)
			if _, err := os.Stat(fullPath); err == nil {
				foundAny = true
				break
			}
		}
		if !foundAny {
			failures = append(failures, fmt.Sprintf("None of the alternative files found: [%s]", strings.Join(checked, ", ")))
		}
	}

	// 2. Locate files to inspect for content and pattern assertions
	filesToInspect := e.findMatchingFiles(targetDir, p.Spec.MatchFiles, p.Spec.ExcludeFiles, ctx)

	// 3. Run individual assertions
	for _, assertion := range p.Spec.Assertions {
		switch assertion.Type {
		case AssertFileExists:
			// Verified above or via match_files
			if len(p.Spec.RequireFiles) == 0 && len(p.Spec.AlternativeFiles) == 0 && len(filesToInspect) == 0 {
				failures = append(failures, assertion.Message)
			}

		case AssertFileNotExists:
			if len(filesToInspect) > 0 {
				var foundList []string
				for _, f := range filesToInspect {
					foundList = append(foundList, filepath.Base(f))
				}
				failures = append(failures, fmt.Sprintf("%s (Found: %s)", assertion.Message, strings.Join(foundList, ", ")))
				evidence["forbidden_files_found"] = foundList
			}

		case AssertRegexMatch:
			if len(filesToInspect) == 0 {
				// No target config files matched to evaluate
				continue
			}
			re, err := regexp.Compile(assertion.Pattern)
			if err != nil {
				failures = append(failures, fmt.Sprintf("Invalid regex pattern %q: %v", assertion.Pattern, err))
				continue
			}

			for _, filePath := range filesToInspect {
				content, err := e.readFileContent(filePath)
				if err != nil {
					continue
				}

				matches := re.FindStringSubmatch(string(content))
				if len(matches) == 0 {
					// Only flag if the file actually defines password or authentication settings
					contentLower := strings.ToLower(string(content))
					if strings.Contains(contentLower, "password") || strings.Contains(contentLower, "passwd") || strings.Contains(contentLower, "auth") {
						failures = append(failures, fmt.Sprintf("%s (%s)", assertion.Message, filepath.Base(filePath)))
					}
					// Unrelated configuration files without password definitions are not violations
					continue
				}

				// Check numerical threshold if specified (e.g. min password length)
				if assertion.MinValue != nil && len(matches) > 1 {
					// Last capture group is expected to contain the numeric value
					valStr := matches[len(matches)-1]
					val, parseErr := strconv.Atoi(valStr)
					if parseErr != nil || val < *assertion.MinValue {
						failures = append(failures, fmt.Sprintf("%s: value %s is less than minimum %d (%s)",
							assertion.Message, valStr, *assertion.MinValue, filepath.Base(filePath)))
					}
				}
			}

		case AssertDisallowPatterns:
			patterns := assertion.Patterns
			if len(patterns) == 0 && assertion.Pattern != "" {
				patterns = []string{assertion.Pattern}
			}

			var compiledRegexes []*regexp.Regexp
			for _, pat := range patterns {
				if r, err := regexp.Compile(pat); err == nil {
					compiledRegexes = append(compiledRegexes, r)
				}
			}

			var detected []string
			for _, filePath := range filesToInspect {
				content, err := e.readFileContent(filePath)
				if err != nil {
					continue
				}

				for _, r := range compiledRegexes {
					if r.Match(content) {
						rel, _ := filepath.Rel(targetDir, filePath)
						detected = append(detected, fmt.Sprintf("%s matches %s", rel, r.String()))
					}
				}
			}

			if len(detected) > 0 {
				failures = append(failures, assertion.Message)
				evidence["disallowed_matches"] = detected
			}
		}
	}

	if len(failures) > 0 {
		evidence["violations"] = failures
		return engine.RuleResult{
			RuleID:      p.ID,
			ControlID:   p.ControlID,
			Title:       p.Title,
			Category:    p.Category,
			Severity:    p.Severity,
			Status:      engine.StatusFail,
			Message:     strings.Join(failures, "; "),
			Remediation: p.Remediation,
			Details:     evidence,
		}
	}

	return engine.RuleResult{
		RuleID:    p.ID,
		ControlID: p.ControlID,
		Title:     p.Title,
		Category:  p.Category,
		Severity:  p.Severity,
		Status:    engine.StatusPass,
		Message:   fmt.Sprintf("Compliance verified against policy criteria (%d file(s) evaluated)", len(filesToInspect)),
	}
}

func (e *DefaultEvaluator) findMatchingFiles(targetDir string, matchPatterns, excludePatterns []string, ctx *engine.ScanContext) []string {
	var matched []string
	if len(matchPatterns) == 0 {
		return matched
	}

	isExcluded := func(rel, base string) bool {
		for _, pattern := range excludePatterns {
			if matchGlob(pattern, rel) || matchGlob(pattern, base) {
				return true
			}
		}
		return false
	}

	// First try using cached filesystem artifact if available
	if raw, ok := ctx.Artifacts["filesystem"]; ok {
		if artifact, ok := raw.(*file.FileArtifact); ok {
			for _, f := range artifact.AllFiles {
				relSlash := filepath.ToSlash(f.RelPath)
				base := filepath.Base(f.Path)
				if isExcluded(relSlash, base) {
					continue
				}
				for _, pattern := range matchPatterns {
					if matchGlob(pattern, relSlash) || matchGlob(pattern, base) {
						matched = append(matched, f.Path)
						break
					}
				}
			}
			return matched
		}
	}

	// Fallback to directory walk
	_ = filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(targetDir, path)
		if err != nil {
			return nil
		}
		relSlash := filepath.ToSlash(rel)
		base := filepath.Base(path)
		if isExcluded(relSlash, base) {
			return nil
		}

		for _, pattern := range matchPatterns {
			if matchGlob(pattern, relSlash) || matchGlob(pattern, base) {
				matched = append(matched, path)
				break
			}
		}
		return nil
	})

	return matched
}

func matchGlob(pattern, s string) bool {
	matched, err := filepath.Match(pattern, s)
	if err == nil && matched {
		return true
	}
	// Case-insensitive fallback
	matchedLower, err := filepath.Match(strings.ToLower(pattern), strings.ToLower(s))
	return err == nil && matchedLower
}

func (e *DefaultEvaluator) readFileContent(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}

	readLimit := e.MaxFileReadBytes
	if stat.Size() < readLimit {
		readLimit = stat.Size()
	}

	buf := make([]byte, readLimit)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return nil, err
	}

	return buf[:n], nil
}

var _ Evaluator = (*DefaultEvaluator)(nil)
