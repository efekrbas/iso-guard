package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/efekrbas/iso-guard/engine"
	"gopkg.in/yaml.v3"
)

// PolicyEngine manages the lifecycle, storage, and execution of YAML-based policies.
type PolicyEngine interface {
	LoadFromFile(path string) ([]*Policy, error)
	LoadFromDir(dir string) ([]*Policy, error)
	LoadFromBytes(data []byte) ([]*Policy, error)
	RegisterPolicy(p *Policy) error
	GetPolicies() []*Policy
	Execute(ctx *engine.ScanContext) []engine.RuleResult
	RegisterToEngineRegistry(registry *engine.Registry) error
}

// Engine implements the PolicyEngine interface.
type Engine struct {
	mu        sync.RWMutex
	policies  map[string]*Policy
	order     []string
	evaluator Evaluator
}

// NewPolicyEngine creates a new YAML Policy Engine instance.
func NewPolicyEngine(eval Evaluator) *Engine {
	if eval == nil {
		eval = NewDefaultEvaluator()
	}
	return &Engine{
		policies:  make(map[string]*Policy),
		order:     make([]string, 0),
		evaluator: eval,
	}
}

// LoadFromFile parses a YAML policy file and registers its policies.
func (e *Engine) LoadFromFile(path string) ([]*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file %q: %w", path, err)
	}
	return e.LoadFromBytes(data)
}

// LoadFromDir recursively scans a directory for .yaml or .yml files and loads them.
func (e *Engine) LoadFromDir(dir string) ([]*Policy, error) {
	var loaded []*Policy

	err := filepath.Walk(dir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yaml" || ext == ".yml" {
			pList, err := e.LoadFromFile(path)
			if err != nil {
				return fmt.Errorf("error loading %q: %w", path, err)
			}
			loaded = append(loaded, pList...)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to load policies from directory %q: %w", dir, err)
	}

	return loaded, nil
}

// LoadFromBytes unmarshals YAML content and registers valid policies.
func (e *Engine) LoadFromBytes(data []byte) ([]*Policy, error) {
	var fileDoc PolicyFile

	if err := yaml.Unmarshal(data, &fileDoc); err != nil {
		// Try unmarshaling as a single policy or array of policies
		var single Policy
		if singleErr := yaml.Unmarshal(data, &single); singleErr == nil && single.ID != "" {
			fileDoc.Policies = []Policy{single}
		} else {
			var list []Policy
			if listErr := yaml.Unmarshal(data, &list); listErr == nil && len(list) > 0 {
				fileDoc.Policies = list
			} else {
				return nil, fmt.Errorf("failed to parse policy YAML: %w", err)
			}
		}
	}

	var registered []*Policy
	for i := range fileDoc.Policies {
		p := fileDoc.Policies[i]
		if err := p.Validate(); err != nil {
			return nil, fmt.Errorf("policy validation failed: %w", err)
		}
		pCopy := p
		if err := e.RegisterPolicy(&pCopy); err != nil {
			return nil, err
		}
		registered = append(registered, &pCopy)
	}

	return registered, nil
}

// RegisterPolicy stores a policy in memory.
func (e *Engine) RegisterPolicy(p *Policy) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.policies[p.ID]; exists {
		// Update existing
		e.policies[p.ID] = p
		return nil
	}

	e.policies[p.ID] = p
	e.order = append(e.order, p.ID)
	return nil
}

// GetPolicies returns all loaded policies.
func (e *Engine) GetPolicies() []*Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]*Policy, 0, len(e.order))
	for _, id := range e.order {
		result = append(result, e.policies[id])
	}
	return result
}

// Execute evaluates all registered YAML policies against the scan context.
func (e *Engine) Execute(ctx *engine.ScanContext) []engine.RuleResult {
	e.mu.RLock()
	policies := make([]*Policy, 0, len(e.order))
	for _, id := range e.order {
		policies = append(policies, e.policies[id])
	}
	e.mu.RUnlock()

	results := make([]engine.RuleResult, 0, len(policies))
	for _, p := range policies {
		res := e.evaluator.Evaluate(ctx, p)
		results = append(results, res)
	}
	return results
}

// RegisterToEngineRegistry converts all YAML policies into engine.Rule items and adds them to an engine.Registry.
func (e *Engine) RegisterToEngineRegistry(registry *engine.Registry) error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, id := range e.order {
		pol := e.policies[id]
		polCopy := *pol

		rule := engine.Rule{
			ID:             polCopy.ID,
			ControlID:      polCopy.ControlID,
			Title:          polCopy.Title,
			Description:    polCopy.Description,
			Category:       polCopy.Category,
			Severity:       polCopy.Severity,
			DefaultEnabled: polCopy.Enabled,
			Tags:           polCopy.Tags,
			Evaluate: func(ctx *engine.ScanContext) engine.RuleResult {
				return e.evaluator.Evaluate(ctx, &polCopy)
			},
		}

		// If rule already exists in registry, ignore error or replace
		_ = registry.Register(rule)
	}

	return nil
}

var _ PolicyEngine = (*Engine)(nil)
