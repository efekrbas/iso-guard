package engine

import (
	"fmt"
	"strings"
	"sync"
)

// Registry manages the set of available audit rules.
type Registry struct {
	mu    sync.RWMutex
	rules map[string]Rule
	order []string
}

var defaultRegistry = NewRegistry()

// DefaultRegistry returns the default shared rule registry.
func DefaultRegistry() *Registry {
	return defaultRegistry
}

// NewRegistry creates a new Rule Registry.
func NewRegistry() *Registry {
	return &Registry{
		rules: make(map[string]Rule),
		order: make([]string, 0),
	}
}

// Register adds a rule to the registry.
func (r *Registry) Register(rule Rule) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if rule.ID == "" {
		return fmt.Errorf("rule ID cannot be empty")
	}

	if _, exists := r.rules[rule.ID]; exists {
		return fmt.Errorf("rule with ID %q already registered", rule.ID)
	}

	r.rules[rule.ID] = rule
	r.order = append(r.order, rule.ID)
	return nil
}

// MustRegister adds a rule and panics if an error occurs.
func (r *Registry) MustRegister(rule Rule) {
	if err := r.Register(rule); err != nil {
		panic(err)
	}
}

// GetByID looks up a rule by its ID.
func (r *Registry) GetByID(id string) (Rule, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rule, exists := r.rules[id]
	return rule, exists
}

// GetAll returns all rules in registration order.
func (r *Registry) GetAll() []Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()

	res := make([]Rule, 0, len(r.order))
	for _, id := range r.order {
		res = append(res, r.rules[id])
	}
	return res
}

// Filter filters rules by category, minimum severity, and tags.
func (r *Registry) Filter(category string, minSeverity Severity, tags []string) []Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var filtered []Rule
	minWeight := minSeverity.Weight()

	for _, id := range r.order {
		rule := r.rules[id]

		if category != "" && !strings.EqualFold(rule.Category, category) {
			continue
		}

		if minWeight > 0 && rule.Severity.Weight() < minWeight {
			continue
		}

		if len(tags) > 0 {
			matchedTag := false
			for _, queryTag := range tags {
				for _, ruleTag := range rule.Tags {
					if strings.EqualFold(ruleTag, queryTag) {
						matchedTag = true
						break
					}
				}
				if matchedTag {
					break
				}
			}
			if !matchedTag {
				continue
			}
		}

		filtered = append(filtered, rule)
	}

	return filtered
}

// RegisterRule helper registers a rule in the default registry.
func RegisterRule(rule Rule) {
	defaultRegistry.MustRegister(rule)
}
