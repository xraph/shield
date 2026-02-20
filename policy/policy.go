// Package policy provides administrative governance over safety rules.
//
// Policies wrap reflexes for admin management. They define tenant-scoped
// safety rules that can be assigned and cascaded (app-level policies
// apply globally, org/tenant policies are additive).
package policy

import (
	"context"

	"github.com/xraph/shield"
	"github.com/xraph/shield/id"
)

// ScopeLevel defines the scope at which a policy operates.
type ScopeLevel string

const (
	ScopeApp ScopeLevel = "app"
	ScopeOrg ScopeLevel = "org"
)

// Rule defines a specific enforcement rule within a policy.
type Rule struct {
	CheckType    string `json:"check_type"`              // "instinct", "awareness", "values", "judgment", etc.
	Condition    string `json:"condition"`               // "score > 0.8", "pii_detected", etc.
	Action       string `json:"action"`                  // "block", "flag", "redact"
	ErrorMessage string `json:"error_message,omitempty"` // custom error message for blocks
	Priority     int    `json:"priority,omitempty"`
}

// Policy defines safety rules that can be assigned to tenants.
type Policy struct {
	shield.Entity
	ID          id.PolicyID    `json:"id" bun:",pk"`
	Name        string         `json:"name" bun:",notnull"`
	Description string         `json:"description,omitempty"`
	ScopeKey    string         `json:"scope_key" bun:",notnull"`
	ScopeLevel  ScopeLevel     `json:"scope_level" bun:",notnull"`
	Rules       []Rule         `json:"rules" bun:"type:jsonb"`
	Enabled     bool           `json:"enabled" bun:",notnull,default:true"`
	Metadata    map[string]any `json:"metadata,omitempty" bun:"type:jsonb"`
}

// ListFilter defines filtering for policy list queries.
type ListFilter struct {
	ScopeKey   string
	ScopeLevel ScopeLevel
	Enabled    *bool
	Limit      int
	Offset     int
}

// Store defines persistence operations for policies.
type Store interface {
	CreatePolicy(ctx context.Context, pol *Policy) error
	GetPolicy(ctx context.Context, polID id.PolicyID) (*Policy, error)
	GetPolicyByName(ctx context.Context, scopeKey, name string) (*Policy, error)
	UpdatePolicy(ctx context.Context, pol *Policy) error
	DeletePolicy(ctx context.Context, polID id.PolicyID) error
	ListPolicies(ctx context.Context, filter *ListFilter) ([]*Policy, error)
	GetPoliciesForScope(ctx context.Context, scopeKey string, level ScopeLevel) ([]*Policy, error)
	AssignToTenant(ctx context.Context, tenantID string, polID id.PolicyID) error
	UnassignFromTenant(ctx context.Context, tenantID string, polID id.PolicyID) error
}
