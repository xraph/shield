// Package boundary models hard safety limits that cannot be crossed.
//
// Boundaries are absolute. Unlike values (which have thresholds and
// gradients), boundaries are binary: cross them and content is immediately
// blocked. Topic restrictions are boundaries. Action limitations are
// boundaries. Data access controls are boundaries.
package boundary

import (
	"context"

	"github.com/xraph/shield"
	"github.com/xraph/shield/id"
)

// Scope defines what a boundary restricts.
type Scope string

const (
	// ScopeTopic restricts forbidden conversation topics.
	ScopeTopic Scope = "topic"
	// ScopeAction restricts forbidden agent actions.
	ScopeAction Scope = "action"
	// ScopeData restricts forbidden data access patterns.
	ScopeData Scope = "data"
	// ScopeOutput restricts forbidden output types or formats.
	ScopeOutput Scope = "output"
	// ScopeCustom is a user-defined scope.
	ScopeCustom Scope = "custom"
)

// Limit defines a specific boundary constraint.
type Limit struct {
	Scope    Scope    `json:"scope"`
	Deny     []string `json:"deny,omitempty"`     // explicitly denied items
	Allow    []string `json:"allow,omitempty"`    // explicitly allowed items (allowlist mode)
	UseAllow bool     `json:"use_allow,omitempty"` // true = allowlist mode, false = denylist mode
}

// Boundary represents a hard safety limit that cannot be crossed.
// Boundaries are the third layer of the safety engine — fast binary
// checks that enforce absolute limits. There is no threshold, no
// gradient: content either passes or is immediately blocked.
type Boundary struct {
	shield.Entity
	ID          id.BoundaryID  `json:"id" bun:",pk"`
	Name        string         `json:"name" bun:",notnull"`
	Description string         `json:"description,omitempty"`
	AppID       string         `json:"app_id" bun:",notnull"`
	TenantID    string         `json:"tenant_id,omitempty"`
	Limits      []Limit        `json:"limits,omitempty" bun:"type:jsonb"`
	Response    string         `json:"response,omitempty"` // canned response when boundary is hit
	Enabled     bool           `json:"enabled" bun:",notnull,default:true"`
	Metadata    map[string]any `json:"metadata,omitempty" bun:"type:jsonb"`
}

// ListFilter defines filtering options for listing boundaries.
type ListFilter struct {
	AppID    string
	TenantID string
	Scope    Scope
	Enabled  *bool
	Limit    int
	Offset   int
}

// Store defines persistence operations for boundaries.
type Store interface {
	CreateBoundary(ctx context.Context, b *Boundary) error
	GetBoundary(ctx context.Context, bID id.BoundaryID) (*Boundary, error)
	GetBoundaryByName(ctx context.Context, appID, name string) (*Boundary, error)
	UpdateBoundary(ctx context.Context, b *Boundary) error
	DeleteBoundary(ctx context.Context, bID id.BoundaryID) error
	ListBoundaries(ctx context.Context, filter *ListFilter) ([]*Boundary, error)
}
