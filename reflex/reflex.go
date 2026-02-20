// Package reflex models condition-triggered safety responses.
//
// Reflexes are trained responses — condition→action pairs that fire
// when specific conditions are met. Policy rules are reflexes.
// Rate limiting is a reflex. Escalation logic is a reflex. They
// are the Shield equivalent of Cortex's Behaviors.
package reflex

import (
	"context"

	"github.com/xraph/shield"
	"github.com/xraph/shield/id"
)

// TriggerType defines when a reflex activates.
type TriggerType string

const (
	// TriggerOnScore activates when a check score exceeds a threshold.
	TriggerOnScore TriggerType = "on_score"
	// TriggerOnFinding activates when a specific finding type appears.
	TriggerOnFinding TriggerType = "on_finding"
	// TriggerOnPattern activates when text matches a pattern.
	TriggerOnPattern TriggerType = "on_pattern"
	// TriggerOnContext activates when context metadata matches.
	TriggerOnContext TriggerType = "on_context"
	// TriggerOnRate activates on rate-limit conditions.
	TriggerOnRate TriggerType = "on_rate"
	// TriggerAlways activates unconditionally.
	TriggerAlways TriggerType = "always"
)

// Trigger defines when a reflex activates.
type Trigger struct {
	Type      TriggerType `json:"type"`
	Pattern   string      `json:"pattern,omitempty"`   // regex/pattern for matching
	Threshold float64     `json:"threshold,omitempty"` // score threshold
	Window    string      `json:"window,omitempty"`    // time window for rate triggers (e.g., "1m", "5m")
}

// ActionType defines what happens when a reflex triggers.
type ActionType string

const (
	// ActionBlock prevents content from passing.
	ActionBlock ActionType = "block"
	// ActionRedact replaces sensitive content with placeholders.
	ActionRedact ActionType = "redact"
	// ActionFlag marks content for review.
	ActionFlag ActionType = "flag"
	// ActionRewrite transforms content.
	ActionRewrite ActionType = "rewrite"
	// ActionEscalate sends content for human review.
	ActionEscalate ActionType = "escalate"
	// ActionLog records the event without modifying content.
	ActionLog ActionType = "log"
	// ActionThrottle rate-limits the request.
	ActionThrottle ActionType = "throttle"
)

// Action defines what a reflex does when triggered.
type Action struct {
	Type     ActionType `json:"type"`
	Target   string     `json:"target,omitempty"`   // what to act on
	Value    any        `json:"value,omitempty"`    // action-specific value
	Fallback string     `json:"fallback,omitempty"` // fallback response text
}

// Reflex represents a condition-triggered safety response.
// Reflexes are the sixth layer of the safety engine — they evaluate
// policy rules and custom conditions to produce actions.
type Reflex struct {
	shield.Entity
	ID          id.ReflexID    `json:"id" bun:",pk"`
	Name        string         `json:"name" bun:",notnull"`
	Description string         `json:"description,omitempty"`
	AppID       string         `json:"app_id" bun:",notnull"`
	TenantID    string         `json:"tenant_id,omitempty"`
	Triggers    []Trigger      `json:"triggers,omitempty" bun:"type:jsonb"`
	Actions     []Action       `json:"actions,omitempty" bun:"type:jsonb"`
	Priority    int            `json:"priority,omitempty" bun:",default:0"`
	Enabled     bool           `json:"enabled" bun:",notnull,default:true"`
	Metadata    map[string]any `json:"metadata,omitempty" bun:"type:jsonb"`
}

// ListFilter defines filtering options for listing reflexes.
type ListFilter struct {
	AppID    string
	TenantID string
	Enabled  *bool
	Limit    int
	Offset   int
}

// Store defines persistence operations for reflexes.
type Store interface {
	CreateReflex(ctx context.Context, r *Reflex) error
	GetReflex(ctx context.Context, rID id.ReflexID) (*Reflex, error)
	GetReflexByName(ctx context.Context, appID, name string) (*Reflex, error)
	UpdateReflex(ctx context.Context, r *Reflex) error
	DeleteReflex(ctx context.Context, rID id.ReflexID) error
	ListReflexes(ctx context.Context, filter *ListFilter) ([]*Reflex, error)
}
