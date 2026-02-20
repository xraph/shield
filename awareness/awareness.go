// Package awareness models what an agent pays attention to in content.
//
// Awareness is about perception — what you notice. PII detection is
// awareness: you notice an email address in text. Topic classification
// is awareness: you recognize what a conversation is about. Intent
// detection is awareness: you understand what someone is trying to do.
package awareness

import (
	"context"

	"github.com/xraph/shield"
	"github.com/xraph/shield/id"
)

// Focus defines what type of content an awareness detector looks for.
type Focus string

const (
	// FocusPII detects personal identifiable information.
	FocusPII Focus = "pii"
	// FocusTopic classifies conversation topics.
	FocusTopic Focus = "topic"
	// FocusSentiment analyzes emotional tone.
	FocusSentiment Focus = "sentiment"
	// FocusIntent classifies user intent.
	FocusIntent Focus = "intent"
	// FocusLanguage detects language.
	FocusLanguage Focus = "language"
	// FocusCustom is a user-defined focus.
	FocusCustom Focus = "custom"
)

// Detector defines a specific awareness detection strategy.
type Detector struct {
	Name     string         `json:"name"`
	Focus    Focus          `json:"focus"`
	Patterns []string       `json:"patterns,omitempty"` // regex patterns for pattern-based detection
	Config   map[string]any `json:"config,omitempty"`
}

// PIIAction defines what to do when PII is found.
type PIIAction string

const (
	// PIIActionRedact replaces PII with placeholders.
	PIIActionRedact PIIAction = "redact"
	// PIIActionFlag marks content as containing PII.
	PIIActionFlag PIIAction = "flag"
	// PIIActionBlock prevents content from passing.
	PIIActionBlock PIIAction = "block"
	// PIIActionVault redacts PII and stores the original encrypted.
	PIIActionVault PIIAction = "vault"
)

// Awareness represents what an agent pays attention to in content.
// Awareness detectors run after instincts and notice patterns,
// entities, and characteristics in text.
type Awareness struct {
	shield.Entity
	ID          id.AwarenessID `json:"id" bun:",pk"`
	Name        string         `json:"name" bun:",notnull"`
	Description string         `json:"description,omitempty"`
	AppID       string         `json:"app_id" bun:",notnull"`
	TenantID    string         `json:"tenant_id,omitempty"`
	Focus       Focus          `json:"focus" bun:",notnull"`
	Detectors   []Detector     `json:"detectors,omitempty" bun:"type:jsonb"`
	Action      string         `json:"action" bun:",notnull"` // "redact", "flag", "block", "vault"
	Enabled     bool           `json:"enabled" bun:",notnull,default:true"`
	Metadata    map[string]any `json:"metadata,omitempty" bun:"type:jsonb"`
}

// ListFilter defines filtering options for listing awareness detectors.
type ListFilter struct {
	AppID    string
	TenantID string
	Focus    Focus
	Enabled  *bool
	Limit    int
	Offset   int
}

// Store defines persistence operations for awareness detectors.
type Store interface {
	CreateAwareness(ctx context.Context, a *Awareness) error
	GetAwareness(ctx context.Context, aID id.AwarenessID) (*Awareness, error)
	GetAwarenessByName(ctx context.Context, appID, name string) (*Awareness, error)
	UpdateAwareness(ctx context.Context, a *Awareness) error
	DeleteAwareness(ctx context.Context, aID id.AwarenessID) error
	ListAwareness(ctx context.Context, filter *ListFilter) ([]*Awareness, error)
}
