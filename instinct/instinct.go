// Package instinct models hardwired, automatic safety responses.
//
// Instincts are the fastest safety layer — pre-conscious, immediate
// threat detection. Like a human flinching from danger, instincts fire
// before any deliberation. Prompt injection detection, jailbreak detection,
// and exfiltration detection are instincts.
package instinct

import (
	"context"

	"github.com/xraph/shield"
	"github.com/xraph/shield/id"
)

// Sensitivity represents how easily an instinct triggers.
// Lower sensitivity means more tolerant; higher means more aggressive.
type Sensitivity string

const (
	// SensitivityParanoid triggers on faint signals.
	SensitivityParanoid Sensitivity = "paranoid"
	// SensitivityCautious triggers on moderate signals.
	SensitivityCautious Sensitivity = "cautious"
	// SensitivityBalanced is the default sensitivity.
	SensitivityBalanced Sensitivity = "balanced"
	// SensitivityRelaxed triggers only on strong signals.
	SensitivityRelaxed Sensitivity = "relaxed"
	// SensitivityPermissive triggers only on obvious threats.
	SensitivityPermissive Sensitivity = "permissive"
)

// Weight returns the numeric threshold modifier for this sensitivity.
// Lower values mean more sensitive (easier to trigger).
func (s Sensitivity) Weight() float64 {
	switch s {
	case SensitivityParanoid:
		return 0.2
	case SensitivityCautious:
		return 0.4
	case SensitivityBalanced:
		return 0.6
	case SensitivityRelaxed:
		return 0.8
	case SensitivityPermissive:
		return 0.95
	default:
		return 0.6
	}
}

// Category groups related instincts.
type Category string

const (
	// CategoryInjection covers prompt injection attacks.
	CategoryInjection Category = "injection"
	// CategoryExfiltration covers attempts to extract internal data.
	CategoryExfiltration Category = "exfiltration"
	// CategoryManipulation covers social engineering and manipulation.
	CategoryManipulation Category = "manipulation"
	// CategoryJailbreak covers attempts to bypass safety guardrails.
	CategoryJailbreak Category = "jailbreak"
)

// Strategy defines how an instinct detects threats.
type Strategy struct {
	Name   string         `json:"name"`             // e.g., "classifier", "canary", "perplexity", "hierarchy"
	Weight float64        `json:"weight,omitempty"`  // contribution to combined score (0.0-1.0)
	Config map[string]any `json:"config,omitempty"`
}

// Instinct represents a hardwired, automatic safety response.
// Instincts are the first layer of the safety engine — fast, pre-conscious,
// and non-negotiable. They run before any other safety evaluation.
type Instinct struct {
	shield.Entity
	ID          id.InstinctID  `json:"id" bun:",pk"`
	Name        string         `json:"name" bun:",notnull"`
	Description string         `json:"description,omitempty"`
	AppID       string         `json:"app_id" bun:",notnull"`
	TenantID    string         `json:"tenant_id,omitempty"`
	Category    Category       `json:"category" bun:",notnull"`
	Strategies  []Strategy     `json:"strategies,omitempty" bun:"type:jsonb"`
	Sensitivity Sensitivity    `json:"sensitivity,omitempty" bun:",notnull,default:'balanced'"`
	Action      string         `json:"action" bun:",notnull"` // "block", "flag", "alert"
	Enabled     bool           `json:"enabled" bun:",notnull,default:true"`
	Metadata    map[string]any `json:"metadata,omitempty" bun:"type:jsonb"`
}

// ListFilter defines filtering options for listing instincts.
type ListFilter struct {
	AppID    string
	TenantID string
	Category Category
	Enabled  *bool
	Limit    int
	Offset   int
}

// Store defines persistence operations for instincts.
type Store interface {
	CreateInstinct(ctx context.Context, inst *Instinct) error
	GetInstinct(ctx context.Context, instID id.InstinctID) (*Instinct, error)
	GetInstinctByName(ctx context.Context, appID, name string) (*Instinct, error)
	UpdateInstinct(ctx context.Context, inst *Instinct) error
	DeleteInstinct(ctx context.Context, instID id.InstinctID) error
	ListInstincts(ctx context.Context, filter *ListFilter) ([]*Instinct, error)
}
