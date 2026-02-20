// Package profile models a complete safety identity composed from primitives.
//
// A SafetyProfile is the Shield equivalent of a Cortex Persona. Just as
// a Persona composes Skills + Traits + Behaviors into a complete agent
// identity, a SafetyProfile composes Instincts + Awareness + Boundaries +
// Values + Judgment + Reflexes into a complete safety character.
package profile

import (
	"context"

	"github.com/xraph/shield"
	"github.com/xraph/shield/id"
	"github.com/xraph/shield/instinct"
)

// InstinctAssignment assigns an instinct with an optional sensitivity override.
type InstinctAssignment struct {
	InstinctName string               `json:"instinct_name"`
	Sensitivity  instinct.Sensitivity `json:"sensitivity,omitempty"` // override default sensitivity
}

// JudgmentAssignment assigns a judgment with an optional threshold override.
type JudgmentAssignment struct {
	JudgmentName string  `json:"judgment_name"`
	Threshold    float64 `json:"threshold,omitempty"` // override default threshold (0.0-1.0)
}

// AwarenessAssignment assigns an awareness detector to the profile.
type AwarenessAssignment struct {
	AwarenessName string `json:"awareness_name"`
}

// SafetyProfile represents a complete safety identity composed from primitives.
// It is the primary composition unit for Shield — the recommended way to
// configure safety for an agent or application.
type SafetyProfile struct {
	shield.Entity
	ID          id.SafetyProfileID    `json:"id" bun:",pk"`
	Name        string                `json:"name" bun:",notnull"`
	Description string                `json:"description,omitempty"`
	AppID       string                `json:"app_id" bun:",notnull"`
	TenantID    string                `json:"tenant_id,omitempty"`
	Instincts   []InstinctAssignment  `json:"instincts,omitempty" bun:"type:jsonb"`
	Judgments   []JudgmentAssignment  `json:"judgments,omitempty" bun:"type:jsonb"`
	Awareness   []AwarenessAssignment `json:"awareness,omitempty" bun:"type:jsonb"`
	Values      []string              `json:"values,omitempty" bun:"type:jsonb"`     // value names
	Reflexes    []string              `json:"reflexes,omitempty" bun:"type:jsonb"`   // reflex names
	Boundaries  []string              `json:"boundaries,omitempty" bun:"type:jsonb"` // boundary names
	Enabled     bool                  `json:"enabled" bun:",notnull,default:true"`
	Metadata    map[string]any        `json:"metadata,omitempty" bun:"type:jsonb"`
}

// ListFilter defines filtering options for listing safety profiles.
type ListFilter struct {
	AppID    string
	TenantID string
	Enabled  *bool
	Limit    int
	Offset   int
}

// Store defines persistence operations for safety profiles.
type Store interface {
	CreateProfile(ctx context.Context, p *SafetyProfile) error
	GetProfile(ctx context.Context, pID id.SafetyProfileID) (*SafetyProfile, error)
	GetProfileByName(ctx context.Context, appID, name string) (*SafetyProfile, error)
	UpdateProfile(ctx context.Context, p *SafetyProfile) error
	DeleteProfile(ctx context.Context, pID id.SafetyProfileID) error
	ListProfiles(ctx context.Context, filter *ListFilter) ([]*SafetyProfile, error)
}
