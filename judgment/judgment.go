// Package judgment models the learned ability to assess risk in context.
//
// Judgment is slower and more deliberate than instincts. A hallucination
// detector needs to compare claims against source material. A grounding
// scorer needs context. These require "thinking" — contextual assessment
// that goes beyond pattern matching.
package judgment

import (
	"context"

	"github.com/xraph/shield"
	"github.com/xraph/shield/id"
)

// RiskLevel represents the assessed risk from a judgment evaluation.
type RiskLevel string

const (
	// RiskNone indicates no risk detected.
	RiskNone RiskLevel = "none"
	// RiskLow indicates low risk.
	RiskLow RiskLevel = "low"
	// RiskMedium indicates moderate risk.
	RiskMedium RiskLevel = "medium"
	// RiskHigh indicates high risk.
	RiskHigh RiskLevel = "high"
	// RiskCritical indicates critical risk.
	RiskCritical RiskLevel = "critical"
)

// Domain defines what area of safety a judgment covers.
type Domain string

const (
	// DomainGrounding evaluates factual accuracy and hallucination.
	DomainGrounding Domain = "grounding"
	// DomainRelevance evaluates response relevance to input.
	DomainRelevance Domain = "relevance"
	// DomainConsistency evaluates self-consistency of output.
	DomainConsistency Domain = "consistency"
	// DomainCompliance evaluates regulatory compliance.
	DomainCompliance Domain = "compliance"
	// DomainCustom is a user-defined domain.
	DomainCustom Domain = "custom"
)

// Assessor defines a judgment assessment strategy.
type Assessor struct {
	Name            string         `json:"name"`
	Domain          Domain         `json:"domain"`
	Weight          float64        `json:"weight,omitempty"`          // contribution to combined score
	Config          map[string]any `json:"config,omitempty"`
	RequiresContext bool           `json:"requires_context,omitempty"` // needs source material
}

// Judgment represents a learned ability to assess risk in context.
// Judgments are the fifth layer of the safety engine — the slowest
// but most sophisticated, capable of contextual risk assessment.
type Judgment struct {
	shield.Entity
	ID          id.JudgmentID  `json:"id" bun:",pk"`
	Name        string         `json:"name" bun:",notnull"`
	Description string         `json:"description,omitempty"`
	AppID       string         `json:"app_id" bun:",notnull"`
	TenantID    string         `json:"tenant_id,omitempty"`
	Domain      Domain         `json:"domain" bun:",notnull"`
	Assessors   []Assessor     `json:"assessors,omitempty" bun:"type:jsonb"`
	Threshold   float64        `json:"threshold,omitempty"` // risk threshold for action (0.0-1.0)
	Action      string         `json:"action" bun:",notnull"` // "flag", "block", "warn"
	Enabled     bool           `json:"enabled" bun:",notnull,default:true"`
	Metadata    map[string]any `json:"metadata,omitempty" bun:"type:jsonb"`
}

// ListFilter defines filtering options for listing judgments.
type ListFilter struct {
	AppID    string
	TenantID string
	Domain   Domain
	Enabled  *bool
	Limit    int
	Offset   int
}

// Store defines persistence operations for judgments.
type Store interface {
	CreateJudgment(ctx context.Context, j *Judgment) error
	GetJudgment(ctx context.Context, jID id.JudgmentID) (*Judgment, error)
	GetJudgmentByName(ctx context.Context, appID, name string) (*Judgment, error)
	UpdateJudgment(ctx context.Context, j *Judgment) error
	DeleteJudgment(ctx context.Context, jID id.JudgmentID) error
	ListJudgments(ctx context.Context, filter *ListFilter) ([]*Judgment, error)
}
