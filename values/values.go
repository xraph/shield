// Package values models the moral compass and ethical guidelines of an agent.
//
// Values are the rules and principles that govern what is acceptable.
// Toxicity detection is a values question: "Does this violate our
// ethical standards?" Brand safety is a values question: "Does this
// align with our brand principles?" Values evaluate content against
// principles with configurable thresholds and severity levels.
package values

import (
	"context"

	"github.com/xraph/shield"
	"github.com/xraph/shield/id"
)

// Principle defines a specific ethical or moral rule category.
type Principle string

const (
	// PrincipleToxicity evaluates for toxic, harmful, or hateful content.
	PrincipleToxicity Principle = "toxicity"
	// PrincipleBrandSafety evaluates content alignment with brand guidelines.
	PrincipleBrandSafety Principle = "brand_safety"
	// PrincipleHonesty evaluates for deception or misleading content.
	PrincipleHonesty Principle = "honesty"
	// PrincipleRespect evaluates for respectful communication.
	PrincipleRespect Principle = "respect"
	// PrincipleSafety evaluates for dangerous instructions or content.
	PrincipleSafety Principle = "safety"
	// PrinciplePrivacy evaluates for privacy violations.
	PrinciplePrivacy Principle = "privacy"
	// PrincipleCustom is a user-defined principle.
	PrincipleCustom Principle = "custom"
)

// Rule defines a specific value enforcement rule.
type Rule struct {
	Principle  Principle      `json:"principle"`
	Threshold  float64        `json:"threshold,omitempty"`  // score threshold (0.0-1.0)
	Categories []string       `json:"categories,omitempty"` // e.g., toxicity subcategories
	Guidelines []string       `json:"guidelines,omitempty"` // brand guidelines as text
	Config     map[string]any `json:"config,omitempty"`
}

// Values represents the moral compass and ethical guidelines.
// Values are the fourth layer of the safety engine — they evaluate
// content against ethical principles with configurable thresholds.
type Values struct {
	shield.Entity
	ID          id.ValueID     `json:"id" bun:",pk"`
	Name        string         `json:"name" bun:",notnull"`
	Description string         `json:"description,omitempty"`
	AppID       string         `json:"app_id" bun:",notnull"`
	TenantID    string         `json:"tenant_id,omitempty"`
	Rules       []Rule         `json:"rules,omitempty" bun:"type:jsonb"`
	Severity    string         `json:"severity,omitempty" bun:",default:'warning'"` // how seriously violations are treated
	Action      string         `json:"action" bun:",notnull"`                       // "block", "flag", "warn"
	Enabled     bool           `json:"enabled" bun:",notnull,default:true"`
	Metadata    map[string]any `json:"metadata,omitempty" bun:"type:jsonb"`
}

// ListFilter defines filtering options for listing values.
type ListFilter struct {
	AppID    string
	TenantID string
	Enabled  *bool
	Limit    int
	Offset   int
}

// Store defines persistence operations for values.
type Store interface {
	CreateValues(ctx context.Context, v *Values) error
	GetValues(ctx context.Context, vID id.ValueID) (*Values, error)
	GetValuesByName(ctx context.Context, appID, name string) (*Values, error)
	UpdateValues(ctx context.Context, v *Values) error
	DeleteValues(ctx context.Context, vID id.ValueID) error
	ListValues(ctx context.Context, filter *ListFilter) ([]*Values, error)
}
