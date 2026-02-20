// Package scan defines the input/output types and results for safety scans.
package scan

import (
	"time"

	"github.com/xraph/shield"
	"github.com/xraph/shield/id"
)

// Direction indicates whether content is input (user→agent) or output (agent→user).
type Direction string

const (
	DirectionInput  Direction = "input"
	DirectionOutput Direction = "output"
)

// Decision is the final verdict of a safety scan.
type Decision string

const (
	DecisionAllow  Decision = "allow"
	DecisionBlock  Decision = "block"
	DecisionFlag   Decision = "flag"
	DecisionRedact Decision = "redact"
)

// Input represents content to be scanned by the safety engine.
type Input struct {
	Text      string         `json:"text"`
	Direction Direction      `json:"direction"`
	Context   map[string]any `json:"context,omitempty"`  // additional context for judgment
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// Finding represents an individual detection from a safety layer.
type Finding struct {
	ID        id.FindingID   `json:"id"`
	Layer     string         `json:"layer"`      // "instinct", "awareness", "boundary", "values", "judgment", "reflex"
	Source    string         `json:"source"`     // name of the primitive that produced this finding
	Severity  string         `json:"severity"`   // "info", "warning", "error", "critical"
	Message   string         `json:"message"`
	Score     float64        `json:"score,omitempty"` // 0.0-1.0 confidence
	Action    string         `json:"action,omitempty"` // recommended action
	Details   map[string]any `json:"details,omitempty"`
}

// Result is the complete output of a safety scan.
type Result struct {
	shield.Entity
	ID            id.ScanID      `json:"id" bun:",pk"`
	Direction     Direction      `json:"direction" bun:",notnull"`
	Decision      Decision       `json:"decision" bun:",notnull"`
	Blocked       bool           `json:"blocked" bun:",notnull"`
	Findings      []*Finding     `json:"findings" bun:"type:jsonb"`
	Redacted      string         `json:"redacted,omitempty"` // PII-redacted version of text
	PIICount      int            `json:"pii_count,omitempty"`
	ProfileUsed   string         `json:"profile_used,omitempty"`
	PoliciesUsed  []string       `json:"policies_used,omitempty" bun:"type:jsonb"`
	TenantID      string         `json:"tenant_id" bun:",notnull"`
	AppID         string         `json:"app_id" bun:",notnull"`
	Duration      time.Duration  `json:"duration"`
	Metadata      map[string]any `json:"metadata,omitempty" bun:"type:jsonb"`
}

// HasPII returns true if the scan detected any PII.
func (r *Result) HasPII() bool {
	return r.PIICount > 0
}

// HasFindings returns true if the scan produced any findings.
func (r *Result) HasFindings() bool {
	return len(r.Findings) > 0
}
