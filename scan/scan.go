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
	// DirectionToolCall marks a scan of a proposed tool call.
	DirectionToolCall Direction = "tool_call"
)

// Decision is the final verdict of a safety scan.
type Decision string

const (
	DecisionAllow  Decision = "allow"
	DecisionBlock  Decision = "block"
	DecisionFlag   Decision = "flag"
	DecisionRedact Decision = "redact"
	// DecisionRequireApproval asks a person to approve a tool call. Text
	// scans never return it.
	DecisionRequireApproval Decision = "require_approval"
)

// Input represents content to be scanned by the safety engine.
type Input struct {
	Text      string         `json:"text"`
	Direction Direction      `json:"direction"`
	Context   map[string]any `json:"context,omitempty"`  // additional context for judgment
	Metadata  map[string]any `json:"metadata,omitempty"` // copied onto the stored scan

	// Profile names the safety profile to evaluate. Empty uses
	// shield.Config.DefaultProfile.
	Profile string `json:"profile,omitempty"`
	// Source says where the text came from, such as "commit_message" or
	// "log_line". Quote puts it on the wrapper of untrusted text.
	Source string `json:"source,omitempty"`
	// Untrusted marks text from outside the operator. Unless the scan
	// blocks, Result.Redacted is then always set to the quoted text, ready
	// to hand to a model.
	Untrusted bool `json:"untrusted,omitempty"`
}

// Finding represents an individual detection from a safety layer.
type Finding struct {
	ID       id.FindingID   `json:"id"`
	Layer    string         `json:"layer"`    // "instinct", "awareness", "boundary", "values", "judgment", "reflex"
	Source   string         `json:"source"`   // name of the primitive that produced this finding
	Severity string         `json:"severity"` // "info", "warning", "error", "critical"
	Message  string         `json:"message"`
	Score    float64        `json:"score,omitempty"`  // 0.0-1.0 confidence
	Action   string         `json:"action,omitempty"` // recommended action
	Details  map[string]any `json:"details,omitempty"`
}

// Result is the complete output of a safety scan.
type Result struct {
	shield.Entity
	ID           id.ScanID      `json:"id" bun:",pk"`
	Direction    Direction      `json:"direction" bun:",notnull"`
	Decision     Decision       `json:"decision" bun:",notnull"`
	Blocked      bool           `json:"blocked" bun:",notnull"`
	Findings     []*Finding     `json:"findings" bun:"type:jsonb"`
	Redacted     string         `json:"redacted,omitempty"` // text to use in place of the input; see Input.Untrusted
	PIICount     int            `json:"pii_count,omitempty"`
	ProfileUsed  string         `json:"profile_used,omitempty"`
	PoliciesUsed []string       `json:"policies_used,omitempty" bun:"type:jsonb"`
	TenantID     string         `json:"tenant_id" bun:",notnull"`
	AppID        string         `json:"app_id" bun:",notnull"`
	Duration     time.Duration  `json:"duration"`
	Metadata     map[string]any `json:"metadata,omitempty" bun:"type:jsonb"`
}

// HasPII returns true if the scan detected any PII.
func (r *Result) HasPII() bool {
	return r.PIICount > 0
}

// HasFindings returns true if the scan produced any findings.
func (r *Result) HasFindings() bool {
	return len(r.Findings) > 0
}

// decisionRank orders decisions from least to most restrictive.
var decisionRank = map[Decision]int{
	DecisionAllow:           0,
	DecisionFlag:            1,
	DecisionRedact:          2,
	DecisionRequireApproval: 3,
	DecisionBlock:           4,
}

// Stricter returns the more restrictive of a and b, in the order allow <
// flag < redact < require_approval < block. An unknown decision counts as
// block, so a host combining its own verdict with a scan's fails closed.
func Stricter(a, b Decision) Decision {
	ra, okA := decisionRank[a]
	rb, okB := decisionRank[b]
	if !okA || !okB {
		return DecisionBlock
	}
	if rb > ra {
		return b
	}
	return a
}

// ActionDecision returns the decision a finding's action asks for on a text
// scan: block and throttle block; redact, vault, quote and rewrite redact;
// flag, alert, warn and escalate flag; log and info allow. Any other action
// blocks, so an unknown action fails closed.
func ActionDecision(action string) Decision {
	switch action {
	case "block", "throttle":
		return DecisionBlock
	case "redact", "vault", "quote", "rewrite":
		return DecisionRedact
	case "flag", "alert", "warn", "escalate":
		return DecisionFlag
	case "log", "info":
		return DecisionAllow
	default:
		return DecisionBlock
	}
}

// Reason returns the message of the first finding whose action produced the
// final decision, or "" when the scan allowed the text.
func (r *Result) Reason() string {
	if r.Decision == DecisionAllow {
		return ""
	}
	for _, f := range r.Findings {
		if f != nil && ActionDecision(f.Action) == r.Decision {
			return f.Message
		}
	}
	return ""
}
