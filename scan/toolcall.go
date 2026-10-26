package scan

import "encoding/json"

// RiskUnknown is the risk class of a tool call that names none. An empty
// class is never read as a safe one.
const RiskUnknown = "unknown"

// ToolCallInput is a tool call an agent proposes, for engine.ScanToolCall.
type ToolCallInput struct {
	// Tool is the name of the tool. It is required.
	Tool string `json:"tool"`
	// Arguments are the call's JSON arguments, untrusted. Empty and null
	// mean none.
	Arguments json.RawMessage `json:"arguments,omitempty"`
	// RiskClass is the host's own class for the call, such as "read" or
	// "destroy_production". Empty means RiskUnknown.
	RiskClass string `json:"risk_class,omitempty"`
	// Metadata is copied onto the stored scan, and on_context reflexes
	// match its keys.
	Metadata map[string]string `json:"metadata,omitempty"`
	// Profile names the safety profile to evaluate. Empty uses
	// shield.Config.DefaultProfile.
	Profile string `json:"profile,omitempty"`
}

// ToolCallActionDecision returns the decision a finding's action asks for on
// a tool call, which is only ever allow, block or require_approval. Actions
// that block a text scan block the call. Flag, alert and warn allow it, so
// the finding reaches the host without sending every flag to a person; log
// and info allow it too. Escalate, and every action a text scan answers by
// redacting, quoting or rewriting the text, asks a person, since none of
// them can change a call. An unknown action blocks, as ActionDecision does.
func ToolCallActionDecision(action string) Decision {
	if action == "escalate" {
		return DecisionRequireApproval
	}
	switch d := ActionDecision(action); d {
	case DecisionBlock, DecisionAllow:
		return d
	case DecisionFlag:
		return DecisionAllow
	default:
		return DecisionRequireApproval
	}
}

// actionDecision returns the decision an action asks for on a scan in
// direction d.
func actionDecision(d Direction, action string) Decision {
	if d == DirectionToolCall {
		return ToolCallActionDecision(action)
	}
	return ActionDecision(action)
}
