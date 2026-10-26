package policy

import (
	"errors"
	"math"
	"strconv"
	"strings"
)

// Condition kinds a rule can test.
const (
	// ConditionPIIDetected holds when the scan found personal data.
	ConditionPIIDetected = "pii_detected"
	// ConditionSecretDetected holds when the scan found a secret.
	ConditionSecretDetected = "secret_detected"
	// ConditionFinding holds when the rule's check type has a finding.
	ConditionFinding = "finding"
	// ConditionScore compares the highest finding score of the rule's
	// check type with a number: "score >= 0.9".
	ConditionScore = "score"
)

// ErrInvalidCondition reports a rule condition outside the grammar.
var ErrInvalidCondition = errors.New("policy: invalid condition")

// Condition is a parsed rule condition.
type Condition struct {
	Kind  string  // one of the Condition constants
	Op    string  // ConditionScore only: >, >=, < or <=
	Value float64 // ConditionScore only
}

// ParseCondition parses a rule condition: pii_detected, secret_detected,
// finding, or score followed by >, >=, < or <= and a number. Spaces around
// the parts do not matter.
func ParseCondition(s string) (Condition, error) {
	s = strings.TrimSpace(s)
	switch s {
	case ConditionPIIDetected, ConditionSecretDetected, ConditionFinding:
		return Condition{Kind: s}, nil
	}
	rest, ok := strings.CutPrefix(s, ConditionScore)
	if !ok {
		return Condition{}, ErrInvalidCondition
	}
	rest = strings.TrimSpace(rest)
	var op string
	for _, candidate := range []string{">=", "<=", ">", "<"} {
		if after, found := strings.CutPrefix(rest, candidate); found {
			op, rest = candidate, after
			break
		}
	}
	if op == "" {
		return Condition{}, ErrInvalidCondition
	}
	value, err := strconv.ParseFloat(strings.TrimSpace(rest), 64)
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
		return Condition{}, ErrInvalidCondition
	}
	return Condition{Kind: ConditionScore, Op: op, Value: value}, nil
}

// Holds compares score with a score condition's number.
func (c Condition) Holds(score float64) bool {
	switch c.Op {
	case ">":
		return score > c.Value
	case ">=":
		return score >= c.Value
	case "<":
		return score < c.Value
	case "<=":
		return score <= c.Value
	default:
		return false
	}
}
