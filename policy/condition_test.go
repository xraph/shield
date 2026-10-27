package policy

import (
	"errors"
	"testing"
)

func TestParseCondition(t *testing.T) {
	for s, want := range map[string]Condition{
		"pii_detected":     {Kind: ConditionPIIDetected},
		" secret_detected": {Kind: ConditionSecretDetected},
		"finding":          {Kind: ConditionFinding},
		"score > 0.8":      {Kind: ConditionScore, Op: ">", Value: 0.8},
		"score>=0.9":       {Kind: ConditionScore, Op: ">=", Value: 0.9},
		"score <  1":       {Kind: ConditionScore, Op: "<", Value: 1},
		"score <= .5":      {Kind: ConditionScore, Op: "<=", Value: 0.5},
	} {
		got, err := ParseCondition(s)
		if err != nil || got != want {
			t.Errorf("%q: %+v %v, want %+v", s, got, err, want)
		}
	}
	for _, s := range []string{"", "score >>> 1", "score = 1", "score > x", "score > NaN", "score > Inf", "pii", "score", "finding x"} {
		if _, err := ParseCondition(s); !errors.Is(err, ErrInvalidCondition) {
			t.Errorf("%q: err = %v", s, err)
		}
	}
}
