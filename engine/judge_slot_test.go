package engine

import (
	"context"
	"testing"
	"time"

	"github.com/xraph/shield"
	"github.com/xraph/shield/judgment"
	"github.com/xraph/shield/scan"
)

type scoreJudge struct{}

func (scoreJudge) Assess(context.Context, *judgment.JudgeRequest) (*judgment.JudgeVerdict, error) {
	return &judgment.JudgeVerdict{Score: 0.5}, nil
}

// A panic while the judge's request is built must not hold a judge slot:
// with one slot, a leaked one would leave every later scan's judge busy.
func TestJudgeRequestPanicHoldsNoSlot(t *testing.T) {
	cfg := shield.DefaultConfig()
	cfg.ModelJudge, cfg.JudgeConcurrency, cfg.JudgeTimeout = true, 1, 50*time.Millisecond
	e, err := New(WithConfig(cfg), WithJudge(scoreJudge{}))
	if err != nil {
		t.Fatal(err)
	}
	// No compiled profile, so naming the judgments panics.
	broken := &evaluation{input: &scan.Input{Text: "hello", Direction: scan.DirectionInput}}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("building the request did not panic")
			}
		}()
		e.callJudge(context.Background(), broken)
	}()
	if n := len(e.judgeSlots); n != 0 {
		t.Fatalf("%d judge slots held after the panic, want 0", n)
	}
	ok := &evaluation{input: broken.input, profile: &compiledProfile{}}
	ok.setUnits()
	if v, cause := e.callJudge(context.Background(), ok); v == nil || cause != judgeAnswered {
		t.Fatalf("the next call got %v, %q", v, cause)
	}
}
