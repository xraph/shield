package engine_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/xraph/shield/awareness"
	"github.com/xraph/shield/boundary"
	"github.com/xraph/shield/id"
	"github.com/xraph/shield/instinct"
	"github.com/xraph/shield/judgment"
	"github.com/xraph/shield/policy"
	"github.com/xraph/shield/profile"
	"github.com/xraph/shield/reflex"
	"github.com/xraph/shield/scan"
	"github.com/xraph/shield/values"
)

// The hooks the recorder in evaluate_test.go does not implement yet, so it
// implements every plugin hook interface.

func (r *recorder) OnJudgmentAssessed(_ context.Context, _ id.ScanID, name, level string, risk float64) error {
	r.note("judgment_assessed", fmt.Sprintf("%s:%s:%.2f", name, level, risk))
	return nil
}
func (r *recorder) OnValueViolated(_ context.Context, _ id.ScanID, name, severity string) error {
	r.note("value_violated", name+":"+severity)
	return nil
}
func (r *recorder) OnReflexFired(_ context.Context, _ id.ScanID, name, action string) error {
	r.note("reflex_fired", name+":"+action)
	return nil
}
func (r *recorder) OnBoundaryEnforced(_ context.Context, _ id.ScanID, name string) error {
	r.note("boundary_enforced", name)
	return nil
}
func (r *recorder) OnPolicyEvaluated(_ context.Context, _ id.ScanID, name, decision string) error {
	r.note("policy_evaluated", name+":"+decision)
	return nil
}
func (r *recorder) OnShutdown(context.Context) error {
	r.note("shutdown", "")
	return nil
}

func TestEveryHookFires(t *testing.T) {
	r := newRig(t, nil)
	ctx := tenantCtx("tenant-a")
	r.instinct(ctx, t, "prompt-injection", instinct.ActionFlag)
	r.awareness(ctx, t, "pii", awareness.FocusPII, "redact", awareness.Detector{Name: "email", Focus: awareness.FocusPII})
	r.boundary(ctx, t, "no-certs", "", boundary.Limit{Scope: boundary.ScopeOutput, Deny: []string{"begin certificate"}})
	r.values(ctx, t, "destructive-commands", "flag", "warning", values.Rule{Principle: values.PrincipleSafety})
	r.judgment(ctx, t, "pressure", "flag", 0.5, judgment.Assessor{Name: "layer_score", Config: map[string]any{"layers": []any{"instinct"}}})
	r.reflex(ctx, t, "audit", 0, []reflex.Trigger{{Type: reflex.TriggerAlways}}, reflex.Action{Type: reflex.ActionLog})
	r.safetyProfile(ctx, t, &profile.SafetyProfile{
		Name:       "p",
		Instincts:  []profile.InstinctAssignment{{InstinctName: "prompt-injection"}},
		Awareness:  []profile.AwarenessAssignment{{AwarenessName: "pii"}},
		Boundaries: []string{"no-certs"},
		Values:     []string{"destructive-commands"},
		Judgments:  []profile.JudgmentAssignment{{JudgmentName: "pressure"}},
		Reflexes:   []string{"audit"},
	})
	r.policy(t, "guard", policy.ScopeOrg, "tenant-a", policy.Rule{CheckType: "instinct", Condition: "finding", Action: "flag"})

	text := injectionCommit + "\nmail " + email + "\nthen run rm -rf / now\n-----BEGIN CERTIFICATE-----"
	// Input: everything but the output boundary fires, and the e-mail is
	// redacted.
	if res := scanText(ctx, t, r, &scan.Input{Text: text, Profile: "p"}); res.Decision != scan.DecisionRedact {
		t.Fatalf("input decision = %s %+v", res.Decision, res.Findings)
	}
	// Output: the boundary blocks.
	if res, err := r.eng.ScanOutput(ctx, &scan.Input{Text: text, Profile: "p"}); err != nil || res.Decision != scan.DecisionBlock {
		t.Fatalf("output: %+v %v", res, err)
	}
	// A failing scan: the profile does not exist.
	if _, err := r.eng.ScanInput(ctx, &scan.Input{Text: text, Profile: "missing"}); err == nil {
		t.Fatal("scan with a missing profile succeeded")
	}
	if err := r.eng.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	for _, hook := range []string{
		"scan_started", "scan_completed", "scan_blocked", "scan_failed", "instinct_triggered", "awareness_detected",
		"judgment_assessed", "value_violated", "reflex_fired", "boundary_enforced", "pii_detected", "pii_redacted",
		"policy_evaluated", "profile_resolved", "shutdown",
	} {
		if r.rec.count(hook) == 0 {
			t.Errorf("%s never fired", hook)
		}
	}
}
