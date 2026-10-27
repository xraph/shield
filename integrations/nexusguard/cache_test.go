package nexusguard_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/xraph/nexus/guard"
	"github.com/xraph/nexus/provider"

	"github.com/xraph/shield"
	"github.com/xraph/shield/engine"
	"github.com/xraph/shield/instinct"
	"github.com/xraph/shield/integrations/nexusguard"
	"github.com/xraph/shield/presets"
	"github.com/xraph/shield/scan"
)

// agentLoop runs turns checks of g over a history that gains one tool result
// per turn, sending the history as the host keeps it (unguarded).
func agentLoop(t *testing.T, g guard.Guard, turns int) {
	t.Helper()
	history := make([]provider.Message, 0, 1+turns)
	history = append(history, provider.Message{Role: "system", Content: "You are the deploy agent."})
	for i := range turns {
		history = append(history, provider.Message{Role: "tool", Content: fmt.Sprintf("step %d: 3 pods ready", i)})
		if _, err := g.Check(context.Background(), &guard.CheckInput{Messages: history, TenantID: testTenant}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestVerdictCacheScansEachMessageOnce(t *testing.T) {
	r := newRig(t)
	agentLoop(t, inputGuard(r), 20)
	if n := len(r.scans(t)); n != 20 {
		t.Errorf("%d scans for 20 turns, want 20", n)
	}
}

func TestVerdictCacheOff(t *testing.T) {
	r := newRig(t)
	agentLoop(t, inputGuard(r, nexusguard.WithVerdictCache(0)), 5)
	if n := len(r.scans(t)); n != 15 {
		t.Errorf("%d scans for 5 turns without a cache, want 15", n)
	}
}

func TestVerdictCacheAnswersWithTheSameText(t *testing.T) {
	r := newRig(t)
	g := inputGuard(r)
	in := &guard.CheckInput{Messages: []provider.Message{{Role: "tool", Content: toolLog()}}, TenantID: testTenant}
	first, err := g.Check(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	second, err := g.Check(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Modified || second.Messages[0].Content != first.Messages[0].Content || second.Action != first.Action {
		t.Errorf("cached result %+v, first %+v", second, first)
	}
	if fmt.Sprint(second.Details["scan_ids"]) != fmt.Sprint(first.Details["scan_ids"]) {
		t.Errorf("scan ids %v, first %v", second.Details["scan_ids"], first.Details["scan_ids"])
	}
	if n := len(r.scans(t)); n != 1 {
		t.Errorf("%d scans, want 1", n)
	}
}

func TestVerdictCacheFollowsProfileChanges(t *testing.T) {
	r := newRig(t)
	r.instinctProfile(t, "edited", instinct.ActionFlag)
	g := inputGuard(r, nexusguard.WithProfile("edited"), nexusguard.WithUntrustedRoles())
	in := &guard.CheckInput{Messages: []provider.Message{{Role: "user", Content: "please " + injectionLine}}, TenantID: testTenant}
	res, err := g.Check(context.Background(), in)
	if err != nil || res.Action != guard.ActionWarn {
		t.Fatalf("result %+v, err %v", res, err)
	}
	inst, err := r.st.GetInstinctByName(tenantCtx(), testApp, "edited")
	if err != nil {
		t.Fatal(err)
	}
	inst.Action = instinct.ActionBlock
	if err = r.st.UpdateInstinct(tenantCtx(), inst); err != nil {
		t.Fatal(err)
	}
	r.eng.InvalidateProfiles(testTenant)
	if res, err = g.Check(context.Background(), in); err != nil || !res.Blocked {
		t.Fatalf("after the edit: result %+v, err %v", res, err)
	}
	// A block is never cached: lifting it takes effect on the next check.
	inst.Action = instinct.ActionFlag
	if err = r.st.UpdateInstinct(tenantCtx(), inst); err != nil {
		t.Fatal(err)
	}
	r.eng.InvalidateProfiles(testTenant)
	if res, err = g.Check(context.Background(), in); err != nil || res.Blocked || res.Action != guard.ActionWarn {
		t.Fatalf("after lifting the block: result %+v, err %v", res, err)
	}
	if n := len(r.scans(t)); n != 3 {
		t.Errorf("%d scans, want 3", n)
	}
}

func TestVerdictCacheNeverHoldsABlock(t *testing.T) {
	r := newRig(t)
	r.instinctProfile(t, "blocking", instinct.ActionBlock)
	g := inputGuard(r, nexusguard.WithProfile("blocking"))
	in := &guard.CheckInput{Messages: []provider.Message{{Role: "user", Content: injectionLine}}, TenantID: testTenant}
	for range 3 {
		if res, err := g.Check(context.Background(), in); err != nil || !res.Blocked {
			t.Fatalf("result %+v, err %v", res, err)
		}
	}
	if n := len(r.scans(t)); n != 3 {
		t.Errorf("%d scans, want 3", n)
	}
}

func TestVerdictCacheExpiresWithTheProfileTTL(t *testing.T) {
	cfg := shield.DefaultConfig()
	cfg.ProfileCacheTTL = 20 * time.Millisecond
	r := newRig(t, engine.WithConfig(cfg))
	g := inputGuard(r)
	in := &guard.CheckInput{Messages: []provider.Message{{Role: "tool", Content: "3 pods ready"}}, TenantID: testTenant}
	for range 2 {
		if _, err := g.Check(context.Background(), in); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(40 * time.Millisecond)
	if _, err := g.Check(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if n := len(r.scans(t)); n != 2 {
		t.Errorf("%d scans, want 2 (one cached, one after expiry)", n)
	}
}

func TestVerdictCacheKeepsTenantsApart(t *testing.T) {
	r := newRig(t)
	if _, err := presets.InfraAgent().Seed(context.Background(), r.st, "tenant-b", testApp); err != nil {
		t.Fatal(err)
	}
	g := inputGuard(r)
	msgs := []provider.Message{{Role: "tool", Content: "3 pods ready"}}
	for _, tenant := range []string{testTenant, "tenant-b", testTenant, "tenant-b"} {
		if _, err := g.Check(context.Background(), &guard.CheckInput{Messages: msgs, TenantID: tenant}); err != nil {
			t.Fatal(err)
		}
	}
	for _, tenant := range []string{testTenant, "tenant-b"} {
		got, err := r.st.ListScans(context.Background(), &scan.ListFilter{TenantID: tenant, AppID: testApp})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].TenantID != tenant {
			t.Errorf("%s: %d scans", tenant, len(got))
		}
	}
}

// A host that sends back the history the guard already quoted gets each
// message quoted once, not once more per turn.
func TestGuardDoesNotNestItsOwnQuotes(t *testing.T) {
	r := newRig(t)
	g := inputGuard(r)
	in := &guard.CheckInput{Messages: []provider.Message{{Role: "tool", Content: toolLog()}}, TenantID: testTenant}
	first, err := g.Check(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	again, err := g.Check(context.Background(), &guard.CheckInput{Messages: first.Messages, TenantID: testTenant})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := again.Messages[0].Content.(string)
	if got != first.Messages[0].Content || strings.Count(got, "<untrusted_content") != 1 {
		t.Errorf("re-guarded content %q", got)
	}
}

func TestOutputGuardScansEveryReplyRole(t *testing.T) {
	r := newRig(t)
	res, err := outputGuard(r).Check(context.Background(), &guard.CheckInput{
		Messages: []provider.Message{{Role: "model", Content: "key " + awsAccessKey()}}, TenantID: testTenant,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := res.Messages[0].Content.(string); !res.Modified || strings.Contains(got, awsAccessKey()) {
		t.Errorf("result %+v", res)
	}
}
