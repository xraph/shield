package storetest

import (
	"testing"
	"time"

	"github.com/xraph/shield/awareness"
	"github.com/xraph/shield/boundary"
	"github.com/xraph/shield/compliance"
	"github.com/xraph/shield/id"
	"github.com/xraph/shield/instinct"
	"github.com/xraph/shield/judgment"
	"github.com/xraph/shield/policy"
	"github.com/xraph/shield/profile"
	"github.com/xraph/shield/reflex"
	"github.com/xraph/shield/scan"
	"github.com/xraph/shield/values"
)

// testNilCollections writes every row kind that holds a collection through
// the engine-facing store with each slice and map left nil, creates and then
// updates, and reads each one back. Postgres keeps collections in NOT NULL
// jsonb columns, so a backend must write a nil collection as an empty one.
// PII tokens hold no collection; a token without ciphertext stays an error.
func testNilCollections(t *testing.T, factory func(*testing.T) Backend) {
	s := factory(t)
	const tenant = "tenant-a"
	ctx := tenantCtx(tenant, tenantApp)
	check := func(t *testing.T, what string, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}

	t.Run("instincts", func(t *testing.T) {
		v := &instinct.Instinct{ID: id.NewInstinctID(), Name: "nil-collections", AppID: tenantApp, Category: "injection", Action: "block"}
		check(t, "create", s.CreateInstinct(ctx, v))
		check(t, "update", s.UpdateInstinct(ctx, v))
		check(t, "get", second(s.GetInstinct(ctx, v.ID)))
		check(t, "list", second(s.ListInstincts(ctx, &instinct.ListFilter{AppID: tenantApp})))
	})
	t.Run("awareness", func(t *testing.T) {
		v := &awareness.Awareness{ID: id.NewAwarenessID(), Name: "nil-collections", AppID: tenantApp, Focus: "pii", Action: "redact"}
		check(t, "create", s.CreateAwareness(ctx, v))
		check(t, "update", s.UpdateAwareness(ctx, v))
		check(t, "get", second(s.GetAwareness(ctx, v.ID)))
		check(t, "list", second(s.ListAwareness(ctx, &awareness.ListFilter{AppID: tenantApp})))
	})
	t.Run("boundaries", func(t *testing.T) {
		v := &boundary.Boundary{ID: id.NewBoundaryID(), Name: "nil-collections", AppID: tenantApp}
		check(t, "create", s.CreateBoundary(ctx, v))
		check(t, "update", s.UpdateBoundary(ctx, v))
		check(t, "get", second(s.GetBoundary(ctx, v.ID)))
		check(t, "list", second(s.ListBoundaries(ctx, &boundary.ListFilter{AppID: tenantApp})))
	})
	t.Run("values", func(t *testing.T) {
		v := &values.Values{ID: id.NewValueID(), Name: "nil-collections", AppID: tenantApp, Severity: "warning", Action: "flag"}
		check(t, "create", s.CreateValues(ctx, v))
		check(t, "update", s.UpdateValues(ctx, v))
		check(t, "get", second(s.GetValues(ctx, v.ID)))
		check(t, "list", second(s.ListValues(ctx, &values.ListFilter{AppID: tenantApp})))
	})
	t.Run("judgments", func(t *testing.T) {
		v := &judgment.Judgment{ID: id.NewJudgmentID(), Name: "nil-collections", AppID: tenantApp, Domain: "grounding", Action: "flag"}
		check(t, "create", s.CreateJudgment(ctx, v))
		check(t, "update", s.UpdateJudgment(ctx, v))
		check(t, "get", second(s.GetJudgment(ctx, v.ID)))
		check(t, "list", second(s.ListJudgments(ctx, &judgment.ListFilter{AppID: tenantApp})))
	})
	t.Run("reflexes", func(t *testing.T) {
		v := &reflex.Reflex{ID: id.NewReflexID(), Name: "nil-collections", AppID: tenantApp}
		check(t, "create", s.CreateReflex(ctx, v))
		check(t, "update", s.UpdateReflex(ctx, v))
		check(t, "get", second(s.GetReflex(ctx, v.ID)))
		check(t, "list", second(s.ListReflexes(ctx, &reflex.ListFilter{AppID: tenantApp})))
	})
	t.Run("profiles", func(t *testing.T) {
		v := &profile.SafetyProfile{ID: id.NewSafetyProfileID(), Name: "nil-collections", AppID: tenantApp}
		check(t, "create", s.CreateProfile(ctx, v))
		check(t, "update", s.UpdateProfile(ctx, v))
		check(t, "get", second(s.GetProfile(ctx, v.ID)))
		check(t, "list", second(s.ListProfiles(ctx, &profile.ListFilter{AppID: tenantApp})))
	})
	t.Run("policies", func(t *testing.T) {
		v := &policy.Policy{ID: id.NewPolicyID(), Name: "nil-collections", ScopeKey: tenant, ScopeLevel: policy.ScopeOrg, Enabled: true}
		check(t, "create", s.CreatePolicy(ctx, v))
		check(t, "update", s.UpdatePolicy(ctx, v))
		check(t, "get", second(s.GetPolicy(ctx, v.ID)))
		check(t, "for scope", second(s.GetPoliciesForScope(ctx, tenant, policy.ScopeOrg)))
	})
	t.Run("scans", func(t *testing.T) {
		v := &scan.Result{ID: id.NewScanID(), Direction: scan.DirectionInput, Decision: scan.DecisionAllow, TenantID: tenant, AppID: tenantApp}
		check(t, "create", s.CreateScan(ctx, v))
		check(t, "get", second(s.GetScan(ctx, v.ID)))
		check(t, "list", second(s.ListScans(ctx, &scan.ListFilter{TenantID: tenant})))
	})
	t.Run("compliance", func(t *testing.T) {
		n := time.Now().UTC()
		v := &compliance.Report{ID: id.NewComplianceReportID(), Framework: compliance.FrameworkSOC2, ScopeKey: tenant, ScopeLevel: "org", PeriodStart: n.Add(-time.Hour), PeriodEnd: n, GeneratedAt: n}
		check(t, "create", s.CreateReport(ctx, v))
		check(t, "get", second(s.GetReport(ctx, v.ID)))
	})
}
