package storetest

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/xraph/shield"
	"github.com/xraph/shield/compliance"
	"github.com/xraph/shield/id"
	"github.com/xraph/shield/pii"
	"github.com/xraph/shield/store"
)

func testDashboardScopeAndNestedRoundTrip(t *testing.T, factory func(*testing.T) Backend) {
	s := factory(t)
	ctx := context.Background()
	a := store.Scope{TenantID: "tenant-a", AppID: "app-a"}
	b := store.Scope{TenantID: "tenant-b", AppID: "app-b"}
	rows := map[string]string{
		"instincts":  `{"name":"same","category":"injection","sensitivity":"balanced","action":"block","enabled":false,"strategies":[{"name":"classifier","weight":0,"config":{"nested":[1,2]}}]}`,
		"awareness":  `{"name":"same","focus":"pii","action":"redact","enabled":false,"detectors":[{"name":"email","focus":"pii","patterns":["@"],"config":{"x":true}}]}`,
		"boundaries": `{"name":"same","enabled":false,"limits":[{"scope":"topic","deny":["private"],"allow":[],"use_allow":false}],"response":"refuse"}`,
		"values":     `{"name":"same","action":"flag","severity":"warning","enabled":false,"rules":[{"principle":"honesty","threshold":0,"categories":["x"],"guidelines":["cite"],"config":{"x":0}}]}`,
		"judgments":  `{"name":"same","domain":"grounding","threshold":0,"action":"warn","enabled":false,"assessors":[{"name":"judge","domain":"grounding","weight":0,"requires_context":true,"config":{"x":1}}]}`,
		"reflexes":   `{"name":"same","priority":0,"enabled":false,"triggers":[{"type":"on_score","threshold":0,"window":"1m"}],"actions":[{"type":"flag","target":"output","value":{"x":1},"fallback":"review"}]}`,
		"profiles":   `{"name":"same","enabled":false,"instincts":[{"instinct_name":"same","sensitivity":"cautious"}],"awareness":[{"awareness_name":"same"}],"boundaries":["same"],"values":["same"],"judgments":[{"judgment_name":"same","threshold":0}],"reflexes":["same"]}`,
		"policies":   `{"name":"same","enabled":false,"rules":[{"check_type":"instinct","condition":"score > 0.5","action":"block","priority":0}]}`,
	}
	for kind, raw := range rows {
		t.Run(kind, func(t *testing.T) {
			r, err := s.DashboardCreate(ctx, a, kind, json.RawMessage(raw))
			if err != nil {
				t.Fatal(err)
			}
			var item map[string]any
			assertDashboardJSON(t, r, &item)
			key := dashboardID(t, item)
			if item["enabled"] != false {
				t.Fatal("false lost")
			}
			if _, err = s.DashboardGet(ctx, b, kind, key); err == nil {
				t.Fatal("foreign ID readable")
			}
			if _, err = s.DashboardUpdate(ctx, b, kind, key, r); err == nil {
				t.Fatal("foreign ID writable")
			}
			if err = s.DashboardDelete(ctx, b, kind, key); err == nil {
				t.Fatal("foreign ID deletable")
			}
			if _, err = s.DashboardCreate(ctx, b, kind, json.RawMessage(raw)); err != nil {
				t.Fatal(err)
			}
			page, err := s.DashboardList(ctx, a, kind, store.Filter{Limit: 1})
			if err != nil {
				t.Fatal(err)
			}
			if page.Total != 1 || len(page.Items) != 1 {
				t.Fatalf("bad paging: %+v", page)
			}
			got, err := s.DashboardGet(ctx, a, kind, key)
			if err != nil {
				t.Fatal(err)
			}
			var back map[string]any
			assertDashboardJSON(t, got, &back)
			var expected map[string]any
			assertDashboardJSON(t, []byte(raw), &expected)
			assertFields(t, expected, back)
		})
	}
	for _, kind := range []string{"instincts", "awareness", "boundaries", "values", "judgments", "reflexes"} {
		page, err := s.DashboardList(ctx, a, "profiles", store.Filter{Limit: 25, ReferenceKind: kind, ReferenceName: "same"})
		if err != nil || page.Total != 1 {
			t.Fatalf("%s reference filter: %+v %v", kind, page, err)
		}
		page, err = s.DashboardList(ctx, a, "profiles", store.Filter{Limit: 25, ReferenceKind: kind, ReferenceName: "missing"})
		if err != nil || page.Total != 0 {
			t.Fatalf("%s missing reference: %+v %v", kind, page, err)
		}
	}
	if _, err := s.DashboardList(ctx, store.Scope{}, "instincts", store.Filter{}); err == nil {
		t.Fatal("empty scope broadened")
	}
}

func testUpdateRevision(t *testing.T, factory func(*testing.T) Backend) {
	s := factory(t)
	ctx := context.Background()
	scope := store.Scope{TenantID: "revision", AppID: "revision"}
	made, err := s.DashboardCreate(ctx, scope, "boundaries", json.RawMessage(`{"name":"revision","enabled":true}`))
	if err != nil {
		t.Fatal(err)
	}
	var row map[string]any
	assertDashboardJSON(t, made, &row)
	key := dashboardID(t, row)
	before, err := s.DashboardGet(ctx, scope, "boundaries", key)
	if err != nil {
		t.Fatal(err)
	}
	assertDashboardJSON(t, before, &row)
	patch, err := json.Marshal(map[string]any{"enabled": false, "_expected_updated_at": row["updated_at"]})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DashboardUpdate(ctx, scope, "boundaries", key, patch); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DashboardUpdate(ctx, scope, "boundaries", key, patch); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale store revision accepted: %v", err)
	}
}

func assertFields(t *testing.T, expected, got any) {
	t.Helper()
	switch e := expected.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			t.Fatalf("expected object: %v", got)
		}
		for k, v := range e {
			assertFields(t, v, g[k])
		}
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(e) {
			t.Fatalf("array changed: %v != %v", e, got)
		}
		for i, v := range e {
			assertFields(t, v, g[i])
		}
	default:
		if expected != got {
			t.Fatalf("value lost: %v != %v", expected, got)
		}
	}
}

func testDashboardPagingClearAndAssignment(t *testing.T, factory func(*testing.T) Backend) {
	s := factory(t)
	ctx := context.Background()
	scope := store.Scope{TenantID: "a", AppID: "a"}
	for _, name := range []string{"one", "two", "three"} {
		if _, err := s.DashboardCreate(ctx, scope, "instincts", json.RawMessage(`{"name":"`+name+`","category":"injection","action":"block","strategies":[{"name":"x"}]}`)); err != nil {
			t.Fatal(err)
		}
	}
	page, err := s.DashboardList(ctx, scope, "instincts", store.Filter{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 3 || !page.HasMore {
		t.Fatal(page)
	}
	var first map[string]any
	assertDashboardJSON(t, page.Items[0], &first)
	key := dashboardID(t, first)
	got, err := s.DashboardUpdate(ctx, scope, "instincts", key, json.RawMessage(`{"enabled":false,"strategies":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	var cleared map[string]any
	assertDashboardJSON(t, got, &cleared)
	if cleared["enabled"] != false || !emptyDashboardArray(cleared["strategies"]) || cleared["name"] != "one" {
		t.Fatal(cleared)
	}
	next, err := s.DashboardList(ctx, scope, "instincts", store.Filter{Limit: 1, Offset: 1})
	if err != nil {
		t.Fatal(err)
	}
	if string(next.Items[0]) == string(page.Items[0]) {
		t.Fatal("page repeated")
	}
	// App-level policies belong to an app-scope (operator) actor, who assigns
	// them to tenants.
	operator := store.Scope{TenantID: "a", AppID: "a", PolicyKey: "a", PolicyLevel: "app"}
	pol, err := s.DashboardCreate(ctx, operator, "policies", json.RawMessage(`{"name":"policy","rules":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	assertDashboardJSON(t, pol, &p)
	pid := dashboardID(t, p)
	if p["scope_level"] != "app" || p["scope_key"] != "a" {
		t.Fatalf("operator policy scope = %v/%v", p["scope_key"], p["scope_level"])
	}
	if _, err = s.DashboardGet(ctx, scope, "policies", pid); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unassigned app policy visible to the tenant: %v", err)
	}
	if err = s.DashboardAssign(ctx, scope, pid, true); !errors.Is(err, store.ErrReadOnly) {
		t.Fatalf("tenant assigned an app policy: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err = s.DashboardAssign(ctx, operator, pid, true); err != nil {
			t.Fatal(err)
		}
	}
	assigned, err := s.DashboardAssigned(ctx, scope, pid)
	if err != nil || !assigned {
		t.Fatal(assigned, err)
	}
	if _, err = s.DashboardGet(ctx, scope, "policies", pid); err != nil {
		t.Fatalf("assigned app policy not visible to the tenant: %v", err)
	}
	if _, err = s.DashboardUpdate(ctx, scope, "policies", pid, json.RawMessage(`{"enabled":false}`)); !errors.Is(err, store.ErrReadOnly) {
		t.Fatalf("tenant changed an assigned app policy: %v", err)
	}
	if err = s.DashboardDelete(ctx, scope, "policies", pid); !errors.Is(err, store.ErrReadOnly) {
		t.Fatalf("tenant deleted an assigned app policy: %v", err)
	}
	if err = s.DashboardAssign(ctx, store.Scope{TenantID: "b", AppID: "b", PolicyKey: "b", PolicyLevel: "app"}, pid, true); err == nil {
		t.Fatal("foreign policy assigned")
	}
	if err = s.DashboardAssign(ctx, operator, pid, false); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DashboardAssigned(ctx, scope, pid); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unassigned policy still visible: %v", err)
	}
	assigned, err = s.DashboardAssigned(ctx, operator, pid)
	if err != nil || assigned {
		t.Fatal(assigned, err)
	}
}

// testDashboardPolicyTenancy pins that tenants of one app never reach each
// other's policies: tenant b cannot list, read, change, disable or delete
// tenant a's policy, and a tenant actor never writes the shared app scope.
func testDashboardPolicyTenancy(t *testing.T, factory func(*testing.T) Backend) {
	s := factory(t)
	ctx := context.Background()
	a := store.Scope{TenantID: "tenant-a", AppID: "shared"}
	b := store.Scope{TenantID: "tenant-b", AppID: "shared"}
	made, err := s.DashboardCreate(ctx, a, "policies", json.RawMessage(`{"name":"guard","enabled":true,"rules":[{"check_type":"instinct","condition":"finding","action":"flag"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	var row map[string]any
	assertDashboardJSON(t, made, &row)
	key := dashboardID(t, row)
	if row["scope_key"] != "tenant-a" || row["scope_level"] != "org" {
		t.Fatalf("tenant policy scope = %v/%v, want tenant-a/org", row["scope_key"], row["scope_level"])
	}
	page, err := s.DashboardList(ctx, b, "policies", store.Filter{Limit: 25})
	if err != nil || page.Total != 0 {
		t.Fatalf("tenant-b lists tenant-a's policy: %+v %v", page, err)
	}
	if _, err = s.DashboardGet(ctx, b, "policies", key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("tenant-b reads tenant-a's policy: %v", err)
	}
	if _, err = s.DashboardUpdate(ctx, b, "policies", key, json.RawMessage(`{"enabled":false}`)); err == nil {
		t.Fatal("tenant-b disabled tenant-a's policy")
	}
	if _, err = s.DashboardUpdate(ctx, b, "policies", key, json.RawMessage(`{"rules":[{"check_type":"instinct","condition":"score >= 0","action":"block"}]}`)); err == nil {
		t.Fatal("tenant-b edited tenant-a's policy")
	}
	if err = s.DashboardDelete(ctx, b, "policies", key); err == nil {
		t.Fatal("tenant-b deleted tenant-a's policy")
	}
	if err = s.DashboardAssign(ctx, b, key, true); err == nil {
		t.Fatal("tenant-b assigned tenant-a's policy")
	}
	got, err := s.DashboardGet(ctx, a, "policies", key)
	if err != nil {
		t.Fatal(err)
	}
	assertDashboardJSON(t, got, &row)
	if rules, ok := row["rules"].([]any); !ok || row["enabled"] != true || len(rules) != 1 {
		t.Fatalf("tenant-a's policy changed: %v", row)
	}
	if _, err = s.DashboardList(ctx, store.Scope{TenantID: "tenant-a", AppID: "shared", PolicyKey: "tenant-b", PolicyLevel: "org"}, "policies", store.Filter{}); !errors.Is(err, store.ErrScope) {
		t.Fatalf("an org policy key naming another tenant: %v", err)
	}
}

func testPrivacyMetadataAndBoundedRetention(t *testing.T, factory func(*testing.T) Backend) {
	s := factory(t)
	ctx := context.Background()
	a := store.Scope{TenantID: "a", AppID: "a"}
	b := store.Scope{TenantID: "b", AppID: "b"}
	cutoff := time.Now().UTC()
	expired := cutoff.Add(-time.Hour)
	for _, tenant := range []string{"a", "b"} {
		token := &pii.Token{ID: id.NewPIITokenID(), ScanID: id.NewScanID(), TenantID: tenant, PIIType: "email", Placeholder: "[EMAIL]", EncryptedValue: []byte("secret-ciphertext"), ExpiresAt: &expired}
		if err := s.StorePIITokens(ctx, []*pii.Token{token}); err != nil {
			t.Fatal(err)
		}
	}
	page, err := s.DashboardTokens(ctx, a, "", nil, store.Filter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 {
		t.Fatal(page)
	}
	if strings.Contains(string(page.Items[0]), "secret") || strings.Contains(string(page.Items[0]), "encrypted") {
		t.Fatal("secret exposed")
	}
	var token map[string]any
	assertDashboardJSON(t, page.Items[0], &token)
	key := dashboardID(t, token)
	if _, err = s.DashboardDeleteTokens(ctx, b, cutoff, []string{key}); err != nil {
		t.Fatal(err)
	}
	page, err = s.DashboardTokens(ctx, a, "", &cutoff, store.Filter{Limit: 100})
	if err != nil || page.Total != 1 {
		t.Fatal(page, err)
	}
	n, err := s.DashboardDeleteTokens(ctx, a, cutoff, []string{key})
	if err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if _, err = s.DashboardDeleteTokens(ctx, store.Scope{}, cutoff, []string{key}); err == nil {
		t.Fatal("empty tenant purge")
	}
	if _, err = s.DashboardDeleteTokens(ctx, a, cutoff, nil); err == nil {
		t.Fatal("empty selection purge")
	}
}

func testPrivacyTypeTotals(t *testing.T, factory func(*testing.T) Backend) {
	s := factory(t)
	ctx := context.Background()
	a := store.Scope{TenantID: "summary-a", AppID: "a"}
	for _, tenant := range []string{"summary-a", "summary-b"} {
		tokens := []*pii.Token{}
		for i := 0; i < 31; i++ {
			kind := "email"
			if i >= 28 {
				kind = "phone"
			}
			tokens = append(tokens, &pii.Token{ID: id.NewPIITokenID(), ScanID: id.NewScanID(), TenantID: tenant, PIIType: kind, Placeholder: "[REDACTED]", EncryptedValue: []byte("private")})
		}
		if err := s.StorePIITokens(ctx, tokens); err != nil {
			t.Fatal(err)
		}
	}
	stats, err := s.DashboardTokenStats(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != 31 || stats.DistinctTypes != 2 || stats.ByType["email"] != 28 || stats.ByType["phone"] != 3 {
		t.Fatalf("scoped totals across pages: %+v", stats)
	}
	if _, err = s.DashboardTokenStats(ctx, store.Scope{}); err == nil {
		t.Fatal("empty scope aggregate")
	}
}

// testReportTenancy pins that tenants of one app never reach each other's
// compliance reports, through the store API or the dashboard, and that
// app-level reports need the app scope: tenant b cannot see or delete
// tenant a's report, and no tenant reads the app's shared reports.
func testReportTenancy(t *testing.T, factory func(*testing.T) Backend) {
	s := factory(t)
	ctx := context.Background()
	a := tenantCtx("tenant-a", tenantApp)
	b := tenantCtx("tenant-b", tenantApp)
	operator := shield.WithApp(context.Background(), tenantApp)
	mine := newReport("tenant-a")
	if err := s.CreateReport(a, mine); err != nil {
		t.Fatal(err)
	}
	shared := newReport(tenantApp)
	shared.ScopeLevel = "app"
	if err := s.CreateReport(operator, shared); err != nil {
		t.Fatal(err)
	}

	// Store API.
	if _, err := s.GetReport(a, mine.ID); err != nil {
		t.Fatalf("owner read: %v", err)
	}
	if _, err := s.GetReport(b, mine.ID); !errors.Is(err, shield.ErrComplianceNotFound) {
		t.Fatalf("tenant-b reads tenant-a's report: %v", err)
	}
	if _, err := s.GetReport(a, shared.ID); !errors.Is(err, shield.ErrComplianceNotFound) {
		t.Fatalf("a tenant reads the app's report: %v", err)
	}
	if _, err := s.GetReport(operator, shared.ID); err != nil {
		t.Fatalf("operator read of the app report: %v", err)
	}
	if _, err := s.ListReports(b, &compliance.ListFilter{ScopeKey: "tenant-a"}); !errors.Is(err, shield.ErrTenantMismatch) {
		t.Fatalf("tenant-b lists tenant-a's reports: %v", err)
	}
	if _, err := s.ListReports(a, &compliance.ListFilter{ScopeKey: tenantApp}); !errors.Is(err, shield.ErrTenantMismatch) {
		t.Fatalf("a tenant lists the app's reports: %v", err)
	}

	// Dashboard.
	scopeA := store.Scope{TenantID: "tenant-a", AppID: tenantApp}
	scopeB := store.Scope{TenantID: "tenant-b", AppID: tenantApp}
	appScope := store.Scope{TenantID: "tenant-a", AppID: tenantApp, PolicyKey: tenantApp, PolicyLevel: "app"}
	for name, want := range map[string]struct {
		scope store.Scope
		total int64
	}{"tenant-a": {scopeA, 1}, "tenant-b": {scopeB, 0}, "app": {appScope, 1}} {
		page, err := s.DashboardList(ctx, want.scope, "compliance", store.Filter{Limit: 25})
		if err != nil || page.Total != want.total {
			t.Fatalf("%s lists %d reports (%v), want %d", name, page.Total, err, want.total)
		}
	}
	if _, err := s.DashboardGet(ctx, scopeB, "compliance", mine.ID.String()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("tenant-b reads tenant-a's report on the dashboard: %v", err)
	}
	if _, err := s.DashboardGet(ctx, scopeA, "compliance", shared.ID.String()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a tenant reads the app's report on the dashboard: %v", err)
	}
	if err := s.DashboardDelete(ctx, scopeB, "compliance", mine.ID.String()); err == nil {
		t.Fatal("tenant-b deleted tenant-a's report")
	}
	if _, err := s.DashboardGet(ctx, scopeA, "compliance", mine.ID.String()); err != nil {
		t.Fatalf("tenant-a's report gone: %v", err)
	}
}

type Backend interface {
	store.Store
	store.DashboardStore
	store.AssignmentStore
	store.PrivacyStore
	store.PrivacyStatsStore
}

func Run(t *testing.T, factory func(*testing.T) Backend) {
	RunTenancy(t, factory)
	t.Run("update-revision", func(t *testing.T) { testUpdateRevision(t, factory) })
	t.Run("scope-and-round-trip", func(t *testing.T) { testDashboardScopeAndNestedRoundTrip(t, factory) })
	t.Run("paging-and-assignment", func(t *testing.T) { testDashboardPagingClearAndAssignment(t, factory) })
	t.Run("policy-tenancy", func(t *testing.T) { testDashboardPolicyTenancy(t, factory) })
	t.Run("report-tenancy", func(t *testing.T) { testReportTenancy(t, factory) })
	t.Run("privacy-type-totals", func(t *testing.T) { testPrivacyTypeTotals(t, factory) })
	t.Run("privacy-and-retention", func(t *testing.T) { testPrivacyMetadataAndBoundedRetention(t, factory) })
}

func assertDashboardJSON(t *testing.T, raw []byte, target any) {
	t.Helper()
	if err := json.Unmarshal(raw, target); err != nil {
		t.Fatal(err)
	}
}
func dashboardID(t *testing.T, row map[string]any) string {
	t.Helper()
	value, ok := row["id"].(string)
	if !ok {
		t.Fatalf("expected string ID: %v", row["id"])
	}
	return value
}
func emptyDashboardArray(value any) bool {
	items, ok := value.([]any)
	return ok && len(items) == 0
}
