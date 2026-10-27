package storetest

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/xraph/shield"
	"github.com/xraph/shield/awareness"
	"github.com/xraph/shield/boundary"
	"github.com/xraph/shield/compliance"
	"github.com/xraph/shield/id"
	"github.com/xraph/shield/instinct"
	"github.com/xraph/shield/judgment"
	"github.com/xraph/shield/pii"
	"github.com/xraph/shield/policy"
	"github.com/xraph/shield/profile"
	"github.com/xraph/shield/reflex"
	"github.com/xraph/shield/scan"
	"github.com/xraph/shield/store"
	"github.com/xraph/shield/values"
)

// RunTenancy checks that primitive names are unique per (app, tenant), not per
// app, and that the engine-facing store never reads or changes another
// tenant's rows.
func RunTenancy(t *testing.T, factory func(*testing.T) Backend) {
	t.Run("same-name-in-each-tenant", func(t *testing.T) { testSameNameInEachTenant(t, factory) })
	t.Run("empty-tenant-is-an-error", func(t *testing.T) { testEmptyTenantIsAnError(t, factory) })
	t.Run("foreign-ids-are-invisible", func(t *testing.T) { testForeignIDsAreInvisible(t, factory) })
	t.Run("filter-tenant-must-match-context", func(t *testing.T) { testFilterTenantMustMatchContext(t, factory) })
	t.Run("by-name-reads-the-context-tenant", func(t *testing.T) { testByNameReadsTheContextTenant(t, factory) })
	t.Run("policy-scopes", func(t *testing.T) { testPolicyScopes(t, factory) })
}

func testSameNameInEachTenant(t *testing.T, factory func(*testing.T) Backend) {
	s := factory(t)
	ctx := context.Background()
	a := store.Scope{TenantID: "tenant-a", AppID: "app-a"}
	b := store.Scope{TenantID: "tenant-b", AppID: "app-a"}
	rows := map[string]string{
		"instincts":  `{"name":"same","category":"injection","action":"block"}`,
		"awareness":  `{"name":"same","focus":"pii","action":"redact"}`,
		"boundaries": `{"name":"same"}`,
		"values":     `{"name":"same","action":"flag","severity":"warning"}`,
		"judgments":  `{"name":"same","domain":"grounding","action":"warn"}`,
		"reflexes":   `{"name":"same"}`,
		"profiles":   `{"name":"same"}`,
	}
	for kind, raw := range rows {
		t.Run(kind, func(t *testing.T) {
			if _, err := s.DashboardCreate(ctx, a, kind, json.RawMessage(raw)); err != nil {
				t.Fatalf("tenant-a: %v", err)
			}
			if _, err := s.DashboardCreate(ctx, b, kind, json.RawMessage(raw)); err != nil {
				t.Fatalf("tenant-b: %v", err)
			}
			if _, err := s.DashboardCreate(ctx, a, kind, json.RawMessage(raw)); !errors.Is(err, store.ErrConflict) {
				t.Fatalf("duplicate in tenant-a: want ErrConflict, got %v", err)
			}
			for _, scope := range []store.Scope{a, b} {
				page, err := s.DashboardList(ctx, scope, kind, store.Filter{Limit: 25})
				if err != nil {
					t.Fatal(err)
				}
				if page.Total != 1 || len(page.Items) != 1 {
					t.Fatalf("%s list in %s: %+v", kind, scope.TenantID, page)
				}
			}
		})
	}
}

// tenantApp is the app every tenancy test row belongs to, so only the tenant
// tells two rows apart.
const tenantApp = "app-a"

func tenantCtx(tenant, app string) context.Context {
	return shield.WithApp(shield.WithTenant(context.Background(), tenant), app)
}

// primitiveCase drives one of the seven primitive kinds through the
// engine-facing store with plain closures, so one test body covers them all.
type primitiveCase struct {
	kind     string
	notFound error
	newID    func() id.ID
	// write creates the row, or replaces it when update is set. tenant is the
	// entity's TenantID; empty means "take the context tenant".
	write  func(ctx context.Context, key id.ID, tenant, name string, update bool) error
	get    func(ctx context.Context, key id.ID) (string, error)
	byName func(ctx context.Context, name string) (string, error)
	remove func(ctx context.Context, key id.ID) error
	// list returns how many rows a filter with TenantID tenant sees.
	list func(ctx context.Context, tenant string) (int, error)
}

func primitiveCases(s Backend) []primitiveCase {
	return []primitiveCase{
		{
			kind: "instincts", notFound: shield.ErrInstinctNotFound, newID: id.NewInstinctID,
			write: func(ctx context.Context, key id.ID, tenant, name string, update bool) error {
				v := &instinct.Instinct{ID: key, Name: name, AppID: tenantApp, TenantID: tenant, Category: "injection", Action: "block", Strategies: []instinct.Strategy{}, Metadata: map[string]any{}}
				if update {
					return s.UpdateInstinct(ctx, v)
				}
				return s.CreateInstinct(ctx, v)
			},
			get: func(ctx context.Context, key id.ID) (string, error) {
				v, err := s.GetInstinct(ctx, key)
				if err != nil {
					return "", err
				}
				return v.ID.String(), nil
			},
			byName: func(ctx context.Context, name string) (string, error) {
				v, err := s.GetInstinctByName(ctx, tenantApp, name)
				if err != nil {
					return "", err
				}
				return v.ID.String(), nil
			},
			remove: func(ctx context.Context, key id.ID) error { return s.DeleteInstinct(ctx, key) },
			list: func(ctx context.Context, tenant string) (int, error) {
				rows, err := s.ListInstincts(ctx, &instinct.ListFilter{TenantID: tenant})
				return len(rows), err
			},
		},
		{
			kind: "awareness", notFound: shield.ErrAwarenessNotFound, newID: id.NewAwarenessID,
			write: func(ctx context.Context, key id.ID, tenant, name string, update bool) error {
				v := &awareness.Awareness{ID: key, Name: name, AppID: tenantApp, TenantID: tenant, Focus: "pii", Action: "redact", Detectors: []awareness.Detector{}, Metadata: map[string]any{}}
				if update {
					return s.UpdateAwareness(ctx, v)
				}
				return s.CreateAwareness(ctx, v)
			},
			get: func(ctx context.Context, key id.ID) (string, error) {
				v, err := s.GetAwareness(ctx, key)
				if err != nil {
					return "", err
				}
				return v.ID.String(), nil
			},
			byName: func(ctx context.Context, name string) (string, error) {
				v, err := s.GetAwarenessByName(ctx, tenantApp, name)
				if err != nil {
					return "", err
				}
				return v.ID.String(), nil
			},
			remove: func(ctx context.Context, key id.ID) error { return s.DeleteAwareness(ctx, key) },
			list: func(ctx context.Context, tenant string) (int, error) {
				rows, err := s.ListAwareness(ctx, &awareness.ListFilter{TenantID: tenant})
				return len(rows), err
			},
		},
		{
			kind: "boundaries", notFound: shield.ErrBoundaryNotFound, newID: id.NewBoundaryID,
			write: func(ctx context.Context, key id.ID, tenant, name string, update bool) error {
				v := &boundary.Boundary{ID: key, Name: name, AppID: tenantApp, TenantID: tenant, Limits: []boundary.Limit{}, Metadata: map[string]any{}}
				if update {
					return s.UpdateBoundary(ctx, v)
				}
				return s.CreateBoundary(ctx, v)
			},
			get: func(ctx context.Context, key id.ID) (string, error) {
				v, err := s.GetBoundary(ctx, key)
				if err != nil {
					return "", err
				}
				return v.ID.String(), nil
			},
			byName: func(ctx context.Context, name string) (string, error) {
				v, err := s.GetBoundaryByName(ctx, tenantApp, name)
				if err != nil {
					return "", err
				}
				return v.ID.String(), nil
			},
			remove: func(ctx context.Context, key id.ID) error { return s.DeleteBoundary(ctx, key) },
			list: func(ctx context.Context, tenant string) (int, error) {
				rows, err := s.ListBoundaries(ctx, &boundary.ListFilter{TenantID: tenant})
				return len(rows), err
			},
		},
		{
			kind: "values", notFound: shield.ErrValueNotFound, newID: id.NewValueID,
			write: func(ctx context.Context, key id.ID, tenant, name string, update bool) error {
				v := &values.Values{ID: key, Name: name, AppID: tenantApp, TenantID: tenant, Severity: "warning", Action: "flag", Rules: []values.Rule{}, Metadata: map[string]any{}}
				if update {
					return s.UpdateValues(ctx, v)
				}
				return s.CreateValues(ctx, v)
			},
			get: func(ctx context.Context, key id.ID) (string, error) {
				v, err := s.GetValues(ctx, key)
				if err != nil {
					return "", err
				}
				return v.ID.String(), nil
			},
			byName: func(ctx context.Context, name string) (string, error) {
				v, err := s.GetValuesByName(ctx, tenantApp, name)
				if err != nil {
					return "", err
				}
				return v.ID.String(), nil
			},
			remove: func(ctx context.Context, key id.ID) error { return s.DeleteValues(ctx, key) },
			list: func(ctx context.Context, tenant string) (int, error) {
				rows, err := s.ListValues(ctx, &values.ListFilter{TenantID: tenant})
				return len(rows), err
			},
		},
		{
			kind: "judgments", notFound: shield.ErrJudgmentNotFound, newID: id.NewJudgmentID,
			write: func(ctx context.Context, key id.ID, tenant, name string, update bool) error {
				v := &judgment.Judgment{ID: key, Name: name, AppID: tenantApp, TenantID: tenant, Domain: "grounding", Action: "warn", Assessors: []judgment.Assessor{}, Metadata: map[string]any{}}
				if update {
					return s.UpdateJudgment(ctx, v)
				}
				return s.CreateJudgment(ctx, v)
			},
			get: func(ctx context.Context, key id.ID) (string, error) {
				v, err := s.GetJudgment(ctx, key)
				if err != nil {
					return "", err
				}
				return v.ID.String(), nil
			},
			byName: func(ctx context.Context, name string) (string, error) {
				v, err := s.GetJudgmentByName(ctx, tenantApp, name)
				if err != nil {
					return "", err
				}
				return v.ID.String(), nil
			},
			remove: func(ctx context.Context, key id.ID) error { return s.DeleteJudgment(ctx, key) },
			list: func(ctx context.Context, tenant string) (int, error) {
				rows, err := s.ListJudgments(ctx, &judgment.ListFilter{TenantID: tenant})
				return len(rows), err
			},
		},
		{
			kind: "reflexes", notFound: shield.ErrReflexNotFound, newID: id.NewReflexID,
			write: func(ctx context.Context, key id.ID, tenant, name string, update bool) error {
				v := &reflex.Reflex{ID: key, Name: name, AppID: tenantApp, TenantID: tenant, Triggers: []reflex.Trigger{}, Actions: []reflex.Action{}, Metadata: map[string]any{}}
				if update {
					return s.UpdateReflex(ctx, v)
				}
				return s.CreateReflex(ctx, v)
			},
			get: func(ctx context.Context, key id.ID) (string, error) {
				v, err := s.GetReflex(ctx, key)
				if err != nil {
					return "", err
				}
				return v.ID.String(), nil
			},
			byName: func(ctx context.Context, name string) (string, error) {
				v, err := s.GetReflexByName(ctx, tenantApp, name)
				if err != nil {
					return "", err
				}
				return v.ID.String(), nil
			},
			remove: func(ctx context.Context, key id.ID) error { return s.DeleteReflex(ctx, key) },
			list: func(ctx context.Context, tenant string) (int, error) {
				rows, err := s.ListReflexes(ctx, &reflex.ListFilter{TenantID: tenant})
				return len(rows), err
			},
		},
		{
			kind: "profiles", notFound: shield.ErrProfileNotFound, newID: id.NewSafetyProfileID,
			write: func(ctx context.Context, key id.ID, tenant, name string, update bool) error {
				v := &profile.SafetyProfile{
					ID: key, Name: name, AppID: tenantApp, TenantID: tenant,
					Instincts: []profile.InstinctAssignment{}, Judgments: []profile.JudgmentAssignment{}, Awareness: []profile.AwarenessAssignment{},
					Values: []string{}, Reflexes: []string{}, Boundaries: []string{}, Metadata: map[string]any{},
				}
				if update {
					return s.UpdateProfile(ctx, v)
				}
				return s.CreateProfile(ctx, v)
			},
			get: func(ctx context.Context, key id.ID) (string, error) {
				v, err := s.GetProfile(ctx, key)
				if err != nil {
					return "", err
				}
				return v.ID.String(), nil
			},
			byName: func(ctx context.Context, name string) (string, error) {
				v, err := s.GetProfileByName(ctx, tenantApp, name)
				if err != nil {
					return "", err
				}
				return v.ID.String(), nil
			},
			remove: func(ctx context.Context, key id.ID) error { return s.DeleteProfile(ctx, key) },
			list: func(ctx context.Context, tenant string) (int, error) {
				rows, err := s.ListProfiles(ctx, &profile.ListFilter{TenantID: tenant})
				return len(rows), err
			},
		},
	}
}

// The fixtures below set every collection; testNilCollections covers rows
// that leave them nil.

func newScan(tenant string) *scan.Result {
	return &scan.Result{ID: id.NewScanID(), Direction: scan.DirectionInput, Decision: scan.DecisionAllow, TenantID: tenant, AppID: tenantApp, Findings: []*scan.Finding{}, PoliciesUsed: []string{}, Metadata: map[string]any{}}
}

func newToken(scanID id.ID, tenant string) *pii.Token {
	return &pii.Token{ID: id.NewPIITokenID(), ScanID: scanID, TenantID: tenant, PIIType: "email", Placeholder: "[EMAIL]", EncryptedValue: []byte("ciphertext")}
}

func newPolicy(name, key string, level policy.ScopeLevel) *policy.Policy {
	return &policy.Policy{ID: id.NewPolicyID(), Name: name, ScopeKey: key, ScopeLevel: level, Enabled: true, Rules: []policy.Rule{}, Metadata: map[string]any{}}
}

// newReport builds an org-level report keyed by key.
func newReport(key string) *compliance.Report {
	n := time.Now().UTC()
	return &compliance.Report{ID: id.NewComplianceReportID(), Framework: compliance.FrameworkSOC2, ScopeKey: key, ScopeLevel: "org", PeriodStart: n.Add(-time.Hour), PeriodEnd: n, GeneratedAt: n, Summary: map[string]any{}, Details: map[string]any{}}
}

func testEmptyTenantIsAnError(t *testing.T, factory func(*testing.T) Backend) {
	s := factory(t)
	ctx := context.Background()
	for _, c := range primitiveCases(s) {
		t.Run(c.kind, func(t *testing.T) {
			wantTenantRequired(t, "list", second(c.list(ctx, "")))
			wantTenantRequired(t, "get by name", second(c.byName(ctx, "same")))
			wantTenantRequired(t, "get", second(c.get(ctx, c.newID())))
			wantTenantRequired(t, "create", c.write(ctx, c.newID(), "", "same", false))
			wantTenantRequired(t, "update", c.write(ctx, c.newID(), "", "same", true))
			wantTenantRequired(t, "delete", c.remove(ctx, c.newID()))
		})
	}
	checks := map[string]func() error{
		"nil instinct filter":  func() error { _, err := s.ListInstincts(ctx, nil); return err },
		"nil awareness filter": func() error { _, err := s.ListAwareness(ctx, nil); return err },
		"nil boundary filter":  func() error { _, err := s.ListBoundaries(ctx, nil); return err },
		"nil values filter":    func() error { _, err := s.ListValues(ctx, nil); return err },
		"nil judgment filter":  func() error { _, err := s.ListJudgments(ctx, nil); return err },
		"nil reflex filter":    func() error { _, err := s.ListReflexes(ctx, nil); return err },
		"nil profile filter":   func() error { _, err := s.ListProfiles(ctx, nil); return err },
		"create scan":          func() error { return s.CreateScan(ctx, newScan("")) },
		"get scan":             func() error { _, err := s.GetScan(ctx, id.NewScanID()); return err },
		"list scans":           func() error { _, err := s.ListScans(ctx, &scan.ListFilter{}); return err },
		"nil scan filter":      func() error { _, err := s.ListScans(ctx, nil); return err },
		"scan stats":           func() error { _, err := s.ScanStats(ctx, &scan.StatsFilter{}); return err },
		"nil stats filter":     func() error { _, err := s.ScanStats(ctx, nil); return err },
		"store pii tokens":     func() error { return s.StorePIITokens(ctx, []*pii.Token{newToken(id.NewScanID(), "")}) },
		"load pii tokens": func() error {
			_, err := s.LoadPIITokens(ctx, []id.PIITokenID{id.NewPIITokenID()})
			return err
		},
		"load pii tokens by scan": func() error { _, err := s.LoadPIITokensByScan(ctx, id.NewScanID()); return err },
		"delete pii tokens":       func() error { return s.DeletePIITokens(ctx, []id.PIITokenID{id.NewPIITokenID()}) },
		"delete tenant tokens":    func() error { return s.DeletePIITokensByTenant(ctx, "") },
		"pii stats":               func() error { _, err := s.PIIStats(ctx, ""); return err },
		"list policies":           func() error { _, err := s.ListPolicies(ctx, &policy.ListFilter{}); return err },
		"nil policy filter":       func() error { _, err := s.ListPolicies(ctx, nil); return err },
		"policies for scope": func() error {
			_, err := s.GetPoliciesForScope(ctx, "", policy.ScopeOrg)
			return err
		},
		"policy by name":    func() error { _, err := s.GetPolicyByName(ctx, "", "same"); return err },
		"create policy":     func() error { return s.CreatePolicy(ctx, newPolicy("same", "", policy.ScopeOrg)) },
		"assign to tenant":  func() error { return s.AssignToTenant(ctx, "", id.NewPolicyID()) },
		"unassign":          func() error { return s.UnassignFromTenant(ctx, "", id.NewPolicyID()) },
		"list reports":      func() error { _, err := s.ListReports(ctx, &compliance.ListFilter{}); return err },
		"nil report filter": func() error { _, err := s.ListReports(ctx, nil); return err },
		"create report":     func() error { return s.CreateReport(ctx, newReport("")) },
	}
	for name, check := range checks {
		wantTenantRequired(t, name, check())
	}
}

func second[T any](_ T, err error) error { return err }

func wantTenantRequired(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, shield.ErrTenantRequired) {
		t.Errorf("%s with no tenant: want ErrTenantRequired, got %v", what, err)
	}
}

func testForeignIDsAreInvisible(t *testing.T, factory func(*testing.T) Backend) {
	s := factory(t)
	a := tenantCtx("tenant-a", tenantApp)
	b := tenantCtx("tenant-b", tenantApp)
	for _, c := range primitiveCases(s) {
		t.Run(c.kind, func(t *testing.T) {
			key := c.newID()
			if err := c.write(a, key, "", "foreign", false); err != nil {
				t.Fatal(err)
			}
			if _, err := c.get(a, key); err != nil {
				t.Fatalf("owner cannot read its row: %v", err)
			}
			if _, err := c.get(b, key); !errors.Is(err, c.notFound) {
				t.Fatalf("foreign get: want %v, got %v", c.notFound, err)
			}
			if err := c.write(b, key, "", "taken", true); !errors.Is(err, c.notFound) {
				t.Fatalf("foreign update: want %v, got %v", c.notFound, err)
			}
			if err := c.write(b, key, "tenant-a", "taken", true); !errors.Is(err, shield.ErrTenantMismatch) {
				t.Fatalf("update naming the owner's tenant: want ErrTenantMismatch, got %v", err)
			}
			if err := c.remove(b, key); err != nil {
				t.Fatalf("foreign delete: want nil, got %v", err)
			}
			if _, err := c.get(a, key); err != nil {
				t.Fatalf("foreign delete removed the row: %v", err)
			}
			if n, err := c.list(b, ""); err != nil || n != 0 {
				t.Fatalf("foreign list saw %d rows (%v)", n, err)
			}
			if n, err := c.list(a, ""); err != nil || n != 1 {
				t.Fatalf("owner list saw %d rows (%v)", n, err)
			}
		})
	}
	t.Run("scans", func(t *testing.T) { foreignScansAreInvisible(t, s) })
	t.Run("pii", func(t *testing.T) { foreignTokensAreInvisible(t, s) })
	t.Run("policies", func(t *testing.T) {
		pol := newPolicy("foreign", "tenant-a", policy.ScopeOrg)
		if err := s.CreatePolicy(a, pol); err != nil {
			t.Fatal(err)
		}
		if _, err := s.GetPolicy(b, pol.ID); !errors.Is(err, shield.ErrPolicyNotFound) {
			t.Fatalf("foreign get: want ErrPolicyNotFound, got %v", err)
		}
		if err := s.UpdatePolicy(b, pol); !errors.Is(err, shield.ErrPolicyNotFound) {
			t.Fatalf("foreign update: want ErrPolicyNotFound, got %v", err)
		}
		if err := s.DeletePolicy(b, pol.ID); err != nil {
			t.Fatalf("foreign delete: want nil, got %v", err)
		}
		if _, err := s.GetPolicy(a, pol.ID); err != nil {
			t.Fatalf("foreign delete removed the policy: %v", err)
		}
		if err := s.DeletePolicy(a, pol.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := s.GetPolicy(a, pol.ID); !errors.Is(err, shield.ErrPolicyNotFound) {
			t.Fatalf("owner delete left the policy: %v", err)
		}
	})
	t.Run("compliance", func(t *testing.T) {
		report := newReport("tenant-a")
		if err := s.CreateReport(a, report); err != nil {
			t.Fatal(err)
		}
		if _, err := s.GetReport(a, report.ID); err != nil {
			t.Fatalf("owner cannot read its report: %v", err)
		}
		if _, err := s.GetReport(b, report.ID); !errors.Is(err, shield.ErrComplianceNotFound) {
			t.Fatalf("foreign get: want ErrComplianceNotFound, got %v", err)
		}
		rows, err := s.ListReports(b, &compliance.ListFilter{ScopeKey: "tenant-b"})
		if err != nil || len(rows) != 0 {
			t.Fatalf("foreign list saw %d reports (%v)", len(rows), err)
		}
	})
}

func foreignScansAreInvisible(t *testing.T, s Backend) {
	t.Helper()
	a := tenantCtx("tenant-a", tenantApp)
	b := tenantCtx("tenant-b", tenantApp)
	result := newScan("")
	if err := s.CreateScan(a, result); err != nil {
		t.Fatal(err)
	}
	if result.TenantID != "tenant-a" {
		t.Fatalf("scan did not take the context tenant: %q", result.TenantID)
	}
	if _, err := s.GetScan(a, result.ID); err != nil {
		t.Fatalf("owner cannot read its scan: %v", err)
	}
	if _, err := s.GetScan(b, result.ID); !errors.Is(err, shield.ErrScanNotFound) {
		t.Fatalf("foreign get: want ErrScanNotFound, got %v", err)
	}
	rows, err := s.ListScans(b, &scan.ListFilter{})
	if err != nil || len(rows) != 0 {
		t.Fatalf("foreign list saw %d scans (%v)", len(rows), err)
	}
	stats, err := s.ScanStats(b, nil)
	if err != nil || stats.TotalScans != 0 {
		t.Fatalf("foreign stats: %+v (%v)", stats, err)
	}
	stats, err = s.ScanStats(a, nil)
	if err != nil || stats.TotalScans != 1 {
		t.Fatalf("owner stats: %+v (%v)", stats, err)
	}
}

func foreignTokensAreInvisible(t *testing.T, s Backend) {
	t.Helper()
	a := tenantCtx("tenant-a", tenantApp)
	b := tenantCtx("tenant-b", tenantApp)
	token := newToken(id.NewScanID(), "")
	if err := s.StorePIITokens(a, []*pii.Token{token}); err != nil {
		t.Fatal(err)
	}
	if token.TenantID != "tenant-a" {
		t.Fatalf("token did not take the context tenant: %q", token.TenantID)
	}
	ids := []id.PIITokenID{token.ID}
	rows, err := s.LoadPIITokens(b, ids)
	if err != nil || len(rows) != 0 {
		t.Fatalf("foreign load saw %d tokens (%v)", len(rows), err)
	}
	rows, err = s.LoadPIITokensByScan(b, token.ScanID)
	if err != nil || len(rows) != 0 {
		t.Fatalf("foreign load by scan saw %d tokens (%v)", len(rows), err)
	}
	if err = s.DeletePIITokens(b, ids); err != nil {
		t.Fatalf("foreign delete: %v", err)
	}
	if err = s.DeletePIITokensByTenant(b, ""); err != nil {
		t.Fatalf("delete own tokens: %v", err)
	}
	stats, err := s.PIIStats(b, "")
	if err != nil || stats.TotalTokens != 0 {
		t.Fatalf("foreign stats: %+v (%v)", stats, err)
	}
	rows, err = s.LoadPIITokens(a, ids)
	if err != nil || len(rows) != 1 {
		t.Fatalf("foreign delete removed the token: %d (%v)", len(rows), err)
	}
	rows, err = s.LoadPIITokensByScan(a, token.ScanID)
	if err != nil || len(rows) != 1 {
		t.Fatalf("owner load by scan saw %d tokens (%v)", len(rows), err)
	}
	stats, err = s.PIIStats(a, "")
	if err != nil || stats.TotalTokens != 1 {
		t.Fatalf("owner stats: %+v (%v)", stats, err)
	}
}

func testFilterTenantMustMatchContext(t *testing.T, factory func(*testing.T) Backend) {
	s := factory(t)
	a := tenantCtx("tenant-a", tenantApp)
	b := tenantCtx("tenant-b", tenantApp)
	none := context.Background()
	for _, c := range primitiveCases(s) {
		t.Run(c.kind, func(t *testing.T) {
			for _, ctx := range []context.Context{a, b} {
				if err := c.write(ctx, c.newID(), "", "row", false); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := c.list(a, "tenant-b"); !errors.Is(err, shield.ErrTenantMismatch) {
				t.Fatalf("foreign filter: want ErrTenantMismatch, got %v", err)
			}
			if err := c.write(a, c.newID(), "tenant-b", "planted", false); !errors.Is(err, shield.ErrTenantMismatch) {
				t.Fatalf("create in a foreign tenant: want ErrTenantMismatch, got %v", err)
			}
			// Filter-only callers (cortex's catalogs) carry no context tenant.
			if n, err := c.list(none, "tenant-a"); err != nil || n != 1 {
				t.Fatalf("filter-only list saw %d rows (%v)", n, err)
			}
		})
	}
	t.Run("scans", func(t *testing.T) {
		for _, ctx := range []context.Context{a, b} {
			if err := s.CreateScan(ctx, newScan("")); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := s.ListScans(a, &scan.ListFilter{TenantID: "tenant-b"}); !errors.Is(err, shield.ErrTenantMismatch) {
			t.Fatalf("foreign scan filter: want ErrTenantMismatch, got %v", err)
		}
		if _, err := s.ScanStats(a, &scan.StatsFilter{TenantID: "tenant-b"}); !errors.Is(err, shield.ErrTenantMismatch) {
			t.Fatalf("foreign stats filter: want ErrTenantMismatch, got %v", err)
		}
		if err := s.CreateScan(a, newScan("tenant-b")); !errors.Is(err, shield.ErrTenantMismatch) {
			t.Fatalf("scan in a foreign tenant: want ErrTenantMismatch, got %v", err)
		}
		rows, err := s.ListScans(none, &scan.ListFilter{TenantID: "tenant-a"})
		if err != nil || len(rows) != 1 {
			t.Fatalf("filter-only scans: %d (%v)", len(rows), err)
		}
		stats, err := s.ScanStats(none, &scan.StatsFilter{TenantID: "tenant-a"})
		if err != nil || stats.TotalScans != 1 {
			t.Fatalf("filter-only stats: %+v (%v)", stats, err)
		}
	})
	t.Run("explicit-tenant-arguments", func(t *testing.T) {
		if err := s.StorePIITokens(none, []*pii.Token{newToken(id.NewScanID(), "tenant-b")}); err != nil {
			t.Fatal(err)
		}
		if err := s.StorePIITokens(a, []*pii.Token{newToken(id.NewScanID(), "tenant-b")}); !errors.Is(err, shield.ErrTenantMismatch) {
			t.Fatalf("token in a foreign tenant: want ErrTenantMismatch, got %v", err)
		}
		if _, err := s.PIIStats(a, "tenant-b"); !errors.Is(err, shield.ErrTenantMismatch) {
			t.Fatalf("foreign pii stats: want ErrTenantMismatch, got %v", err)
		}
		if err := s.DeletePIITokensByTenant(a, "tenant-b"); !errors.Is(err, shield.ErrTenantMismatch) {
			t.Fatalf("foreign token purge: want ErrTenantMismatch, got %v", err)
		}
		stats, err := s.PIIStats(none, "tenant-b")
		if err != nil || stats.TotalTokens != 1 {
			t.Fatalf("filter-only pii stats: %+v (%v)", stats, err)
		}
		// App scope is shared by every tenant of the app, so only an operator
		// call (no context tenant) writes there.
		pol := newPolicy("assignable", tenantApp, policy.ScopeApp)
		if err = s.CreatePolicy(none, pol); err != nil {
			t.Fatal(err)
		}
		if err = s.AssignToTenant(a, "tenant-b", pol.ID); !errors.Is(err, shield.ErrTenantMismatch) {
			t.Fatalf("assign to a foreign tenant: want ErrTenantMismatch, got %v", err)
		}
		if err = s.UnassignFromTenant(a, "tenant-b", pol.ID); !errors.Is(err, shield.ErrTenantMismatch) {
			t.Fatalf("unassign from a foreign tenant: want ErrTenantMismatch, got %v", err)
		}
		if err = s.AssignToTenant(a, "", pol.ID); err != nil {
			t.Fatalf("assign to the context tenant: %v", err)
		}
		if err = s.UnassignFromTenant(a, "tenant-a", pol.ID); err != nil {
			t.Fatalf("unassign from the context tenant: %v", err)
		}
	})
	t.Run("assign-needs-a-visible-policy", func(t *testing.T) {
		foreign := newPolicy("foreign-org", "tenant-a", policy.ScopeOrg)
		if err := s.CreatePolicy(a, foreign); err != nil {
			t.Fatal(err)
		}
		if err := s.AssignToTenant(b, "", foreign.ID); !errors.Is(err, shield.ErrPolicyNotFound) {
			t.Fatalf("assign another org's policy: want ErrPolicyNotFound, got %v", err)
		}
		if err := s.UnassignFromTenant(b, "", foreign.ID); err != nil {
			t.Fatalf("unassign another org's policy: want nil, got %v", err)
		}
		missing := id.NewPolicyID()
		if err := s.AssignToTenant(a, "", missing); !errors.Is(err, shield.ErrPolicyNotFound) {
			t.Fatalf("assign a missing policy: want ErrPolicyNotFound, got %v", err)
		}
		if err := s.UnassignFromTenant(a, "", missing); err != nil {
			t.Fatalf("unassign a missing policy: want nil, got %v", err)
		}
		if err := s.AssignToTenant(a, "", foreign.ID); err != nil {
			t.Fatalf("assign own org policy: %v", err)
		}
		if err := s.UnassignFromTenant(a, "", foreign.ID); err != nil {
			t.Fatalf("unassign own org policy: %v", err)
		}
	})
}

func testByNameReadsTheContextTenant(t *testing.T, factory func(*testing.T) Backend) {
	s := factory(t)
	a := tenantCtx("tenant-a", tenantApp)
	b := tenantCtx("tenant-b", tenantApp)
	for _, c := range primitiveCases(s) {
		t.Run(c.kind, func(t *testing.T) {
			keys := map[context.Context]id.ID{a: c.newID(), b: c.newID()}
			for ctx, key := range keys {
				if err := c.write(ctx, key, "", "same", false); err != nil {
					t.Fatal(err)
				}
			}
			for ctx, key := range keys {
				got, err := c.byName(ctx, "same")
				if err != nil {
					t.Fatal(err)
				}
				if got != key.String() {
					t.Fatalf("by name returned %s, want %s", got, key)
				}
			}
		})
	}
}

func testPolicyScopes(t *testing.T, factory func(*testing.T) Backend) {
	s := factory(t)
	a := tenantCtx("tenant-a", tenantApp)
	b := tenantCtx("tenant-b", tenantApp)
	otherApp := tenantCtx("tenant-a", "app-b")
	none := context.Background()

	operator := shield.WithApp(context.Background(), tenantApp)

	org := newPolicy("org", "tenant-a", policy.ScopeOrg)
	if err := s.CreatePolicy(a, org); err != nil {
		t.Fatal(err)
	}
	// App scope is shared by every tenant of the app: only an operator call
	// (no context tenant) may write there.
	app := newPolicy("app", tenantApp, policy.ScopeApp)
	if err := s.CreatePolicy(none, app); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePolicy(b, newPolicy("planted", "tenant-a", policy.ScopeOrg)); !errors.Is(err, shield.ErrTenantMismatch) {
		t.Fatalf("policy in a foreign org: want ErrTenantMismatch, got %v", err)
	}
	if err := s.CreatePolicy(a, newPolicy("shared", tenantApp, policy.ScopeApp)); !errors.Is(err, shield.ErrTenantMismatch) {
		t.Fatalf("app-level policy from a tenant: want ErrTenantMismatch, got %v", err)
	}

	t.Run("get", func(t *testing.T) {
		if _, err := s.GetPolicy(a, org.ID); err != nil {
			t.Fatalf("owner cannot read its org policy: %v", err)
		}
		if _, err := s.GetPolicy(b, org.ID); !errors.Is(err, shield.ErrPolicyNotFound) {
			t.Fatalf("org policy from another tenant: want ErrPolicyNotFound, got %v", err)
		}
		if _, err := s.GetPolicy(a, app.ID); err != nil {
			t.Fatalf("app policy under its app: %v", err)
		}
		if _, err := s.GetPolicy(otherApp, app.ID); !errors.Is(err, shield.ErrPolicyNotFound) {
			t.Fatalf("app policy under another app: want ErrPolicyNotFound, got %v", err)
		}
		if _, err := s.GetPolicy(none, org.ID); !errors.Is(err, shield.ErrPolicyNotFound) {
			t.Fatalf("org policy with no context: want ErrPolicyNotFound, got %v", err)
		}
	})

	t.Run("update", func(t *testing.T) {
		if err := s.UpdatePolicy(otherApp, app); !errors.Is(err, shield.ErrPolicyNotFound) {
			t.Fatalf("app policy updated from another app: %v", err)
		}
		moved := *org
		moved.ScopeKey = "tenant-b"
		if err := s.UpdatePolicy(a, &moved); !errors.Is(err, shield.ErrTenantMismatch) {
			t.Fatalf("policy moved into a foreign org: want ErrTenantMismatch, got %v", err)
		}
		movedApp := *org
		movedApp.ScopeKey, movedApp.ScopeLevel = tenantApp, policy.ScopeApp
		if err := s.UpdatePolicy(a, &movedApp); !errors.Is(err, shield.ErrTenantMismatch) {
			t.Fatalf("org policy moved into the shared app scope: want ErrTenantMismatch, got %v", err)
		}
		for name, ctx := range map[string]context.Context{"tenant-a": a, "tenant-b": b} {
			changed := *app
			changed.Description = "changed by " + name
			if err := s.UpdatePolicy(ctx, &changed); !errors.Is(err, shield.ErrTenantMismatch) {
				t.Fatalf("%s updated the shared app policy: want ErrTenantMismatch, got %v", name, err)
			}
			if err := s.DeletePolicy(ctx, app.ID); !errors.Is(err, shield.ErrTenantMismatch) {
				t.Fatalf("%s deleted the shared app policy: want ErrTenantMismatch, got %v", name, err)
			}
		}
		got, err := s.GetPolicy(a, app.ID)
		if err != nil || got.Description != "" {
			t.Fatalf("shared app policy changed or removed by a tenant: %+v (%v)", got, err)
		}
		app.Description = "operator"
		if err = s.UpdatePolicy(operator, app); err != nil {
			t.Fatalf("operator update of the app policy: %v", err)
		}
		org.Description = "updated"
		if err = s.UpdatePolicy(a, org); err != nil {
			t.Fatalf("owner update: %v", err)
		}
		got, err = s.GetPolicy(a, org.ID)
		if err != nil || got.Description != "updated" || got.ScopeKey != "tenant-a" {
			t.Fatalf("owner update lost: %+v (%v)", got, err)
		}
	})

	t.Run("cross-tenant-keys", func(t *testing.T) {
		if _, err := s.ListPolicies(b, &policy.ListFilter{ScopeKey: "tenant-a"}); !errors.Is(err, shield.ErrTenantMismatch) {
			t.Fatalf("list another org: want ErrTenantMismatch, got %v", err)
		}
		if _, err := s.GetPoliciesForScope(b, "tenant-a", policy.ScopeOrg); !errors.Is(err, shield.ErrTenantMismatch) {
			t.Fatalf("scope of another org: want ErrTenantMismatch, got %v", err)
		}
		if _, err := s.GetPolicyByName(b, "tenant-a", "org"); !errors.Is(err, shield.ErrTenantMismatch) {
			t.Fatalf("by name in another org: want ErrTenantMismatch, got %v", err)
		}
		if _, err := s.GetPoliciesForScope(otherApp, tenantApp, policy.ScopeApp); !errors.Is(err, shield.ErrTenantMismatch) {
			t.Fatalf("scope of another app: want ErrTenantMismatch, got %v", err)
		}
		if _, err := s.ListPolicies(a, &policy.ListFilter{ScopeKey: "tenant-a", ScopeLevel: policy.ScopeApp}); !errors.Is(err, shield.ErrTenantMismatch) {
			t.Fatalf("tenant key at the app level: want ErrTenantMismatch, got %v", err)
		}
	})

	t.Run("own-keys", func(t *testing.T) {
		onePolicy(t, "org list")(s.ListPolicies(a, &policy.ListFilter{ScopeKey: "tenant-a"}))
		onePolicy(t, "app list")(s.ListPolicies(a, &policy.ListFilter{ScopeKey: tenantApp}))
		onePolicy(t, "org scope")(s.GetPoliciesForScope(a, "tenant-a", policy.ScopeOrg))
		onePolicy(t, "app scope")(s.GetPoliciesForScope(b, tenantApp, policy.ScopeApp))
		if got, err := s.GetPolicyByName(a, "tenant-a", "org"); err != nil || got.ID.String() != org.ID.String() {
			t.Fatalf("by name in own org: %v", err)
		}
		if _, err := s.GetPolicyByName(otherApp, tenantApp, "app"); !errors.Is(err, shield.ErrTenantMismatch) {
			t.Fatalf("by name in another app: want ErrTenantMismatch, got %v", err)
		}
	})

	t.Run("filter-only", func(t *testing.T) {
		onePolicy(t, "filter-only list")(s.ListPolicies(none, &policy.ListFilter{ScopeKey: "tenant-a"}))
		onePolicy(t, "filter-only scope")(s.GetPoliciesForScope(none, "tenant-a", policy.ScopeOrg))
	})

	t.Run("compliance", func(t *testing.T) {
		report := newReport("tenant-a")
		if err := s.CreateReport(a, report); err != nil {
			t.Fatal(err)
		}
		if err := s.CreateReport(b, newReport("tenant-a")); !errors.Is(err, shield.ErrTenantMismatch) {
			t.Fatalf("report in a foreign org: want ErrTenantMismatch, got %v", err)
		}
		shared := newReport(tenantApp)
		shared.ScopeLevel = "app"
		if err := s.CreateReport(a, shared); !errors.Is(err, shield.ErrTenantMismatch) {
			t.Fatalf("app-level report from a tenant: want ErrTenantMismatch, got %v", err)
		}
		if _, err := s.ListReports(b, &compliance.ListFilter{ScopeKey: "tenant-a"}); !errors.Is(err, shield.ErrTenantMismatch) {
			t.Fatalf("reports of another org: want ErrTenantMismatch, got %v", err)
		}
		rows, err := s.ListReports(a, &compliance.ListFilter{ScopeKey: "tenant-a"})
		if err != nil || len(rows) != 1 {
			t.Fatalf("own reports: %d (%v)", len(rows), err)
		}
		rows, err = s.ListReports(none, &compliance.ListFilter{ScopeKey: "tenant-a"})
		if err != nil || len(rows) != 1 {
			t.Fatalf("filter-only reports: %d (%v)", len(rows), err)
		}
	})
}

// onePolicy returns a check that a policy read found exactly one row.
func onePolicy(t *testing.T, what string) func([]*policy.Policy, error) {
	t.Helper()
	return func(rows []*policy.Policy, err error) {
		t.Helper()
		if err != nil || len(rows) != 1 {
			t.Fatalf("%s: got %d policies (%v), want 1", what, len(rows), err)
		}
	}
}
