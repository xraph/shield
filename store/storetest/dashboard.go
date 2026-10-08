package storetest

import (
	"context"
	"encoding/json"
	"github.com/xraph/shield/id"
	"github.com/xraph/shield/pii"
	"github.com/xraph/shield/store"
	"strings"
	"testing"
	"time"
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
			_ = json.Unmarshal(r, &item)
			id := item["id"].(string)
			if item["enabled"] != false {
				t.Fatal("false lost")
			}
			if _, err := s.DashboardGet(ctx, b, kind, id); err == nil {
				t.Fatal("foreign ID readable")
			}
			if _, err := s.DashboardUpdate(ctx, b, kind, id, r); err == nil {
				t.Fatal("foreign ID writable")
			}
			if err := s.DashboardDelete(ctx, b, kind, id); err == nil {
				t.Fatal("foreign ID deletable")
			}
			if _, err := s.DashboardCreate(ctx, b, kind, json.RawMessage(raw)); err != nil {
				t.Fatal(err)
			}
			page, err := s.DashboardList(ctx, a, kind, store.Filter{Limit: 1})
			if err != nil {
				t.Fatal(err)
			}
			if page.Total != 1 || len(page.Items) != 1 {
				t.Fatalf("bad paging: %+v", page)
			}
			got, err := s.DashboardGet(ctx, a, kind, id)
			if err != nil {
				t.Fatal(err)
			}
			var back map[string]any
			_ = json.Unmarshal(got, &back)
			var expected map[string]any
			_ = json.Unmarshal([]byte(raw), &expected)
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
	_ = json.Unmarshal(page.Items[0], &first)
	key := first["id"].(string)
	got, err := s.DashboardUpdate(ctx, scope, "instincts", key, json.RawMessage(`{"enabled":false,"strategies":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	var cleared map[string]any
	_ = json.Unmarshal(got, &cleared)
	if cleared["enabled"] != false || len(cleared["strategies"].([]any)) != 0 || cleared["name"] != "one" {
		t.Fatal(cleared)
	}
	next, err := s.DashboardList(ctx, scope, "instincts", store.Filter{Limit: 1, Offset: 1})
	if err != nil {
		t.Fatal(err)
	}
	if string(next.Items[0]) == string(page.Items[0]) {
		t.Fatal("page repeated")
	}
	pol, err := s.DashboardCreate(ctx, scope, "policies", json.RawMessage(`{"name":"policy","rules":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	_ = json.Unmarshal(pol, &p)
	pid := p["id"].(string)
	for i := 0; i < 2; i++ {
		if err := s.DashboardAssign(ctx, scope, pid, true); err != nil {
			t.Fatal(err)
		}
	}
	assigned, err := s.DashboardAssigned(ctx, scope, pid)
	if err != nil || !assigned {
		t.Fatal(assigned, err)
	}
	if err := s.DashboardAssign(ctx, store.Scope{TenantID: "b", AppID: "b"}, pid, true); err == nil {
		t.Fatal("foreign policy assigned")
	}
	if err := s.DashboardAssign(ctx, scope, pid, false); err != nil {
		t.Fatal(err)
	}
	assigned, err = s.DashboardAssigned(ctx, scope, pid)
	if err != nil || assigned {
		t.Fatal(assigned, err)
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
	_ = json.Unmarshal(page.Items[0], &token)
	key := token["id"].(string)
	if _, err := s.DashboardDeleteTokens(ctx, b, cutoff, []string{key}); err != nil {
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

type Backend interface {
	store.Store
	store.DashboardStore
	store.AssignmentStore
	store.PrivacyStore
}

func Run(t *testing.T, factory func(*testing.T) Backend) {
	t.Run("scope-and-round-trip", func(t *testing.T) { testDashboardScopeAndNestedRoundTrip(t, factory) })
	t.Run("paging-and-assignment", func(t *testing.T) { testDashboardPagingClearAndAssignment(t, factory) })
	t.Run("privacy-and-retention", func(t *testing.T) { testPrivacyMetadataAndBoundedRetention(t, factory) })
}
