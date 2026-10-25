package storetest

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/xraph/shield/store"
)

// RunTenancy checks that primitive names are unique per (app, tenant), not per app.
func RunTenancy(t *testing.T, factory func(*testing.T) Backend) {
	t.Run("same-name-in-each-tenant", func(t *testing.T) { testSameNameInEachTenant(t, factory) })
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
