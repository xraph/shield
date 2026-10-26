package store

import (
	"context"

	"github.com/xraph/shield"
)

// Scope levels for policies and compliance reports.
const (
	levelOrg = "org"
	levelApp = "app"
)

// Tenant returns the tenant a store call runs for. want is a filter's or an
// entity's TenantID. Empty want takes the context tenant. Both empty is
// ErrTenantRequired; both set and different is ErrTenantMismatch.
func Tenant(ctx context.Context, want string) (string, error) {
	have := shield.TenantFromContext(ctx)
	switch {
	case want == "" && have == "":
		return "", shield.ErrTenantRequired
	case want == "":
		return have, nil
	case have != "" && have != want:
		return "", shield.ErrTenantMismatch
	default:
		return want, nil
	}
}

// ScopeVisible reports whether a policy or compliance scope is readable from
// ctx: level "org" needs key == context tenant, level "app" needs key == context app.
func ScopeVisible(ctx context.Context, key, level string) bool {
	if key == "" {
		return false
	}
	switch level {
	case levelOrg:
		return key == shield.TenantFromContext(ctx)
	case levelApp:
		return key == shield.AppFromContext(ctx)
	default:
		return false
	}
}

// ScopeLevels resolves which scope levels a policy or compliance read keyed by
// key may cover. level narrows the answer to one level when set.
//
// An empty key is ErrTenantRequired. With no tenant on ctx the read is a
// filter-only call (cortex's catalogs make these), so it returns nil and the
// caller adds no level restriction. With a tenant on ctx it returns the
// levels at which ScopeVisible accepts key, and ErrTenantMismatch when there
// are none.
func ScopeLevels(ctx context.Context, key, level string) ([]string, error) {
	if key == "" {
		return nil, shield.ErrTenantRequired
	}
	if shield.TenantFromContext(ctx) == "" {
		return nil, nil
	}
	candidates := []string{levelOrg, levelApp}
	if level != "" {
		candidates = []string{level}
	}
	var levels []string
	for _, l := range candidates {
		if ScopeVisible(ctx, key, l) {
			levels = append(levels, l)
		}
	}
	if len(levels) == 0 {
		return nil, shield.ErrTenantMismatch
	}
	return levels, nil
}

// ScopeWritable checks that ctx may create, change or delete a policy or
// compliance report in the scope (key, level).
//
// With a tenant on ctx, only that tenant's org scope is writable. App scope is
// shared by every tenant of the app (Loomplane gives all workspaces one app
// ID), so a tenant writing there would change every other tenant's safety
// configuration: app-level writes return ErrTenantMismatch, as does an org key
// that is not the context tenant. With no tenant on ctx the call is an
// operator call and any scope is writable. An empty key is ErrTenantRequired.
func ScopeWritable(ctx context.Context, key, level string) error {
	if key == "" {
		return shield.ErrTenantRequired
	}
	tenant := shield.TenantFromContext(ctx)
	if tenant == "" {
		return nil
	}
	if level != levelOrg || key != tenant {
		return shield.ErrTenantMismatch
	}
	return nil
}

// ReportScope is the one compliance report scope ctx may read: a tenant's
// own org scope, or, with no tenant on ctx, the app scope of the context
// app (an operator call). App-level reports are shared by every tenant of the
// app, so a tenant never reads them. ok is false when ctx names neither.
func ReportScope(ctx context.Context) (key, level string, ok bool) {
	if tenant := shield.TenantFromContext(ctx); tenant != "" {
		return tenant, levelOrg, true
	}
	if app := shield.AppFromContext(ctx); app != "" {
		return app, levelApp, true
	}
	return "", "", false
}

// ReportLevels resolves which scope levels a compliance report list keyed by
// key may cover. An empty key is ErrTenantRequired. With no tenant on ctx the
// list is a filter-only call and gets no level restriction (nil). With a
// tenant on ctx only its own org level is readable: any other key is
// ErrTenantMismatch.
func ReportLevels(ctx context.Context, key string) ([]string, error) {
	if key == "" {
		return nil, shield.ErrTenantRequired
	}
	tenant := shield.TenantFromContext(ctx)
	if tenant == "" {
		return nil, nil
	}
	if key != tenant {
		return nil, shield.ErrTenantMismatch
	}
	return []string{levelOrg}, nil
}
