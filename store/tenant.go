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
