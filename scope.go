package shield

import "context"

type contextKey string

const (
	tenantKey contextKey = "shield_tenant"
	appKey    contextKey = "shield_app"
)

// WithTenant returns a context carrying the given tenant ID.
func WithTenant(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantKey, tenantID)
}

// TenantFromContext extracts the tenant ID from context.
// Returns empty string if not set.
func TenantFromContext(ctx context.Context) string {
	v, ok := ctx.Value(tenantKey).(string)
	if !ok {
		return ""
	}
	return v
}

// WithApp returns a context carrying the given app ID.
func WithApp(ctx context.Context, appID string) context.Context {
	return context.WithValue(ctx, appKey, appID)
}

// AppFromContext extracts the app ID from context.
// Returns empty string if not set.
func AppFromContext(ctx context.Context) string {
	v, ok := ctx.Value(appKey).(string)
	if !ok {
		return ""
	}
	return v
}
