package contract

import (
	"context"
	dash "github.com/xraph/forge/extensions/dashboard/contract"
	"github.com/xraph/shield/admin"
	"github.com/xraph/shield/store"
	"strings"
)

type ActorResolver func(context.Context, dash.Principal) (admin.Actor, error)
type ScopeResolver func(context.Context, dash.Principal) (store.Scope, error)

// ResolveActor requires authenticated claims set by the host's identity adapter.
// Request params cannot grant scope or permissions.
func ResolveActor(_ context.Context, p dash.Principal) (admin.Actor, error) {
	if p.User == nil || !p.User.Authenticated() {
		return admin.Actor{}, &dash.Error{Code: dash.CodeUnauthenticated, Message: "Sign in to use Shield"}
	}
	claim := func(key string) (string, error) {
		v, ok := p.Claims[key]
		if !ok {
			return "", &dash.Error{Code: dash.CodePermissionDenied, Message: "Authorized Shield scope is missing"}
		}
		str, ok := v.(string)
		if !ok || strings.TrimSpace(str) == "" {
			return "", &dash.Error{Code: dash.CodePermissionDenied, Message: "Invalid Shield scope claim"}
		}
		if other, exists := p.Claims["shield_"+key]; exists && other != str {
			return "", &dash.Error{Code: dash.CodePermissionDenied, Message: "Conflicting Shield scope claims"}
		}
		return str, nil
	}
	tenant, err := claim("tenant_id")
	if err != nil {
		return admin.Actor{}, err
	}
	app, err := claim("app_id")
	if err != nil {
		return admin.Actor{}, err
	}
	read, _ := p.Claims["shield_read"].(bool)
	manage, _ := p.Claims["shield_manage"].(bool)
	sensitive, _ := p.Claims["shield_privacy_manage"].(bool)
	a := admin.Actor{Subject: p.User.Subject, Scope: store.Scope{TenantID: tenant, AppID: app}, Read: read, Manage: manage, Sensitive: sensitive}
	if err = a.Check(false); err != nil {
		return admin.Actor{}, mapError(err)
	}
	return a, nil
}
