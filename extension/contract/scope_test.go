package contract

import (
	"context"
	auth "github.com/xraph/forge/extensions/dashboard/auth"
	dash "github.com/xraph/forge/extensions/dashboard/contract"
	"testing"
)

func TestScopeRefusesMalformedClaims(t *testing.T) {
	ctx := context.Background()
	for _, claims := range []map[string]any{nil, {}, {"tenant_id": "", "app_id": "a"}, {"tenant_id": nil, "app_id": "a"}, {"tenant_id": 3, "app_id": "a"}, {"tenant_id": "a", "app_id": "a", "shield_app_id": "b"}} {
		p := dash.Principal{User: &auth.UserInfo{Subject: "u"}, Claims: claims}
		if _, err := ResolveActor(ctx, p); err == nil {
			t.Fatal("bad claims accepted", claims)
		}
	}
	if _, err := ResolveActor(ctx, dash.Principal{}); err == nil {
		t.Fatal("anonymous accepted")
	}
	p := dash.Principal{User: &auth.UserInfo{Subject: "u"}, Claims: map[string]any{"tenant_id": "a", "app_id": "a", "shield_read": true, "shield_manage": false}}
	a, err := ResolveActor(ctx, p)
	if err != nil || !a.Read || a.Manage || a.Scope.AppID != "a" {
		t.Fatal(a, err)
	}
}
