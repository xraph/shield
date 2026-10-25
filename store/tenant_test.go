package store

import (
	"context"
	"errors"
	"testing"

	"github.com/xraph/shield"
)

func TestTenantResolution(t *testing.T) {
	cases := []struct {
		name    string
		want    string
		ctx     string
		got     string
		wantErr error
	}{
		{name: "neither", wantErr: shield.ErrTenantRequired},
		{name: "filter only", want: "a", got: "a"},
		{name: "context only", ctx: "a", got: "a"},
		{name: "both agree", want: "a", ctx: "a", got: "a"},
		{name: "both disagree", want: "b", ctx: "a", wantErr: shield.ErrTenantMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.ctx != "" {
				ctx = shield.WithTenant(ctx, tc.ctx)
			}
			got, err := Tenant(ctx, tc.want)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if got != tc.got {
				t.Fatalf("tenant = %q, want %q", got, tc.got)
			}
		})
	}
}

func TestScopeVisible(t *testing.T) {
	ctx := shield.WithApp(shield.WithTenant(context.Background(), "tenant-a"), "app-a")
	cases := []struct {
		name  string
		ctx   context.Context
		key   string
		level string
		want  bool
	}{
		{name: "org key is the context tenant", ctx: ctx, key: "tenant-a", level: "org", want: true},
		{name: "org key is another tenant", ctx: ctx, key: "tenant-b", level: "org"},
		{name: "app key is the context app", ctx: ctx, key: "app-a", level: "app", want: true},
		{name: "app key is another app", ctx: ctx, key: "app-b", level: "app"},
		{name: "app key with no context app", ctx: shield.WithTenant(context.Background(), "tenant-a"), key: "app-a", level: "app"},
		{name: "org key with no context tenant", ctx: context.Background(), key: "tenant-a", level: "org"},
		{name: "empty key never matches", ctx: context.Background(), key: "", level: "org"},
		{name: "unknown level", ctx: ctx, key: "tenant-a", level: "team"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ScopeVisible(tc.ctx, tc.key, tc.level); got != tc.want {
				t.Fatalf("ScopeVisible(%q, %q) = %v, want %v", tc.key, tc.level, got, tc.want)
			}
		})
	}
}

func TestScopeLevels(t *testing.T) {
	ctx := shield.WithApp(shield.WithTenant(context.Background(), "tenant-a"), "app-a")
	cases := []struct {
		name    string
		ctx     context.Context
		key     string
		level   string
		want    []string
		wantErr error
	}{
		{name: "empty key", ctx: ctx, wantErr: shield.ErrTenantRequired},
		{name: "empty key without a context tenant", ctx: context.Background(), wantErr: shield.ErrTenantRequired},
		{name: "filter only keeps every level", ctx: context.Background(), key: "tenant-b"},
		{name: "own tenant narrows to org", ctx: ctx, key: "tenant-a", want: []string{"org"}},
		{name: "own app narrows to app", ctx: ctx, key: "app-a", want: []string{"app"}},
		{name: "own tenant at the org level", ctx: ctx, key: "tenant-a", level: "org", want: []string{"org"}},
		{name: "own tenant at the app level", ctx: ctx, key: "tenant-a", level: "app", wantErr: shield.ErrTenantMismatch},
		{name: "foreign tenant", ctx: ctx, key: "tenant-b", wantErr: shield.ErrTenantMismatch},
		{name: "foreign app", ctx: ctx, key: "app-b", level: "app", wantErr: shield.ErrTenantMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ScopeLevels(tc.ctx, tc.key, tc.level)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("levels = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("levels = %v, want %v", got, tc.want)
				}
			}
		})
	}
}
