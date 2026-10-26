// Package shieldtest builds the store and context that engine, admin and
// extension tests share: a migrated in-memory SQLite store and a context
// carrying a tenant and an app.
package shieldtest

import (
	"context"
	"testing"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/sqlitedriver"

	"github.com/xraph/shield"
	"github.com/xraph/shield/store/sqlite"
)

// Store opens a migrated SQLite store in memory and closes it when t ends.
func Store(t testing.TB) *sqlite.Store {
	t.Helper()
	ctx := context.Background()
	d := sqlitedriver.New()
	if err := d.Open(ctx, ":memory:"); err != nil {
		t.Fatal(err)
	}
	db, err := grove.Open(d)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := sqlite.New(db)
	if migrateErr := s.Migrate(ctx); migrateErr != nil {
		t.Fatal(migrateErr)
	}
	return s
}

// Ctx returns a background context carrying tenant and app.
func Ctx(tenant, app string) context.Context {
	return shield.WithApp(shield.WithTenant(context.Background(), tenant), app)
}
