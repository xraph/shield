package sqlite

import (
	"context"
	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/sqlitedriver"
	"github.com/xraph/shield/store/storetest"
	"testing"
)

func dashboardStore(t *testing.T) *Store {
	t.Helper()
	d := sqlitedriver.New()
	if err := d.Open(context.Background(), ":memory:"); err != nil {
		t.Fatal(err)
	}
	db, err := grove.Open(d)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := New(db)
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}
func TestDashboardConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) storetest.Backend { return dashboardStore(t) })
}
