package postgres

import (
	"context"
	"fmt"
	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/pgdriver"
	"github.com/xraph/shield/store/storetest"
	"os"
	"testing"
	"time"
)

func TestDashboardConformance(t *testing.T) {
	dsn := os.Getenv("SHIELD_TEST_POSTGRES")
	if dsn == "" {
		t.Skip("set SHIELD_TEST_POSTGRES to a disposable database")
	}
	storetest.Run(t, func(t *testing.T) storetest.Backend {
		ctx := context.Background()
		d := pgdriver.New()
		if err := d.Open(ctx, dsn); err != nil {
			t.Fatal(err)
		}
		schema := fmt.Sprintf("shield_test_%d", time.Now().UnixNano())
		if _, err := d.NewRaw("CREATE SCHEMA " + schema).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := d.NewRaw("SET search_path TO " + schema).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		db, err := grove.Open(d)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = d.NewRaw("DROP SCHEMA " + schema + " CASCADE").Exec(ctx); _ = db.Close() })
		s := New(db)
		if err := s.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		return s
	})
}
