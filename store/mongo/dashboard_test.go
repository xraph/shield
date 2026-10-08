package mongo

import (
	"context"
	"fmt"
	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/mongodriver"
	"github.com/xraph/shield/store/storetest"
	"os"
	"testing"
	"time"
)

func TestDashboardConformance(t *testing.T) {
	uri := os.Getenv("SHIELD_TEST_MONGO")
	if uri == "" {
		t.Skip("set SHIELD_TEST_MONGO to a disposable service")
	}
	storetest.Run(t, func(t *testing.T) storetest.Backend {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		d := mongodriver.New()
		if err := d.Open(ctx, uri, mongodriver.WithDatabase(fmt.Sprintf("shield_test_%d", time.Now().UnixNano()))); err != nil {
			t.Fatal(err)
		}
		db, err := grove.Open(d)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = d.Database().Drop(context.Background()); _ = db.Close() })
		s := New(db)
		if err := s.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		return s
	})
}
