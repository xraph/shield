package extension

import (
	"context"
	"errors"
	"github.com/xraph/forge"
	"github.com/xraph/shield/engine"
	"github.com/xraph/shield/store"
	"testing"
)

type lifecycleStore struct {
	store.Store
	migrations int
	failure    error
	closed     bool
}

func (s *lifecycleStore) Migrate(context.Context) error { s.migrations++; return s.failure }
func (s *lifecycleStore) Ping(context.Context) error    { return s.failure }
func (s *lifecycleStore) Close() error                  { s.closed = true; return nil }
func TestLifecycleMigratesAndDoesNotCloseInjectedStore(t *testing.T) {
	s := &lifecycleStore{}
	eng, _ := engine.New(engine.WithStore(s))
	e := New()
	e.eng = eng
	if err := e.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.migrations != 1 {
		t.Fatal("store was not migrated")
	}
	if err := e.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.closed {
		t.Fatal("closed injected store")
	}
}
func TestLifecycleHonorsDisabledMigrationsAndHealthFailures(t *testing.T) {
	s := &lifecycleStore{failure: errors.New("offline")}
	eng, _ := engine.New(engine.WithStore(s))
	e := New(WithDisableMigrate())
	e.eng = eng
	if err := e.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.migrations != 0 {
		t.Fatal("migration disabled")
	}
	if e.Health(context.Background()) == nil {
		t.Fatal("health hid failure")
	}
	e.config.DisableMigrate = false
	if e.Start(context.Background()) == nil {
		t.Fatal("migration failure hidden")
	}
}

func TestRegisterPassesEffectiveConfig(t *testing.T) {
	app := forge.New(forge.WithEnableConfigAutoDiscovery(false))
	e := New(WithConfig(Config{DefaultProfile: "strict", ScanConcurrency: 3, EnableShortCircuit: false}))
	if err := e.Register(app); err != nil {
		t.Fatal(err)
	}
	cfg := e.Engine().Config()
	if cfg.DefaultProfile != "strict" || cfg.ScanConcurrency != 3 || cfg.EnableShortCircuit {
		t.Fatalf("effective config lost: %+v", cfg)
	}
}
