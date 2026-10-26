package extension

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xraph/forge"
	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
	"github.com/xraph/forge/extensions/dashboard/contract/dispatcher"

	"github.com/xraph/shield/engine"
	"github.com/xraph/shield/store"
)

type lifecycleStore struct {
	store.Store
	store.DashboardStore
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

func TestContractContributorRegistration(t *testing.T) {
	s := &lifecycleStore{}
	e := New(WithStore(s))
	app := forge.New(forge.WithEnableConfigAutoDiscovery(false))
	if err := e.Register(app); err != nil {
		t.Fatal(err)
	}
	reg := dashcontract.NewRegistry()
	if err := e.RegisterContractContributor(dispatcher.New(nil), reg, dashcontract.NewWardenRegistry()); err != nil {
		t.Fatal(err)
	}
	if _, ok := reg.Contributor("shield"); !ok {
		t.Fatal("Shield contributor missing")
	}
}

func TestExtensionPassesScanLimits(t *testing.T) {
	dir := t.TempDir()
	yaml := "extensions:\n  shield:\n    max_scan_bytes: 2048\n    profile_cache_ttl: 5s\n    store_redacted: true\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	app := forge.New(forge.WithAppName("shield-limits"), forge.WithConfigSearchPaths(dir))
	e := New()
	if err := e.Register(app); err != nil {
		t.Fatal(err)
	}
	cfg := e.Engine().Config()
	if cfg.MaxScanBytes != 2048 || cfg.ProfileCacheTTL != 5*time.Second || !cfg.StoreRedacted {
		t.Fatalf("scan limits lost: %+v", cfg)
	}
}

func TestExtensionDefaultsScanLimits(t *testing.T) {
	app := forge.New(forge.WithEnableConfigAutoDiscovery(false))
	e := New(WithConfig(Config{ScanConcurrency: 3}))
	if err := e.Register(app); err != nil {
		t.Fatal(err)
	}
	cfg := e.Engine().Config()
	if cfg.MaxScanBytes != 1<<20 || cfg.ProfileCacheTTL != 30*time.Second || cfg.StoreRedacted {
		t.Fatalf("default scan limits = %+v", cfg)
	}
}

func TestExtensionPassesJudgeConfig(t *testing.T) {
	dir := t.TempDir()
	yaml := "extensions:\n  shield:\n    model_judge: true\n    judge_timeout: 2s\n    judge_concurrency: 3\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	app := forge.New(forge.WithAppName("shield-judge"), forge.WithConfigSearchPaths(dir))
	e := New()
	if err := e.Register(app); err != nil {
		t.Fatal(err)
	}
	cfg := e.Engine().Config()
	if !cfg.ModelJudge || cfg.JudgeTimeout != 2*time.Second || cfg.JudgeConcurrency != 3 {
		t.Fatalf("judge config lost: %+v", cfg)
	}
}

func TestExtensionJudgeDefaults(t *testing.T) {
	app := forge.New(forge.WithEnableConfigAutoDiscovery(false))
	e := New()
	if err := e.Register(app); err != nil {
		t.Fatal(err)
	}
	cfg := e.Engine().Config()
	if cfg.ModelJudge || cfg.JudgeTimeout != 5*time.Second || cfg.JudgeConcurrency != 8 {
		t.Fatalf("judge defaults = %+v", cfg)
	}
}
