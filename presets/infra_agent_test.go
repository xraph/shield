package presets_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/pgdriver"
	"github.com/xraph/grove/drivers/sqlitedriver"

	"github.com/xraph/shield"
	"github.com/xraph/shield/awareness"
	"github.com/xraph/shield/boundary"
	"github.com/xraph/shield/engine"
	"github.com/xraph/shield/instinct"
	"github.com/xraph/shield/internal/shieldtest"
	"github.com/xraph/shield/judgment"
	"github.com/xraph/shield/policy"
	"github.com/xraph/shield/presets"
	"github.com/xraph/shield/profile"
	"github.com/xraph/shield/reflex"
	"github.com/xraph/shield/scan"
	"github.com/xraph/shield/store"
	"github.com/xraph/shield/store/postgres"
	"github.com/xraph/shield/store/sqlite"
	"github.com/xraph/shield/values"
)

// bundleRows is the number of rows the InfraAgent bundle seeds: 4 instincts,
// 2 awareness, 1 boundary, 1 values, 1 judgment, 2 reflexes, 3 profiles and
// 1 policy.
const bundleRows = 15

func TestInfraAgentBundleIsComplete(t *testing.T) {
	b := presets.InfraAgent()
	if b.Name == "" {
		t.Fatal("bundle has no name")
	}
	names := map[string][]string{}
	add := func(kind, name string) {
		if slices.Contains(names[kind], name) {
			t.Errorf("%s %q appears twice", kind, name)
		}
		names[kind] = append(names[kind], name)
	}
	for _, r := range b.Instincts {
		add("instinct", r.Name)
	}
	for _, r := range b.Awareness {
		add("awareness", r.Name)
	}
	for _, r := range b.Boundaries {
		add("boundary", r.Name)
	}
	for _, r := range b.Values {
		add("values", r.Name)
	}
	for _, r := range b.Judgments {
		add("judgment", r.Name)
	}
	for _, r := range b.Reflexes {
		add("reflex", r.Name)
	}
	for _, r := range b.Profiles {
		add("profile", r.Name)
	}
	for _, r := range b.Policies {
		add("policy", r.Name)
		if r.ScopeLevel != policy.ScopeOrg {
			t.Errorf("policy %s is %s level, want org", r.Name, r.ScopeLevel)
		}
	}
	total := 0
	for _, list := range names {
		total += len(list)
	}
	if total != bundleRows {
		t.Errorf("bundle has %d rows, want %d", total, bundleRows)
	}
	want := []string{presets.InfraAgentInput, presets.InfraAgentOutput, presets.InfraAgentTools}
	for _, name := range want {
		if !slices.Contains(names["profile"], name) {
			t.Errorf("profile %s is missing", name)
		}
	}
	refers := func(p *profile.SafetyProfile, kind, name string) {
		if !slices.Contains(names[kind], name) {
			t.Errorf("profile %s references %s %q, which the bundle lacks", p.Name, kind, name)
		}
	}
	for _, p := range b.Profiles {
		for _, a := range p.Instincts {
			refers(p, "instinct", a.InstinctName)
		}
		for _, a := range p.Awareness {
			refers(p, "awareness", a.AwarenessName)
		}
		for _, a := range p.Judgments {
			refers(p, "judgment", a.JudgmentName)
		}
		for _, n := range p.Boundaries {
			refers(p, "boundary", n)
		}
		for _, n := range p.Values {
			refers(p, "values", n)
		}
		for _, n := range p.Reflexes {
			refers(p, "reflex", n)
		}
	}
	for _, a := range b.Awareness {
		if a.Focus == awareness.FocusSecrets && a.Action != "redact" {
			t.Errorf("secrets awareness %s acts %q, want redact", a.Name, a.Action)
		}
	}

	b.Instincts[0].Name = "changed"
	b.Instincts[0].Action = "allow"
	b.Instincts[0].Strategies[0].Name = "changed"
	b.Profiles[0].Instincts[0].InstinctName = "changed"
	b.Boundaries[0].Limits[0].Deny[0] = "changed"
	b.Policies[0].Rules[0].Action = "changed"
	next := presets.InfraAgent()
	if next.Instincts[0].Name == "changed" || next.Instincts[0].Action == "allow" ||
		next.Instincts[0].Strategies[0].Name == "changed" || next.Profiles[0].Instincts[0].InstinctName == "changed" ||
		next.Boundaries[0].Limits[0].Deny[0] == "changed" || next.Policies[0].Rules[0].Action == "changed" {
		t.Fatal("InfraAgent shares rows between calls")
	}
}

func TestSeedIsIdempotentAndPerTenant(t *testing.T) {
	s := shieldtest.Store(t)
	ctx := context.Background()
	b := presets.InfraAgent()

	first, err := b.Seed(ctx, s, "tenant-a", "app-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Created) != bundleRows || len(first.Kept) != 0 {
		t.Fatalf("first seed: created %d, kept %d", len(first.Created), len(first.Kept))
	}
	if !slices.Contains(first.Created, "instinct/prompt-injection") || !slices.Contains(first.Created, "policy/infra-agent-baseline") {
		t.Fatalf("report names: %v", first.Created)
	}
	for _, r := range b.Instincts {
		if !r.ID.IsNil() || r.TenantID != "" || r.AppID != "" {
			t.Fatalf("Seed changed the bundle's instinct %s", r.Name)
		}
	}

	second, err := b.Seed(ctx, s, "tenant-a", "app-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Created) != 0 || len(second.Kept) != bundleRows {
		t.Fatalf("second seed: created %v, kept %d", second.Created, len(second.Kept))
	}

	other, err := presets.InfraAgent().Seed(ctx, s, "tenant-b", "app-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(other.Created) != bundleRows {
		t.Fatalf("tenant-b seed: created %d, kept %v", len(other.Created), other.Kept)
	}

	ctxA := shieldtest.Ctx("tenant-a", "app-a")
	inst, err := s.GetInstinctByName(ctxA, "app-a", "prompt-injection")
	if err != nil {
		t.Fatal(err)
	}
	inst.Action = instinct.ActionFlag
	if err = s.UpdateInstinct(ctxA, inst); err != nil {
		t.Fatal(err)
	}
	if _, err = presets.InfraAgent().Seed(ctx, s, "tenant-a", "app-a"); err != nil {
		t.Fatal(err)
	}
	after, err := s.GetInstinctByName(ctxA, "app-a", "prompt-injection")
	if err != nil {
		t.Fatal(err)
	}
	if after.Action != instinct.ActionFlag {
		t.Fatalf("re-seed overwrote the tenant's edit: action %q", after.Action)
	}
	inB, err := s.GetInstinctByName(shieldtest.Ctx("tenant-b", "app-a"), "app-a", "prompt-injection")
	if err != nil {
		t.Fatal(err)
	}
	if inB.Action != instinct.ActionRedact {
		t.Fatalf("tenant-b instinct action %q, want redact", inB.Action)
	}

	pols, err := s.GetPoliciesForScope(ctxA, "tenant-a", policy.ScopeOrg)
	if err != nil {
		t.Fatal(err)
	}
	if len(pols) != 1 || pols[0].ScopeKey != "tenant-a" || pols[0].ScopeLevel != policy.ScopeOrg {
		t.Fatalf("tenant-a policies: %+v", pols)
	}
	appLevel, err := s.ListPolicies(context.Background(), &policy.ListFilter{ScopeKey: "app-a", ScopeLevel: policy.ScopeApp})
	if err != nil {
		t.Fatal(err)
	}
	if len(appLevel) != 0 {
		t.Fatalf("Seed wrote %d app-level policies", len(appLevel))
	}
}

func TestSeedRequiresTenant(t *testing.T) {
	s := shieldtest.Store(t)
	if _, err := presets.InfraAgent().Seed(context.Background(), s, "", "app-a"); !errors.Is(err, shield.ErrTenantRequired) {
		t.Fatalf("empty tenant: %v", err)
	}
	if _, err := presets.InfraAgent().Seed(context.Background(), s, "   ", "app-a"); !errors.Is(err, shield.ErrTenantRequired) {
		t.Fatalf("blank tenant: %v", err)
	}
}

// TestSeedIsSafeConcurrently seeds one tenant from two goroutines at once, as
// two replicas enabling AI for the same workspace would.
//
// The in-memory test store gives each pooled connection its own database, so
// this one is a file, where both goroutines' connections see one database
// and a writer waits for the other's lock.
func TestSeedIsSafeConcurrently(t *testing.T) {
	ctx := context.Background()
	d := sqlitedriver.New()
	dsn := "file:" + filepath.Join(t.TempDir(), "shield.db") + "?_pragma=busy_timeout(10000)"
	if err := d.Open(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	db, err := grove.Open(d)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := sqlite.New(db)
	if err = s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	seedConcurrently(t, s, "tenant-a", "app-a")
}

// seedConcurrently runs Seed for tenant from two goroutines and checks that
// every row was created exactly once and each report accounts for every row.
func seedConcurrently(t *testing.T, s store.Store, tenant, app string) {
	t.Helper()
	const replicas = 2
	reports := make([]presets.SeedReport, replicas)
	errs := make([]error, replicas)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range replicas {
		wg.Go(func() {
			<-start
			reports[i], errs[i] = presets.InfraAgent().Seed(context.Background(), s, tenant, app)
		})
	}
	close(start)
	wg.Wait()
	created := map[string]int{}
	for i, r := range reports {
		if errs[i] != nil {
			t.Fatalf("replica %d: %v", i, errs[i])
		}
		if n := len(r.Created) + len(r.Kept); n != bundleRows {
			t.Fatalf("replica %d accounts for %d rows, want %d", i, n, bundleRows)
		}
		for _, name := range r.Created {
			created[name]++
		}
	}
	if len(created) != bundleRows {
		t.Fatalf("%d rows created, want %d: %v", len(created), bundleRows, created)
	}
	for name, n := range created {
		if n != 1 {
			t.Fatalf("%s created %d times", name, n)
		}
	}
	assertOneRowEach(t, s, tenant, app)
}

// assertOneRowEach checks that tenant holds exactly one row per bundle name.
func assertOneRowEach(t *testing.T, s store.Store, tenant, app string) {
	t.Helper()
	ctx := shieldtest.Ctx(tenant, app)
	b := presets.InfraAgent()
	count := func(kind string, got, want int, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("list %s: %v", kind, err)
		}
		if got != want {
			t.Fatalf("%s: %d rows, want %d", kind, got, want)
		}
	}
	ins, err := s.ListInstincts(ctx, &instinct.ListFilter{AppID: app, TenantID: tenant})
	count("instincts", len(ins), len(b.Instincts), err)
	aw, err := s.ListAwareness(ctx, &awareness.ListFilter{AppID: app, TenantID: tenant})
	count("awareness", len(aw), len(b.Awareness), err)
	bs, err := s.ListBoundaries(ctx, &boundary.ListFilter{AppID: app, TenantID: tenant})
	count("boundaries", len(bs), len(b.Boundaries), err)
	vs, err := s.ListValues(ctx, &values.ListFilter{AppID: app, TenantID: tenant})
	count("values", len(vs), len(b.Values), err)
	js, err := s.ListJudgments(ctx, &judgment.ListFilter{AppID: app, TenantID: tenant})
	count("judgments", len(js), len(b.Judgments), err)
	rs, err := s.ListReflexes(ctx, &reflex.ListFilter{AppID: app, TenantID: tenant})
	count("reflexes", len(rs), len(b.Reflexes), err)
	ps, err := s.ListProfiles(ctx, &profile.ListFilter{AppID: app, TenantID: tenant})
	count("profiles", len(ps), len(b.Profiles), err)
	pols, err := s.GetPoliciesForScope(ctx, tenant, policy.ScopeOrg)
	count("policies", len(pols), len(b.Policies), err)
}

// TestSeedOnPostgres seeds a throwaway Postgres schema, where every
// collection column is a NOT NULL jsonb, then scans through the seeded
// profiles. It runs when SHIELD_TEST_POSTGRES names a disposable database.
func TestSeedOnPostgres(t *testing.T) {
	dsn := os.Getenv("SHIELD_TEST_POSTGRES")
	if dsn == "" {
		t.Skip("set SHIELD_TEST_POSTGRES to a disposable database")
	}
	s := postgresStore(t, dsn)
	ctx := context.Background()
	first, err := presets.InfraAgent().Seed(ctx, s, "tenant-a", "app-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Created) != bundleRows {
		t.Fatalf("first seed created %d rows", len(first.Created))
	}
	again, err := presets.InfraAgent().Seed(ctx, s, "tenant-a", "app-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Kept) != bundleRows {
		t.Fatalf("second seed kept %d rows", len(again.Kept))
	}
	seedConcurrently(t, s, "tenant-b", "app-a")

	eng, err := engine.New(engine.WithStore(s))
	if err != nil {
		t.Fatal(err)
	}
	scanCtx := shieldtest.Ctx("tenant-a", "app-a")
	r, err := eng.ScanOutput(scanCtx, &scan.Input{Text: "token " + githubToken(), Profile: presets.InfraAgentOutput})
	if err != nil {
		t.Fatal(err)
	}
	if r.Decision != scan.DecisionRedact {
		t.Fatalf("decision %s, findings %+v", r.Decision, r.Findings)
	}
	if _, err = s.GetScan(scanCtx, r.ID); err != nil {
		t.Fatalf("scan not stored: %v", err)
	}
	call, err := eng.ScanToolCall(scanCtx, &scan.ToolCallInput{Tool: "delete_environment", RiskClass: presets.RiskDestroyProduction, Profile: presets.InfraAgentTools})
	if err != nil {
		t.Fatal(err)
	}
	if call.Decision != scan.DecisionRequireApproval {
		t.Fatalf("tool call decision %s", call.Decision)
	}
}

// postgresStore opens a migrated store in a fresh schema of dsn and drops the
// schema when t ends. The schema goes on the DSN as search_path, so every
// pooled connection uses it, as the concurrent seed needs.
func postgresStore(t *testing.T, dsn string) *postgres.Store {
	t.Helper()
	ctx := context.Background()
	admin := pgdriver.New()
	if err := admin.Open(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("shield_presets_%d", time.Now().UnixNano())
	if _, err := admin.NewRaw("CREATE SCHEMA " + schema).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	d := pgdriver.New()
	if err := d.Open(ctx, dsn+sep+"search_path="+schema); err != nil {
		t.Fatal(err)
	}
	db, err := grove.Open(d)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		_, _ = admin.NewRaw("DROP SCHEMA " + schema + " CASCADE").Exec(ctx)
		_ = admin.Close()
	})
	s := postgres.New(db)
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return s
}
