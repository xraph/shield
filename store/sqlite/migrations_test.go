package sqlite

import (
	"context"
	"strings"
	"testing"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/sqlitedriver"
	"github.com/xraph/grove/migrate"
)

// primitiveInserts holds one row per primitive table, with the columns each
// table requires. app_id, tenant_id and name are appended by the test.
var primitiveInserts = map[string]string{
	"shield_instincts":  "category, action, strategies, description",
	"shield_awareness":  "focus, action, detectors, description",
	"shield_boundaries": "limits, response, description, metadata",
	"shield_values":     "severity, action, rules, description",
	"shield_judgments":  "domain, action, threshold, description",
	"shield_reflexes":   "priority, triggers, actions, description",
	"shield_profiles":   "instincts, judgments, awareness, boundaries, description",
}

var primitiveValues = map[string]string{
	"shield_instincts":  "'injection', 'block', '[{\"name\":\"x\"}]', 'kept'",
	"shield_awareness":  "'pii', 'redact', '[{\"name\":\"y\"}]', 'kept'",
	"shield_boundaries": "'[1]', 'refuse', 'kept', '{\"k\":1}'",
	"shield_values":     "'warning', 'flag', '[2]', 'kept'",
	"shield_judgments":  "'grounding', 'warn', 0.5, 'kept'",
	"shield_reflexes":   "7, '[3]', '[4]', 'kept'",
	"shield_profiles":   "'[\"a\"]', '[\"b\"]', '[\"c\"]', '[\"d\"]', 'kept'",
}

// preTenantStore applies every migration before 20261024000001 and returns the
// store, its executor and the tenant-unique migration.
func preTenantStore(t *testing.T) (*Store, migrate.Executor, *migrate.Migration) {
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
	s := New(db)
	exec, err := migrate.NewExecutorFor(s.sdb)
	if err != nil {
		t.Fatal(err)
	}
	all := Migrations.Migrations()
	last := all[len(all)-1]
	if last.Version != "20261024000001" || last.Name != "unique_names_per_tenant" {
		t.Fatalf("last migration is %s %s", last.Version, last.Name)
	}
	for _, m := range all[:len(all)-1] {
		if err = m.Up(ctx, exec); err != nil {
			t.Fatalf("%s: %v", m.Name, err)
		}
	}
	return s, exec, last
}

func (s *Store) seedPrimitive(t *testing.T, table, tenant string) error {
	t.Helper()
	_, err := s.sdb.NewRaw("INSERT INTO " + table + " (id, name, app_id, tenant_id, " + primitiveInserts[table] +
		") VALUES ('id-" + tenant + "', 'same', 'app', '" + tenant + "', " + primitiveValues[table] + ")").Exec(context.Background())
	return err
}

func TestUniqueNamesPerTenantKeepsRows(t *testing.T) {
	ctx := context.Background()
	s, exec, last := preTenantStore(t)
	insert := func(table, tenant string) error { return s.seedPrimitive(t, table, tenant) }
	snapshot := func(table string) string {
		var row string
		q := "SELECT id || '|' || name || '|' || description || '|' || app_id || '|' || tenant_id || '|' || created_at || '|' || updated_at || '|' || enabled || '|' || metadata FROM " + table
		if scanErr := s.sdb.NewRaw(q).Scan(ctx, &row); scanErr != nil {
			t.Fatalf("%s snapshot: %v", table, scanErr)
		}
		return row
	}
	before := map[string]string{}
	for table := range primitiveInserts {
		if err := insert(table, "t1"); err != nil {
			t.Fatalf("%s seed: %v", table, err)
		}
		before[table] = snapshot(table)
	}
	if err := last.Up(ctx, exec); err != nil {
		t.Fatal(err)
	}
	for table := range primitiveInserts {
		if got := snapshot(table); got != before[table] {
			t.Fatalf("%s row changed:\n%s\n%s", table, before[table], got)
		}
		if err := insert(table, "t2"); err != nil {
			t.Fatalf("%s same name in another tenant: %v", table, err)
		}
		_, err := s.sdb.NewRaw("INSERT INTO " + table + " (id, name, app_id, tenant_id, " + primitiveInserts[table] +
			") VALUES ('dup', 'same', 'app', 't1', " + primitiveValues[table] + ")").Exec(ctx)
		if err == nil || !strings.Contains(err.Error(), "UNIQUE constraint failed") {
			t.Fatalf("%s same name in same tenant: %v", table, err)
		}
	}
}

func tableNames(t *testing.T, s *Store) string {
	t.Helper()
	var names string
	q := "SELECT group_concat(name, ',') FROM (SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'shield_%' ORDER BY name)"
	if err := s.sdb.NewRaw(q).Scan(context.Background(), &names); err != nil {
		t.Fatal(err)
	}
	return names
}

func TestUniqueNamesPerTenantDownChecksFirst(t *testing.T) {
	ctx := context.Background()
	s, exec, last := preTenantStore(t)
	if err := last.Up(ctx, exec); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"t1", "t2"} {
		if err := s.seedPrimitive(t, "shield_profiles", tenant); err != nil {
			t.Fatal(err)
		}
	}
	tablesBefore := tableNames(t, s)
	if err := last.Down(ctx, exec); err == nil {
		t.Fatal("Down accepted two tenants sharing a name")
	}
	if got := tableNames(t, s); got != tablesBefore {
		t.Fatalf("failed Down changed tables:\n%s\n%s", tablesBefore, got)
	}
	// The tenant-unique key is still in force: the same name in t1 is rejected.
	if err := s.seedPrimitive(t, "shield_instincts", "t1"); err != nil {
		t.Fatal(err)
	}
	if err := s.seedPrimitive(t, "shield_instincts", "t1"); err == nil {
		t.Fatal("tables were reverted by a failed Down")
	}
	if _, err := s.sdb.NewRaw("DELETE FROM shield_profiles WHERE tenant_id = 't2'").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if err := last.Down(ctx, exec); err != nil {
		t.Fatal(err)
	}
	if err := s.seedPrimitive(t, "shield_instincts", "t2"); err == nil {
		t.Fatal("Down did not restore the (app_id, name) key")
	}
}

func TestUniqueNamesPerTenantIgnoresLeftoverTable(t *testing.T) {
	ctx := context.Background()
	s, exec, last := preTenantStore(t)
	if err := s.seedPrimitive(t, "shield_values", "t1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.sdb.NewRaw("CREATE TABLE shield_values_new (junk TEXT)").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if err := last.Up(ctx, exec); err != nil {
		t.Fatalf("leftover _new table blocked Up: %v", err)
	}
	if err := s.seedPrimitive(t, "shield_values", "t2"); err != nil {
		t.Fatal(err)
	}
}

// A rebuild that fails between dropping a table and renaming its copy
// rolls back, so the table and its rows survive, and a rerun after the cause
// is gone completes. The view makes SQLite refuse the rename: it re-checks
// every view then, and this one names the table just dropped.
func TestUniqueNamesPerTenantRollsBackAFailedRebuild(t *testing.T) {
	ctx := context.Background()
	s, exec, last := preTenantStore(t)
	for _, table := range []string{"shield_instincts", "shield_values"} {
		if err := s.seedPrimitive(t, table, "t1"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.sdb.NewRaw("CREATE VIEW shield_values_view AS SELECT name FROM shield_values").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	err := last.Up(ctx, exec)
	if err == nil || !strings.Contains(err.Error(), "shield_values_view") {
		t.Fatalf("Up = %v, want the rename refused over the view", err)
	}
	count := func(table string) int {
		var n int
		if scanErr := s.sdb.NewRaw("SELECT COUNT(*) FROM "+table+" WHERE tenant_id = 't1'").Scan(ctx, &n); scanErr != nil {
			t.Fatalf("%s: %v", table, scanErr)
		}
		return n
	}
	if n := count("shield_values"); n != 1 {
		t.Fatalf("shield_values holds %d rows after the failed rebuild", n)
	}
	if names := tableNames(t, s); strings.Contains(names, "shield_values_new") {
		t.Fatalf("the failed rebuild left its copy behind: %s", names)
	}
	// The connection is usable and holds no open transaction.
	if err = s.seedPrimitive(t, "shield_boundaries", "t1"); err != nil {
		t.Fatal(err)
	}

	if _, err = s.sdb.NewRaw("DROP VIEW shield_values_view").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if err = last.Up(ctx, exec); err != nil {
		t.Fatalf("rerun: %v", err)
	}
	for _, table := range []string{"shield_instincts", "shield_values", "shield_boundaries"} {
		if n := count(table); n != 1 {
			t.Fatalf("%s holds %d rows after the rerun", table, n)
		}
	}
	if err = s.seedPrimitive(t, "shield_values", "t2"); err != nil {
		t.Fatalf("tenant-unique key missing after the rerun: %v", err)
	}
}
