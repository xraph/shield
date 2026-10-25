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

func TestUniqueNamesPerTenantKeepsRows(t *testing.T) {
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
	insert := func(table, tenant string) error {
		_, insertErr := s.sdb.NewRaw("INSERT INTO " + table + " (id, name, app_id, tenant_id, " + primitiveInserts[table] +
			") VALUES ('id-" + tenant + "', 'same', 'app', '" + tenant + "', " + primitiveValues[table] + ")").Exec(ctx)
		return insertErr
	}
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
		if err = insert(table, "t1"); err != nil {
			t.Fatalf("%s seed: %v", table, err)
		}
		before[table] = snapshot(table)
	}
	if err = last.Up(ctx, exec); err != nil {
		t.Fatal(err)
	}
	for table := range primitiveInserts {
		if got := snapshot(table); got != before[table] {
			t.Fatalf("%s row changed:\n%s\n%s", table, before[table], got)
		}
		if err = insert(table, "t2"); err != nil {
			t.Fatalf("%s same name in another tenant: %v", table, err)
		}
		_, err = s.sdb.NewRaw("INSERT INTO " + table + " (id, name, app_id, tenant_id, " + primitiveInserts[table] +
			") VALUES ('dup', 'same', 'app', 't1', " + primitiveValues[table] + ")").Exec(ctx)
		if err == nil || !strings.Contains(err.Error(), "UNIQUE constraint failed") {
			t.Fatalf("%s same name in same tenant: %v", table, err)
		}
	}
}
