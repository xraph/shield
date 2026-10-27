package mongo

import (
	"context"
	"errors"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/xraph/grove/drivers/mongodriver/mongomigrate"
	"github.com/xraph/grove/migrate"
)

// Migrations is the grove migration group for the Shield mongo store.
var Migrations = migrate.NewGroup("shield")

func init() {
	Migrations.MustRegister(
		&migrate.Migration{
			Name:    "create_shield_instincts",
			Version: "20240101000001",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateCollection(ctx, (*instinctModel)(nil)); err != nil {
					return err
				}

				return mexec.CreateIndexes(ctx, colInstincts, []mongo.IndexModel{
					{
						Keys:    bson.D{{Key: "app_id", Value: 1}, {Key: "name", Value: 1}},
						Options: options.Index().SetUnique(true),
					},
					{Keys: bson.D{{Key: "app_id", Value: 1}, {Key: "tenant_id", Value: 1}}},
				})
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*instinctModel)(nil))
			},
		},
		&migrate.Migration{
			Name:    "create_shield_awareness",
			Version: "20240101000002",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateCollection(ctx, (*awarenessModel)(nil)); err != nil {
					return err
				}

				return mexec.CreateIndexes(ctx, colAwareness, []mongo.IndexModel{
					{
						Keys:    bson.D{{Key: "app_id", Value: 1}, {Key: "name", Value: 1}},
						Options: options.Index().SetUnique(true),
					},
					{Keys: bson.D{{Key: "app_id", Value: 1}, {Key: "tenant_id", Value: 1}}},
				})
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*awarenessModel)(nil))
			},
		},
		&migrate.Migration{
			Name:    "create_shield_boundaries",
			Version: "20240101000003",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateCollection(ctx, (*boundaryModel)(nil)); err != nil {
					return err
				}

				return mexec.CreateIndexes(ctx, colBoundaries, []mongo.IndexModel{
					{
						Keys:    bson.D{{Key: "app_id", Value: 1}, {Key: "name", Value: 1}},
						Options: options.Index().SetUnique(true),
					},
					{Keys: bson.D{{Key: "app_id", Value: 1}, {Key: "tenant_id", Value: 1}}},
				})
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*boundaryModel)(nil))
			},
		},
		&migrate.Migration{
			Name:    "create_shield_values",
			Version: "20240101000004",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateCollection(ctx, (*valuesModel)(nil)); err != nil {
					return err
				}

				return mexec.CreateIndexes(ctx, colValues, []mongo.IndexModel{
					{
						Keys:    bson.D{{Key: "app_id", Value: 1}, {Key: "name", Value: 1}},
						Options: options.Index().SetUnique(true),
					},
					{Keys: bson.D{{Key: "app_id", Value: 1}, {Key: "tenant_id", Value: 1}}},
				})
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*valuesModel)(nil))
			},
		},
		&migrate.Migration{
			Name:    "create_shield_judgments",
			Version: "20240101000005",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateCollection(ctx, (*judgmentModel)(nil)); err != nil {
					return err
				}

				return mexec.CreateIndexes(ctx, colJudgments, []mongo.IndexModel{
					{
						Keys:    bson.D{{Key: "app_id", Value: 1}, {Key: "name", Value: 1}},
						Options: options.Index().SetUnique(true),
					},
					{Keys: bson.D{{Key: "app_id", Value: 1}, {Key: "tenant_id", Value: 1}}},
				})
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*judgmentModel)(nil))
			},
		},
		&migrate.Migration{
			Name:    "create_shield_reflexes",
			Version: "20240101000006",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateCollection(ctx, (*reflexModel)(nil)); err != nil {
					return err
				}

				return mexec.CreateIndexes(ctx, colReflexes, []mongo.IndexModel{
					{
						Keys:    bson.D{{Key: "app_id", Value: 1}, {Key: "name", Value: 1}},
						Options: options.Index().SetUnique(true),
					},
					{Keys: bson.D{{Key: "app_id", Value: 1}, {Key: "tenant_id", Value: 1}}},
				})
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*reflexModel)(nil))
			},
		},
		&migrate.Migration{
			Name:    "create_shield_profiles",
			Version: "20240101000007",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateCollection(ctx, (*profileModel)(nil)); err != nil {
					return err
				}

				return mexec.CreateIndexes(ctx, colProfiles, []mongo.IndexModel{
					{
						Keys:    bson.D{{Key: "app_id", Value: 1}, {Key: "name", Value: 1}},
						Options: options.Index().SetUnique(true),
					},
					{Keys: bson.D{{Key: "app_id", Value: 1}, {Key: "tenant_id", Value: 1}}},
				})
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*profileModel)(nil))
			},
		},
		&migrate.Migration{
			Name:    "create_shield_scans",
			Version: "20240101000008",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateCollection(ctx, (*scanResultModel)(nil)); err != nil {
					return err
				}

				return mexec.CreateIndexes(ctx, colScans, []mongo.IndexModel{
					{Keys: bson.D{{Key: "app_id", Value: 1}}},
					{Keys: bson.D{{Key: "tenant_id", Value: 1}}},
					{Keys: bson.D{{Key: "decision", Value: 1}, {Key: "created_at", Value: -1}}},
				})
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*scanResultModel)(nil))
			},
		},
		&migrate.Migration{
			Name:    "create_shield_policies",
			Version: "20240101000009",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateCollection(ctx, (*policyModel)(nil)); err != nil {
					return err
				}

				return mexec.CreateIndexes(ctx, colPolicies, []mongo.IndexModel{
					{
						Keys:    bson.D{{Key: "scope_key", Value: 1}, {Key: "name", Value: 1}},
						Options: options.Index().SetUnique(true),
					},
					{Keys: bson.D{{Key: "scope_key", Value: 1}, {Key: "scope_level", Value: 1}}},
				})
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*policyModel)(nil))
			},
		},
		&migrate.Migration{
			Name:    "create_shield_pii_tokens",
			Version: "20240101000010",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateCollection(ctx, (*piiTokenModel)(nil)); err != nil {
					return err
				}

				return mexec.CreateIndexes(ctx, colPIITokens, []mongo.IndexModel{
					{Keys: bson.D{{Key: "scan_id", Value: 1}}},
					{Keys: bson.D{{Key: "tenant_id", Value: 1}}},
				})
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*piiTokenModel)(nil))
			},
		},
		&migrate.Migration{
			Name:    "create_shield_compliance_reports",
			Version: "20240101000011",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateCollection(ctx, (*complianceReportModel)(nil)); err != nil {
					return err
				}

				return mexec.CreateIndexes(ctx, colCompliance, []mongo.IndexModel{
					{Keys: bson.D{{Key: "scope_key", Value: 1}, {Key: "framework", Value: 1}}},
				})
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*complianceReportModel)(nil))
			},
		},
		&migrate.Migration{
			Name:    "unique_names_per_tenant",
			Version: "20261024000001",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				return swapNameIndex(ctx, exec, appNameIndex, appTenantNameIndex)
			},
			// Down fails if two tenants now share a name under one app.
			Down: func(ctx context.Context, exec migrate.Executor) error {
				return swapNameIndex(ctx, exec, appTenantNameIndex, appNameIndex)
			},
		},
	)
}

var (
	appNameIndex       = bson.D{{Key: "app_id", Value: 1}, {Key: "name", Value: 1}}
	appTenantNameIndex = bson.D{{Key: "app_id", Value: 1}, {Key: "tenant_id", Value: 1}, {Key: "name", Value: 1}}
)

// tenantUniqueCollections lists the primitive collections whose name uniqueness
// moves from (app_id, name) to (app_id, tenant_id, name).
var tenantUniqueCollections = []string{
	colInstincts, colAwareness, colBoundaries, colValues, colJudgments, colReflexes, colProfiles,
}

// swapNameIndex drops the unique index on from (a missing index is fine) and creates a unique one on to.
func swapNameIndex(ctx context.Context, exec migrate.Executor, from, to bson.D) error {
	mexec, ok := exec.(*mongomigrate.Executor)
	if !ok {
		return fmt.Errorf("expected mongomigrate executor, got %T", exec)
	}
	for _, col := range tenantUniqueCollections {
		if err := mexec.DB().Collection(col).Indexes().DropOne(ctx, indexName(from)); err != nil && !isIndexNotFound(err) {
			return err
		}
		if err := mexec.CreateIndexes(ctx, col, []mongo.IndexModel{{Keys: to, Options: options.Index().SetUnique(true)}}); err != nil {
			return err
		}
	}
	return nil
}

func indexName(keys bson.D) string {
	name := ""
	for i, k := range keys {
		if i > 0 {
			name += "_"
		}
		name += fmt.Sprintf("%s_%v", k.Key, k.Value)
	}
	return name
}

func isIndexNotFound(err error) bool {
	var ce mongo.CommandError
	return errors.As(err, &ce) && (ce.Name == "IndexNotFound" || ce.Code == 27 || ce.Code == 26)
}
