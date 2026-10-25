package mongo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	mongod "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/mongodriver"

	"github.com/xraph/shield"
	"github.com/xraph/shield/awareness"
	"github.com/xraph/shield/boundary"
	"github.com/xraph/shield/compliance"
	"github.com/xraph/shield/id"
	"github.com/xraph/shield/instinct"
	"github.com/xraph/shield/judgment"
	"github.com/xraph/shield/pii"
	"github.com/xraph/shield/policy"
	"github.com/xraph/shield/profile"
	"github.com/xraph/shield/reflex"
	"github.com/xraph/shield/scan"
	"github.com/xraph/shield/store"
	"github.com/xraph/shield/values"
)

// Collection name constants.
const (
	colInstincts  = "shield_instincts"
	colAwareness  = "shield_awareness"
	colBoundaries = "shield_boundaries"
	colValues     = "shield_values"
	colJudgments  = "shield_judgments"
	colReflexes   = "shield_reflexes"
	colProfiles   = "shield_profiles"
	colScans      = "shield_scans"
	colPolicies   = "shield_policies"
	colPIITokens  = "shield_pii_tokens"
	colCompliance = "shield_compliance_reports"
)

// Compile-time interface check.
var _ store.Store = (*Store)(nil)

// Store implements store.Store using MongoDB via Grove ORM.
type Store struct {
	db  *grove.DB
	mdb *mongodriver.MongoDB
}

// New creates a new MongoDB store backed by Grove ORM.
func New(db *grove.DB) *Store {
	return &Store{
		db:  db,
		mdb: mongodriver.Unwrap(db),
	}
}

// Migrate creates indexes for all shield collections.
func (s *Store) Migrate(ctx context.Context) error {
	indexes := migrationIndexes()
	for _, col := range tenantUniqueCollections {
		// Stores created before names became unique per tenant still carry the
		// (app_id, name) index, which would reject the same name in a second tenant.
		err := s.mdb.Collection(col).Indexes().DropOne(ctx, indexName(appNameIndex))
		if err != nil && !isIndexNotFound(err) {
			return fmt.Errorf("shield/mongo: migrate %s indexes: %w", col, err)
		}
	}
	for col, models := range indexes {
		if len(models) == 0 {
			continue
		}
		_, err := s.mdb.Collection(col).Indexes().CreateMany(ctx, models)
		if err != nil {
			return fmt.Errorf("shield/mongo: migrate %s indexes: %w", col, err)
		}
	}
	return nil
}

// Ping checks database connectivity.
func (s *Store) Ping(ctx context.Context) error {
	return s.db.Ping(ctx)
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// now returns the current UTC time.
func now() time.Time {
	return time.Now().UTC()
}

// isNoDocuments checks if an error wraps mongo.ErrNoDocuments.
func isNoDocuments(err error) bool {
	return errors.Is(err, mongod.ErrNoDocuments)
}

// notFoundOrWrap returns the appropriate not-found sentinel or wraps the error.
func notFoundOrWrap(err, sentinel error, msg string) error {
	if isNoDocuments(err) {
		return sentinel
	}
	return fmt.Errorf("shield/mongo: %s: %w", msg, err)
}

// claimTenant fills an entity's empty TenantID from the context tenant and
// refuses one that names a different tenant (store.Tenant).
func claimTenant(ctx context.Context, tenantID *string) error {
	tenant, err := store.Tenant(ctx, *tenantID)
	if err != nil {
		return err
	}
	*tenantID = tenant
	return nil
}

// migrationIndexes returns the index definitions for all shield collections.
func migrationIndexes() map[string][]mongod.IndexModel {
	return map[string][]mongod.IndexModel{
		colInstincts: {
			{
				Keys:    bson.D{{Key: "app_id", Value: 1}, {Key: "tenant_id", Value: 1}, {Key: "name", Value: 1}},
				Options: options.Index().SetUnique(true),
			},
			{Keys: bson.D{{Key: "app_id", Value: 1}, {Key: "tenant_id", Value: 1}}},
		},
		colAwareness: {
			{
				Keys:    bson.D{{Key: "app_id", Value: 1}, {Key: "tenant_id", Value: 1}, {Key: "name", Value: 1}},
				Options: options.Index().SetUnique(true),
			},
			{Keys: bson.D{{Key: "app_id", Value: 1}, {Key: "tenant_id", Value: 1}}},
		},
		colBoundaries: {
			{
				Keys:    bson.D{{Key: "app_id", Value: 1}, {Key: "tenant_id", Value: 1}, {Key: "name", Value: 1}},
				Options: options.Index().SetUnique(true),
			},
			{Keys: bson.D{{Key: "app_id", Value: 1}, {Key: "tenant_id", Value: 1}}},
		},
		colValues: {
			{
				Keys:    bson.D{{Key: "app_id", Value: 1}, {Key: "tenant_id", Value: 1}, {Key: "name", Value: 1}},
				Options: options.Index().SetUnique(true),
			},
			{Keys: bson.D{{Key: "app_id", Value: 1}, {Key: "tenant_id", Value: 1}}},
		},
		colJudgments: {
			{
				Keys:    bson.D{{Key: "app_id", Value: 1}, {Key: "tenant_id", Value: 1}, {Key: "name", Value: 1}},
				Options: options.Index().SetUnique(true),
			},
			{Keys: bson.D{{Key: "app_id", Value: 1}, {Key: "tenant_id", Value: 1}}},
		},
		colReflexes: {
			{
				Keys:    bson.D{{Key: "app_id", Value: 1}, {Key: "tenant_id", Value: 1}, {Key: "name", Value: 1}},
				Options: options.Index().SetUnique(true),
			},
			{Keys: bson.D{{Key: "app_id", Value: 1}, {Key: "tenant_id", Value: 1}}},
		},
		colProfiles: {
			{
				Keys:    bson.D{{Key: "app_id", Value: 1}, {Key: "tenant_id", Value: 1}, {Key: "name", Value: 1}},
				Options: options.Index().SetUnique(true),
			},
			{Keys: bson.D{{Key: "app_id", Value: 1}, {Key: "tenant_id", Value: 1}}},
		},
		colScans: {
			{Keys: bson.D{{Key: "app_id", Value: 1}}},
			{Keys: bson.D{{Key: "tenant_id", Value: 1}}},
			{Keys: bson.D{{Key: "decision", Value: 1}, {Key: "created_at", Value: -1}}},
		},
		colPolicies: {
			{
				Keys:    bson.D{{Key: "scope_key", Value: 1}, {Key: "name", Value: 1}},
				Options: options.Index().SetUnique(true),
			},
			{Keys: bson.D{{Key: "scope_key", Value: 1}, {Key: "scope_level", Value: 1}}},
		},
		colPIITokens: {
			{Keys: bson.D{{Key: "scan_id", Value: 1}}},
			{Keys: bson.D{{Key: "tenant_id", Value: 1}}},
		},
		colCompliance: {
			{Keys: bson.D{{Key: "scope_key", Value: 1}, {Key: "framework", Value: 1}}},
		},
	}
}

// ──────────────────────────────────────────────────
// Instinct operations
// ──────────────────────────────────────────────────

func (s *Store) CreateInstinct(ctx context.Context, inst *instinct.Instinct) error {
	if err := claimTenant(ctx, &inst.TenantID); err != nil {
		return err
	}
	n := now()
	inst.CreatedAt = n
	inst.UpdatedAt = n
	m := instinctToModel(inst)
	_, err := s.mdb.NewInsert(m).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/mongo: create instinct: %w", err)
	}
	return nil
}

func (s *Store) GetInstinct(ctx context.Context, instID id.InstinctID) (*instinct.Instinct, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	var m instinctModel
	err := s.mdb.NewFind(&m).Filter(bson.M{"_id": instID.String(), "tenant_id": tenant}).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrInstinctNotFound, "get instinct")
	}
	return instinctFromModel(&m)
}

func (s *Store) GetInstinctByName(ctx context.Context, appID, name string) (*instinct.Instinct, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	var m instinctModel
	err := s.mdb.NewFind(&m).
		Filter(bson.M{"app_id": appID, "tenant_id": tenant, "name": name}).
		Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrInstinctNotFound, "get instinct by name")
	}
	return instinctFromModel(&m)
}

func (s *Store) UpdateInstinct(ctx context.Context, inst *instinct.Instinct) error {
	if err := claimTenant(ctx, &inst.TenantID); err != nil {
		return err
	}
	inst.UpdatedAt = now()
	m := instinctToModel(inst)
	res, err := s.mdb.NewUpdate(m).Filter(bson.M{"_id": m.ID, "tenant_id": inst.TenantID}).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/mongo: update instinct: %w", err)
	}
	if res.MatchedCount() == 0 {
		return shield.ErrInstinctNotFound
	}
	return nil
}

func (s *Store) DeleteInstinct(ctx context.Context, instID id.InstinctID) error {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return tenantErr
	}
	_, err := s.mdb.NewDelete((*instinctModel)(nil)).
		Filter(bson.M{"_id": instID.String(), "tenant_id": tenant}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/mongo: delete instinct: %w", err)
	}
	return nil
}

func (s *Store) ListInstincts(ctx context.Context, filter *instinct.ListFilter) ([]*instinct.Instinct, error) {
	var want string
	if filter != nil {
		want = filter.TenantID
	}
	tenant, tenantErr := store.Tenant(ctx, want)
	if tenantErr != nil {
		return nil, tenantErr
	}
	var models []instinctModel
	f := bson.M{"tenant_id": tenant}
	if filter != nil {
		if filter.AppID != "" {
			f["app_id"] = filter.AppID
		}
		if filter.Category != "" {
			f["category"] = string(filter.Category)
		}
		if filter.Enabled != nil {
			f["enabled"] = *filter.Enabled
		}
	}
	q := s.mdb.NewFind(&models).Filter(f).Sort(bson.D{{Key: "created_at", Value: 1}})
	if filter != nil {
		if filter.Limit > 0 {
			q = q.Limit(int64(filter.Limit))
		}
		if filter.Offset > 0 {
			q = q.Skip(int64(filter.Offset))
		}
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("shield/mongo: list instincts: %w", err)
	}
	result := make([]*instinct.Instinct, 0, len(models))
	for i := range models {
		inst, err := instinctFromModel(&models[i])
		if err != nil {
			return nil, err
		}
		result = append(result, inst)
	}
	return result, nil
}

// ──────────────────────────────────────────────────
// Awareness operations
// ──────────────────────────────────────────────────

func (s *Store) CreateAwareness(ctx context.Context, a *awareness.Awareness) error {
	if err := claimTenant(ctx, &a.TenantID); err != nil {
		return err
	}
	n := now()
	a.CreatedAt = n
	a.UpdatedAt = n
	m := awarenessToModel(a)
	_, err := s.mdb.NewInsert(m).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/mongo: create awareness: %w", err)
	}
	return nil
}

func (s *Store) GetAwareness(ctx context.Context, aID id.AwarenessID) (*awareness.Awareness, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	var m awarenessModel
	err := s.mdb.NewFind(&m).Filter(bson.M{"_id": aID.String(), "tenant_id": tenant}).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrAwarenessNotFound, "get awareness")
	}
	return awarenessFromModel(&m)
}

func (s *Store) GetAwarenessByName(ctx context.Context, appID, name string) (*awareness.Awareness, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	var m awarenessModel
	err := s.mdb.NewFind(&m).Filter(bson.M{"app_id": appID, "tenant_id": tenant, "name": name}).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrAwarenessNotFound, "get awareness by name")
	}
	return awarenessFromModel(&m)
}

func (s *Store) UpdateAwareness(ctx context.Context, a *awareness.Awareness) error {
	if err := claimTenant(ctx, &a.TenantID); err != nil {
		return err
	}
	a.UpdatedAt = now()
	m := awarenessToModel(a)
	res, err := s.mdb.NewUpdate(m).Filter(bson.M{"_id": m.ID, "tenant_id": a.TenantID}).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/mongo: update awareness: %w", err)
	}
	if res.MatchedCount() == 0 {
		return shield.ErrAwarenessNotFound
	}
	return nil
}

func (s *Store) DeleteAwareness(ctx context.Context, aID id.AwarenessID) error {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return tenantErr
	}
	_, err := s.mdb.NewDelete((*awarenessModel)(nil)).Filter(bson.M{"_id": aID.String(), "tenant_id": tenant}).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/mongo: delete awareness: %w", err)
	}
	return nil
}

func (s *Store) ListAwareness(ctx context.Context, filter *awareness.ListFilter) ([]*awareness.Awareness, error) {
	var want string
	if filter != nil {
		want = filter.TenantID
	}
	tenant, tenantErr := store.Tenant(ctx, want)
	if tenantErr != nil {
		return nil, tenantErr
	}
	var models []awarenessModel
	f := bson.M{"tenant_id": tenant}
	if filter != nil {
		if filter.AppID != "" {
			f["app_id"] = filter.AppID
		}
		if filter.Focus != "" {
			f["focus"] = string(filter.Focus)
		}
		if filter.Enabled != nil {
			f["enabled"] = *filter.Enabled
		}
	}
	q := s.mdb.NewFind(&models).Filter(f).Sort(bson.D{{Key: "created_at", Value: 1}})
	if filter != nil {
		if filter.Limit > 0 {
			q = q.Limit(int64(filter.Limit))
		}
		if filter.Offset > 0 {
			q = q.Skip(int64(filter.Offset))
		}
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("shield/mongo: list awareness: %w", err)
	}
	result := make([]*awareness.Awareness, 0, len(models))
	for i := range models {
		a, err := awarenessFromModel(&models[i])
		if err != nil {
			return nil, err
		}
		result = append(result, a)
	}
	return result, nil
}

// ──────────────────────────────────────────────────
// Boundary operations
// ──────────────────────────────────────────────────

func (s *Store) CreateBoundary(ctx context.Context, b *boundary.Boundary) error {
	if err := claimTenant(ctx, &b.TenantID); err != nil {
		return err
	}
	n := now()
	b.CreatedAt = n
	b.UpdatedAt = n
	_, err := s.mdb.NewInsert(boundaryToModel(b)).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/mongo: create boundary: %w", err)
	}
	return nil
}

func (s *Store) GetBoundary(ctx context.Context, bID id.BoundaryID) (*boundary.Boundary, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	var m boundaryModel
	err := s.mdb.NewFind(&m).Filter(bson.M{"_id": bID.String(), "tenant_id": tenant}).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrBoundaryNotFound, "get boundary")
	}
	return boundaryFromModel(&m)
}

func (s *Store) GetBoundaryByName(ctx context.Context, appID, name string) (*boundary.Boundary, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	var m boundaryModel
	err := s.mdb.NewFind(&m).Filter(bson.M{"app_id": appID, "tenant_id": tenant, "name": name}).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrBoundaryNotFound, "get boundary by name")
	}
	return boundaryFromModel(&m)
}

func (s *Store) UpdateBoundary(ctx context.Context, b *boundary.Boundary) error {
	if err := claimTenant(ctx, &b.TenantID); err != nil {
		return err
	}
	b.UpdatedAt = now()
	m := boundaryToModel(b)
	res, err := s.mdb.NewUpdate(m).Filter(bson.M{"_id": m.ID, "tenant_id": b.TenantID}).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/mongo: update boundary: %w", err)
	}
	if res.MatchedCount() == 0 {
		return shield.ErrBoundaryNotFound
	}
	return nil
}

func (s *Store) DeleteBoundary(ctx context.Context, bID id.BoundaryID) error {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return tenantErr
	}
	_, err := s.mdb.NewDelete((*boundaryModel)(nil)).Filter(bson.M{"_id": bID.String(), "tenant_id": tenant}).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/mongo: delete boundary: %w", err)
	}
	return nil
}

func (s *Store) ListBoundaries(ctx context.Context, filter *boundary.ListFilter) ([]*boundary.Boundary, error) {
	var want string
	if filter != nil {
		want = filter.TenantID
	}
	tenant, tenantErr := store.Tenant(ctx, want)
	if tenantErr != nil {
		return nil, tenantErr
	}
	var models []boundaryModel
	f := bson.M{"tenant_id": tenant}
	if filter != nil {
		if filter.AppID != "" {
			f["app_id"] = filter.AppID
		}
		if filter.Enabled != nil {
			f["enabled"] = *filter.Enabled
		}
	}
	q := s.mdb.NewFind(&models).Filter(f).Sort(bson.D{{Key: "created_at", Value: 1}})
	if filter != nil {
		if filter.Limit > 0 {
			q = q.Limit(int64(filter.Limit))
		}
		if filter.Offset > 0 {
			q = q.Skip(int64(filter.Offset))
		}
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("shield/mongo: list boundaries: %w", err)
	}
	result := make([]*boundary.Boundary, 0, len(models))
	for i := range models {
		b, err := boundaryFromModel(&models[i])
		if err != nil {
			return nil, err
		}
		result = append(result, b)
	}
	return result, nil
}

// ──────────────────────────────────────────────────
// Values operations
// ──────────────────────────────────────────────────

func (s *Store) CreateValues(ctx context.Context, v *values.Values) error {
	if err := claimTenant(ctx, &v.TenantID); err != nil {
		return err
	}
	n := now()
	v.CreatedAt = n
	v.UpdatedAt = n
	_, err := s.mdb.NewInsert(valuesToModel(v)).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/mongo: create values: %w", err)
	}
	return nil
}

func (s *Store) GetValues(ctx context.Context, vID id.ValueID) (*values.Values, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	var m valuesModel
	err := s.mdb.NewFind(&m).Filter(bson.M{"_id": vID.String(), "tenant_id": tenant}).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrValueNotFound, "get values")
	}
	return valuesFromModel(&m)
}

func (s *Store) GetValuesByName(ctx context.Context, appID, name string) (*values.Values, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	var m valuesModel
	err := s.mdb.NewFind(&m).Filter(bson.M{"app_id": appID, "tenant_id": tenant, "name": name}).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrValueNotFound, "get values by name")
	}
	return valuesFromModel(&m)
}

func (s *Store) UpdateValues(ctx context.Context, v *values.Values) error {
	if err := claimTenant(ctx, &v.TenantID); err != nil {
		return err
	}
	v.UpdatedAt = now()
	m := valuesToModel(v)
	res, err := s.mdb.NewUpdate(m).Filter(bson.M{"_id": m.ID, "tenant_id": v.TenantID}).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/mongo: update values: %w", err)
	}
	if res.MatchedCount() == 0 {
		return shield.ErrValueNotFound
	}
	return nil
}

func (s *Store) DeleteValues(ctx context.Context, vID id.ValueID) error {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return tenantErr
	}
	_, err := s.mdb.NewDelete((*valuesModel)(nil)).Filter(bson.M{"_id": vID.String(), "tenant_id": tenant}).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/mongo: delete values: %w", err)
	}
	return nil
}

func (s *Store) ListValues(ctx context.Context, filter *values.ListFilter) ([]*values.Values, error) {
	var want string
	if filter != nil {
		want = filter.TenantID
	}
	tenant, tenantErr := store.Tenant(ctx, want)
	if tenantErr != nil {
		return nil, tenantErr
	}
	var models []valuesModel
	f := bson.M{"tenant_id": tenant}
	if filter != nil {
		if filter.AppID != "" {
			f["app_id"] = filter.AppID
		}
		if filter.Enabled != nil {
			f["enabled"] = *filter.Enabled
		}
	}
	q := s.mdb.NewFind(&models).Filter(f).Sort(bson.D{{Key: "created_at", Value: 1}})
	if filter != nil {
		if filter.Limit > 0 {
			q = q.Limit(int64(filter.Limit))
		}
		if filter.Offset > 0 {
			q = q.Skip(int64(filter.Offset))
		}
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("shield/mongo: list values: %w", err)
	}
	result := make([]*values.Values, 0, len(models))
	for i := range models {
		v, err := valuesFromModel(&models[i])
		if err != nil {
			return nil, err
		}
		result = append(result, v)
	}
	return result, nil
}

// ──────────────────────────────────────────────────
// Judgment operations
// ──────────────────────────────────────────────────

func (s *Store) CreateJudgment(ctx context.Context, j *judgment.Judgment) error {
	if err := claimTenant(ctx, &j.TenantID); err != nil {
		return err
	}
	n := now()
	j.CreatedAt = n
	j.UpdatedAt = n
	_, err := s.mdb.NewInsert(judgmentToModel(j)).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/mongo: create judgment: %w", err)
	}
	return nil
}

func (s *Store) GetJudgment(ctx context.Context, jID id.JudgmentID) (*judgment.Judgment, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	var m judgmentModel
	err := s.mdb.NewFind(&m).Filter(bson.M{"_id": jID.String(), "tenant_id": tenant}).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrJudgmentNotFound, "get judgment")
	}
	return judgmentFromModel(&m)
}

func (s *Store) GetJudgmentByName(ctx context.Context, appID, name string) (*judgment.Judgment, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	var m judgmentModel
	err := s.mdb.NewFind(&m).Filter(bson.M{"app_id": appID, "tenant_id": tenant, "name": name}).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrJudgmentNotFound, "get judgment by name")
	}
	return judgmentFromModel(&m)
}

func (s *Store) UpdateJudgment(ctx context.Context, j *judgment.Judgment) error {
	if err := claimTenant(ctx, &j.TenantID); err != nil {
		return err
	}
	j.UpdatedAt = now()
	m := judgmentToModel(j)
	res, err := s.mdb.NewUpdate(m).Filter(bson.M{"_id": m.ID, "tenant_id": j.TenantID}).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/mongo: update judgment: %w", err)
	}
	if res.MatchedCount() == 0 {
		return shield.ErrJudgmentNotFound
	}
	return nil
}

func (s *Store) DeleteJudgment(ctx context.Context, jID id.JudgmentID) error {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return tenantErr
	}
	_, err := s.mdb.NewDelete((*judgmentModel)(nil)).Filter(bson.M{"_id": jID.String(), "tenant_id": tenant}).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/mongo: delete judgment: %w", err)
	}
	return nil
}

func (s *Store) ListJudgments(ctx context.Context, filter *judgment.ListFilter) ([]*judgment.Judgment, error) {
	var want string
	if filter != nil {
		want = filter.TenantID
	}
	tenant, tenantErr := store.Tenant(ctx, want)
	if tenantErr != nil {
		return nil, tenantErr
	}
	var models []judgmentModel
	f := bson.M{"tenant_id": tenant}
	if filter != nil {
		if filter.AppID != "" {
			f["app_id"] = filter.AppID
		}
		if filter.Domain != "" {
			f["domain"] = string(filter.Domain)
		}
		if filter.Enabled != nil {
			f["enabled"] = *filter.Enabled
		}
	}
	q := s.mdb.NewFind(&models).Filter(f).Sort(bson.D{{Key: "created_at", Value: 1}})
	if filter != nil {
		if filter.Limit > 0 {
			q = q.Limit(int64(filter.Limit))
		}
		if filter.Offset > 0 {
			q = q.Skip(int64(filter.Offset))
		}
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("shield/mongo: list judgments: %w", err)
	}
	result := make([]*judgment.Judgment, 0, len(models))
	for i := range models {
		j, err := judgmentFromModel(&models[i])
		if err != nil {
			return nil, err
		}
		result = append(result, j)
	}
	return result, nil
}

// ──────────────────────────────────────────────────
// Reflex operations
// ──────────────────────────────────────────────────

func (s *Store) CreateReflex(ctx context.Context, r *reflex.Reflex) error {
	if err := claimTenant(ctx, &r.TenantID); err != nil {
		return err
	}
	n := now()
	r.CreatedAt = n
	r.UpdatedAt = n
	_, err := s.mdb.NewInsert(reflexToModel(r)).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/mongo: create reflex: %w", err)
	}
	return nil
}

func (s *Store) GetReflex(ctx context.Context, rID id.ReflexID) (*reflex.Reflex, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	var m reflexModel
	err := s.mdb.NewFind(&m).Filter(bson.M{"_id": rID.String(), "tenant_id": tenant}).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrReflexNotFound, "get reflex")
	}
	return reflexFromModel(&m)
}

func (s *Store) GetReflexByName(ctx context.Context, appID, name string) (*reflex.Reflex, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	var m reflexModel
	err := s.mdb.NewFind(&m).Filter(bson.M{"app_id": appID, "tenant_id": tenant, "name": name}).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrReflexNotFound, "get reflex by name")
	}
	return reflexFromModel(&m)
}

func (s *Store) UpdateReflex(ctx context.Context, r *reflex.Reflex) error {
	if err := claimTenant(ctx, &r.TenantID); err != nil {
		return err
	}
	r.UpdatedAt = now()
	m := reflexToModel(r)
	res, err := s.mdb.NewUpdate(m).Filter(bson.M{"_id": m.ID, "tenant_id": r.TenantID}).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/mongo: update reflex: %w", err)
	}
	if res.MatchedCount() == 0 {
		return shield.ErrReflexNotFound
	}
	return nil
}

func (s *Store) DeleteReflex(ctx context.Context, rID id.ReflexID) error {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return tenantErr
	}
	_, err := s.mdb.NewDelete((*reflexModel)(nil)).Filter(bson.M{"_id": rID.String(), "tenant_id": tenant}).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/mongo: delete reflex: %w", err)
	}
	return nil
}

func (s *Store) ListReflexes(ctx context.Context, filter *reflex.ListFilter) ([]*reflex.Reflex, error) {
	var want string
	if filter != nil {
		want = filter.TenantID
	}
	tenant, tenantErr := store.Tenant(ctx, want)
	if tenantErr != nil {
		return nil, tenantErr
	}
	var models []reflexModel
	f := bson.M{"tenant_id": tenant}
	if filter != nil {
		if filter.AppID != "" {
			f["app_id"] = filter.AppID
		}
		if filter.Enabled != nil {
			f["enabled"] = *filter.Enabled
		}
	}
	q := s.mdb.NewFind(&models).Filter(f).Sort(bson.D{{Key: "created_at", Value: 1}})
	if filter != nil {
		if filter.Limit > 0 {
			q = q.Limit(int64(filter.Limit))
		}
		if filter.Offset > 0 {
			q = q.Skip(int64(filter.Offset))
		}
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("shield/mongo: list reflexes: %w", err)
	}
	result := make([]*reflex.Reflex, 0, len(models))
	for i := range models {
		r, err := reflexFromModel(&models[i])
		if err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}

// ──────────────────────────────────────────────────
// Profile operations
// ──────────────────────────────────────────────────

func (s *Store) CreateProfile(ctx context.Context, p *profile.SafetyProfile) error {
	if err := claimTenant(ctx, &p.TenantID); err != nil {
		return err
	}
	n := now()
	p.CreatedAt = n
	p.UpdatedAt = n
	_, err := s.mdb.NewInsert(profileToModel(p)).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/mongo: create profile: %w", err)
	}
	return nil
}

func (s *Store) GetProfile(ctx context.Context, pID id.SafetyProfileID) (*profile.SafetyProfile, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	var m profileModel
	err := s.mdb.NewFind(&m).Filter(bson.M{"_id": pID.String(), "tenant_id": tenant}).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrProfileNotFound, "get profile")
	}
	return profileFromModel(&m)
}

func (s *Store) GetProfileByName(ctx context.Context, appID, name string) (*profile.SafetyProfile, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	var m profileModel
	err := s.mdb.NewFind(&m).Filter(bson.M{"app_id": appID, "tenant_id": tenant, "name": name}).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrProfileNotFound, "get profile by name")
	}
	return profileFromModel(&m)
}

func (s *Store) UpdateProfile(ctx context.Context, p *profile.SafetyProfile) error {
	if err := claimTenant(ctx, &p.TenantID); err != nil {
		return err
	}
	p.UpdatedAt = now()
	m := profileToModel(p)
	res, err := s.mdb.NewUpdate(m).Filter(bson.M{"_id": m.ID, "tenant_id": p.TenantID}).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/mongo: update profile: %w", err)
	}
	if res.MatchedCount() == 0 {
		return shield.ErrProfileNotFound
	}
	return nil
}

func (s *Store) DeleteProfile(ctx context.Context, pID id.SafetyProfileID) error {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return tenantErr
	}
	_, err := s.mdb.NewDelete((*profileModel)(nil)).Filter(bson.M{"_id": pID.String(), "tenant_id": tenant}).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/mongo: delete profile: %w", err)
	}
	return nil
}

func (s *Store) ListProfiles(ctx context.Context, filter *profile.ListFilter) ([]*profile.SafetyProfile, error) {
	var want string
	if filter != nil {
		want = filter.TenantID
	}
	tenant, tenantErr := store.Tenant(ctx, want)
	if tenantErr != nil {
		return nil, tenantErr
	}
	var models []profileModel
	f := bson.M{"tenant_id": tenant}
	if filter != nil {
		if filter.AppID != "" {
			f["app_id"] = filter.AppID
		}
		if filter.Enabled != nil {
			f["enabled"] = *filter.Enabled
		}
	}
	q := s.mdb.NewFind(&models).Filter(f).Sort(bson.D{{Key: "created_at", Value: 1}})
	if filter != nil {
		if filter.Limit > 0 {
			q = q.Limit(int64(filter.Limit))
		}
		if filter.Offset > 0 {
			q = q.Skip(int64(filter.Offset))
		}
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("shield/mongo: list profiles: %w", err)
	}
	result := make([]*profile.SafetyProfile, 0, len(models))
	for i := range models {
		p, err := profileFromModel(&models[i])
		if err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	return result, nil
}

// ──────────────────────────────────────────────────
// Scan operations
// ──────────────────────────────────────────────────

func (s *Store) CreateScan(ctx context.Context, result *scan.Result) error {
	if err := claimTenant(ctx, &result.TenantID); err != nil {
		return err
	}
	n := now()
	result.CreatedAt = n
	result.UpdatedAt = n
	_, err := s.mdb.NewInsert(scanToModel(result)).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/mongo: create scan: %w", err)
	}
	return nil
}

func (s *Store) GetScan(ctx context.Context, scanID id.ScanID) (*scan.Result, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	var m scanResultModel
	err := s.mdb.NewFind(&m).Filter(bson.M{"_id": scanID.String(), "tenant_id": tenant}).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrScanNotFound, "get scan")
	}
	return scanFromModel(&m)
}

func (s *Store) ListScans(ctx context.Context, filter *scan.ListFilter) ([]*scan.Result, error) {
	var want string
	if filter != nil {
		want = filter.TenantID
	}
	tenant, tenantErr := store.Tenant(ctx, want)
	if tenantErr != nil {
		return nil, tenantErr
	}
	var models []scanResultModel
	f := bson.M{"tenant_id": tenant}
	if filter != nil {
		if filter.AppID != "" {
			f["app_id"] = filter.AppID
		}
		if filter.Direction != "" {
			f["direction"] = string(filter.Direction)
		}
		if filter.Decision != "" {
			f["decision"] = string(filter.Decision)
		}
	}
	q := s.mdb.NewFind(&models).Filter(f).Sort(bson.D{{Key: "created_at", Value: -1}})
	if filter != nil {
		if filter.Limit > 0 {
			q = q.Limit(int64(filter.Limit))
		}
		if filter.Offset > 0 {
			q = q.Skip(int64(filter.Offset))
		}
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("shield/mongo: list scans: %w", err)
	}
	result := make([]*scan.Result, 0, len(models))
	for i := range models {
		r, err := scanFromModel(&models[i])
		if err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}

func (s *Store) ScanStats(ctx context.Context, filter *scan.StatsFilter) (*scan.Stats, error) {
	var want string
	if filter != nil {
		want = filter.TenantID
	}
	tenant, tenantErr := store.Tenant(ctx, want)
	if tenantErr != nil {
		return nil, tenantErr
	}
	// Fetch all matching scans and aggregate in-memory for simplicity.
	var models []scanResultModel
	f := bson.M{"tenant_id": tenant}
	if filter != nil {
		if filter.AppID != "" {
			f["app_id"] = filter.AppID
		}
	}
	if err := s.mdb.NewFind(&models).Filter(f).Scan(ctx); err != nil {
		if isNoDocuments(err) {
			return emptyScanStats(), nil
		}
		return nil, fmt.Errorf("shield/mongo: scan stats: %w", err)
	}

	stats := emptyScanStats()
	for i := range models {
		stats.TotalScans++
		stats.ByDirection[models[i].Direction]++
		stats.ByDecision[models[i].Decision]++

		switch scan.Decision(models[i].Decision) {
		case scan.DecisionBlock:
			stats.BlockedCount++
		case scan.DecisionFlag:
			stats.FlaggedCount++
		case scan.DecisionAllow:
			stats.AllowedCount++
		}
	}
	return stats, nil
}

func emptyScanStats() *scan.Stats {
	return &scan.Stats{
		ByDirection: make(map[string]int64),
		ByDecision:  make(map[string]int64),
	}
}

// ──────────────────────────────────────────────────
// Policy operations
// ──────────────────────────────────────────────────

func (s *Store) CreatePolicy(ctx context.Context, pol *policy.Policy) error {
	if _, err := store.ScopeLevels(ctx, pol.ScopeKey, string(pol.ScopeLevel)); err != nil {
		return err
	}
	n := now()
	pol.CreatedAt = n
	pol.UpdatedAt = n
	_, err := s.mdb.NewInsert(policyToModel(pol)).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/mongo: create policy: %w", err)
	}
	return nil
}

func (s *Store) GetPolicy(ctx context.Context, polID id.PolicyID) (*policy.Policy, error) {
	m, err := s.visiblePolicy(ctx, polID)
	if err != nil {
		return nil, err
	}
	return policyFromModel(m)
}

// visiblePolicy loads a policy the context may see. A missing policy and one
// in a scope the context cannot see both return ErrPolicyNotFound.
func (s *Store) visiblePolicy(ctx context.Context, polID id.PolicyID) (*policyModel, error) {
	var m policyModel
	err := s.mdb.NewFind(&m).Filter(bson.M{"_id": polID.String()}).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrPolicyNotFound, "get policy")
	}
	if !store.ScopeVisible(ctx, m.ScopeKey, m.ScopeLevel) {
		return nil, shield.ErrPolicyNotFound
	}
	return &m, nil
}

// scopeFilter matches scope_key and, when levels is set, one of those levels.
func scopeFilter(key string, levels []string) bson.M {
	f := bson.M{"scope_key": key}
	if levels != nil {
		f["scope_level"] = bson.M{"$in": levels}
	}
	return f
}

func (s *Store) GetPolicyByName(ctx context.Context, scopeKey, name string) (*policy.Policy, error) {
	levels, levelErr := store.ScopeLevels(ctx, scopeKey, "")
	if levelErr != nil {
		return nil, levelErr
	}
	f := scopeFilter(scopeKey, levels)
	f["name"] = name
	var m policyModel
	err := s.mdb.NewFind(&m).Filter(f).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrPolicyNotFound, "get policy by name")
	}
	return policyFromModel(&m)
}

func (s *Store) UpdatePolicy(ctx context.Context, pol *policy.Policy) error {
	current, err := s.visiblePolicy(ctx, pol.ID)
	if err != nil {
		return err
	}
	if !store.ScopeVisible(ctx, pol.ScopeKey, string(pol.ScopeLevel)) {
		return shield.ErrTenantMismatch
	}
	pol.UpdatedAt = now()
	m := policyToModel(pol)
	res, err := s.mdb.NewUpdate(m).
		Filter(bson.M{"_id": m.ID, "scope_key": current.ScopeKey, "scope_level": current.ScopeLevel}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/mongo: update policy: %w", err)
	}
	if res.MatchedCount() == 0 {
		return shield.ErrPolicyNotFound
	}
	return nil
}

// DeletePolicy is idempotent: a missing policy and one the context cannot see
// both return nil, and the second is left in place.
func (s *Store) DeletePolicy(ctx context.Context, polID id.PolicyID) error {
	current, err := s.visiblePolicy(ctx, polID)
	if errors.Is(err, shield.ErrPolicyNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = s.mdb.NewDelete((*policyModel)(nil)).
		Filter(bson.M{"_id": polID.String(), "scope_key": current.ScopeKey, "scope_level": current.ScopeLevel}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/mongo: delete policy: %w", err)
	}
	return nil
}

func (s *Store) ListPolicies(ctx context.Context, filter *policy.ListFilter) ([]*policy.Policy, error) {
	if filter == nil {
		return nil, shield.ErrTenantRequired
	}
	levels, levelErr := store.ScopeLevels(ctx, filter.ScopeKey, string(filter.ScopeLevel))
	if levelErr != nil {
		return nil, levelErr
	}
	var models []policyModel
	f := scopeFilter(filter.ScopeKey, levels)
	if filter.ScopeLevel != "" {
		f["scope_level"] = string(filter.ScopeLevel)
	}
	if filter.Enabled != nil {
		f["enabled"] = *filter.Enabled
	}
	q := s.mdb.NewFind(&models).Filter(f).Sort(bson.D{{Key: "created_at", Value: 1}})
	if filter.Limit > 0 {
		q = q.Limit(int64(filter.Limit))
	}
	if filter.Offset > 0 {
		q = q.Skip(int64(filter.Offset))
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("shield/mongo: list policies: %w", err)
	}
	result := make([]*policy.Policy, 0, len(models))
	for i := range models {
		p, err := policyFromModel(&models[i])
		if err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	return result, nil
}

func (s *Store) GetPoliciesForScope(ctx context.Context, scopeKey string, level policy.ScopeLevel) ([]*policy.Policy, error) {
	if _, err := store.ScopeLevels(ctx, scopeKey, string(level)); err != nil {
		return nil, err
	}
	var models []policyModel
	f := bson.M{
		"scope_key":   scopeKey,
		"scope_level": string(level),
		"enabled":     true,
	}
	err := s.mdb.NewFind(&models).Filter(f).Sort(bson.D{{Key: "created_at", Value: 1}}).Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("shield/mongo: get policies for scope: %w", err)
	}
	result := make([]*policy.Policy, 0, len(models))
	for i := range models {
		p, err := policyFromModel(&models[i])
		if err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	return result, nil
}

func (s *Store) AssignToTenant(ctx context.Context, tenantID string, polID id.PolicyID) error {
	tenant, err := store.Tenant(ctx, tenantID)
	if err != nil {
		return err
	}
	// Use $addToSet to add the tenant to the policy document's tenant_ids array.
	_, err = s.mdb.Collection(colPolicies).UpdateOne(ctx,
		bson.M{"_id": polID.String()},
		bson.M{"$addToSet": bson.M{"tenant_ids": tenant}},
	)
	if err != nil {
		return fmt.Errorf("shield/mongo: assign policy to tenant: %w", err)
	}
	return nil
}

func (s *Store) UnassignFromTenant(ctx context.Context, tenantID string, polID id.PolicyID) error {
	tenant, err := store.Tenant(ctx, tenantID)
	if err != nil {
		return err
	}
	// Use $pull to remove the tenant from the policy document's tenant_ids array.
	_, err = s.mdb.Collection(colPolicies).UpdateOne(ctx,
		bson.M{"_id": polID.String()},
		bson.M{"$pull": bson.M{"tenant_ids": tenant}},
	)
	if err != nil {
		return fmt.Errorf("shield/mongo: unassign policy from tenant: %w", err)
	}
	return nil
}

// ──────────────────────────────────────────────────
// PII operations
// ──────────────────────────────────────────────────

func (s *Store) StorePIITokens(ctx context.Context, tokens []*pii.Token) error {
	if len(tokens) == 0 {
		return nil
	}
	n := now()
	models := make([]piiTokenModel, len(tokens))
	for i, t := range tokens {
		if err := claimTenant(ctx, &t.TenantID); err != nil {
			return err
		}
		t.CreatedAt = n
		t.UpdatedAt = n
		models[i] = *piiTokenToModel(t)
	}
	_, err := s.mdb.NewInsert(&models).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/mongo: store pii tokens: %w", err)
	}
	return nil
}

func (s *Store) LoadPIITokens(ctx context.Context, tokenIDs []id.PIITokenID) ([]*pii.Token, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	if len(tokenIDs) == 0 {
		return nil, nil
	}
	ids := make([]string, len(tokenIDs))
	for i, tid := range tokenIDs {
		ids[i] = tid.String()
	}
	var models []piiTokenModel
	err := s.mdb.NewFind(&models).Filter(bson.M{"_id": bson.M{"$in": ids}, "tenant_id": tenant}).Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("shield/mongo: load pii tokens: %w", err)
	}
	result := make([]*pii.Token, 0, len(models))
	for i := range models {
		t, err := piiTokenFromModel(&models[i])
		if err != nil {
			return nil, err
		}
		result = append(result, t)
	}
	return result, nil
}

func (s *Store) LoadPIITokensByScan(ctx context.Context, scanID id.ScanID) ([]*pii.Token, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	var models []piiTokenModel
	err := s.mdb.NewFind(&models).
		Filter(bson.M{"scan_id": scanID.String(), "tenant_id": tenant}).
		Sort(bson.D{{Key: "created_at", Value: 1}}).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("shield/mongo: load pii tokens by scan: %w", err)
	}
	result := make([]*pii.Token, 0, len(models))
	for i := range models {
		t, err := piiTokenFromModel(&models[i])
		if err != nil {
			return nil, err
		}
		result = append(result, t)
	}
	return result, nil
}

func (s *Store) DeletePIITokens(ctx context.Context, tokenIDs []id.PIITokenID) error {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return tenantErr
	}
	if len(tokenIDs) == 0 {
		return nil
	}
	ids := make([]string, len(tokenIDs))
	for i, tid := range tokenIDs {
		ids[i] = tid.String()
	}
	_, err := s.mdb.Collection(colPIITokens).DeleteMany(ctx, bson.M{"_id": bson.M{"$in": ids}, "tenant_id": tenant})
	if err != nil {
		return fmt.Errorf("shield/mongo: delete pii tokens: %w", err)
	}
	return nil
}

func (s *Store) DeletePIITokensByTenant(ctx context.Context, tenantID string) error {
	tenant, err := store.Tenant(ctx, tenantID)
	if err != nil {
		return err
	}
	_, err = s.mdb.Collection(colPIITokens).DeleteMany(ctx, bson.M{"tenant_id": tenant})
	if err != nil {
		return fmt.Errorf("shield/mongo: delete pii tokens by tenant: %w", err)
	}
	return nil
}

// PurgePIITokens is an operator retention sweep: it removes expired tokens in
// every tenant and so takes no tenant.
func (s *Store) PurgePIITokens(ctx context.Context, olderThan time.Time) (int64, error) {
	res, err := s.mdb.Collection(colPIITokens).DeleteMany(ctx, bson.M{
		"expires_at": bson.M{"$ne": nil, "$lt": olderThan},
	})
	if err != nil {
		return 0, fmt.Errorf("shield/mongo: purge pii tokens: %w", err)
	}
	return res.DeletedCount, nil
}

func (s *Store) PIIStats(ctx context.Context, tenantID string) (*pii.Stats, error) {
	tenant, tenantErr := store.Tenant(ctx, tenantID)
	if tenantErr != nil {
		return nil, tenantErr
	}
	var models []piiTokenModel
	if err := s.mdb.NewFind(&models).Filter(bson.M{"tenant_id": tenant}).Scan(ctx); err != nil {
		if isNoDocuments(err) {
			return &pii.Stats{
				ByType:   make(map[string]int64),
				ByTenant: make(map[string]int64),
			}, nil
		}
		return nil, fmt.Errorf("shield/mongo: pii stats: %w", err)
	}

	stats := &pii.Stats{
		TotalTokens: int64(len(models)),
		ByType:      make(map[string]int64),
		ByTenant:    make(map[string]int64),
	}
	for i := range models {
		stats.ByType[models[i].PIIType]++
		stats.ByTenant[models[i].TenantID]++
	}
	return stats, nil
}

// ──────────────────────────────────────────────────
// Compliance operations
// ──────────────────────────────────────────────────

func (s *Store) CreateReport(ctx context.Context, report *compliance.Report) error {
	if _, err := store.ScopeLevels(ctx, report.ScopeKey, report.ScopeLevel); err != nil {
		return err
	}
	n := now()
	report.CreatedAt = n
	report.UpdatedAt = n
	_, err := s.mdb.NewInsert(complianceToModel(report)).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/mongo: create compliance report: %w", err)
	}
	return nil
}

func (s *Store) GetReport(ctx context.Context, reportID id.ComplianceReportID) (*compliance.Report, error) {
	var m complianceReportModel
	err := s.mdb.NewFind(&m).Filter(bson.M{"_id": reportID.String()}).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrComplianceNotFound, "get compliance report")
	}
	if !store.ScopeVisible(ctx, m.ScopeKey, m.ScopeLevel) {
		return nil, shield.ErrComplianceNotFound
	}
	return complianceFromModel(&m)
}

func (s *Store) ListReports(ctx context.Context, filter *compliance.ListFilter) ([]*compliance.Report, error) {
	if filter == nil {
		return nil, shield.ErrTenantRequired
	}
	levels, levelErr := store.ScopeLevels(ctx, filter.ScopeKey, "")
	if levelErr != nil {
		return nil, levelErr
	}
	var models []complianceReportModel
	f := scopeFilter(filter.ScopeKey, levels)
	if filter.Framework != "" {
		f["framework"] = string(filter.Framework)
	}
	q := s.mdb.NewFind(&models).Filter(f).Sort(bson.D{{Key: "generated_at", Value: -1}})
	if filter.Limit > 0 {
		q = q.Limit(int64(filter.Limit))
	}
	if filter.Offset > 0 {
		q = q.Skip(int64(filter.Offset))
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("shield/mongo: list compliance reports: %w", err)
	}
	result := make([]*compliance.Report, 0, len(models))
	for i := range models {
		r, err := complianceFromModel(&models[i])
		if err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}
