package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/sqlitedriver"
	_ "github.com/xraph/grove/drivers/sqlitedriver/sqlitemigrate" // Register SQLite migration support.
	"github.com/xraph/grove/migrate"

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

// Compile-time interface check.
var _ store.Store = (*Store)(nil)

// Store implements store.Store using SQLite via Grove ORM.
type Store struct {
	db  *grove.DB
	sdb *sqlitedriver.SqliteDB
}

// New creates a new SQLite store backed by Grove ORM.
func New(db *grove.DB) *Store {
	return &Store{
		db:  db,
		sdb: sqlitedriver.Unwrap(db),
	}
}

// Migrate creates the required tables and indexes using the grove orchestrator.
func (s *Store) Migrate(ctx context.Context) error {
	executor, err := migrate.NewExecutorFor(s.sdb)
	if err != nil {
		return fmt.Errorf("shield/sqlite: create migration executor: %w", err)
	}
	orch := migrate.NewOrchestrator(executor, Migrations)
	if _, err := orch.Migrate(ctx); err != nil {
		return fmt.Errorf("shield/sqlite: migration failed: %w", err)
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

// isNoRows checks for the standard sql.ErrNoRows sentinel.
func isNoRows(err error) bool {
	return errors.Is(err, sql.ErrNoRows)
}

// notFoundOrWrap returns the appropriate not-found sentinel or wraps the error.
func notFoundOrWrap(err, sentinel error, msg string) error {
	if isNoRows(err) {
		return sentinel
	}
	return fmt.Errorf("shield/sqlite: %s: %w", msg, err)
}

// whereIn builds a "column IN (?, ...)" clause. The grove drivers bind a slice
// to one placeholder as a single value, so each element gets its own.
func whereIn(column string, items []string) (clause string, args []any) {
	marks := make([]string, len(items))
	args = make([]any, len(items))
	for i, v := range items {
		marks[i] = "?"
		args[i] = v
	}
	return column + " IN (" + strings.Join(marks, ", ") + ")", args
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

// updatedOrNotFound returns sentinel when an update matched no row: the ID is
// missing or belongs to another tenant, and the caller cannot tell which.
func updatedOrNotFound(res interface{ RowsAffected() (int64, error) }, sentinel error, msg string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("shield/sqlite: %s rows affected: %w", msg, err)
	}
	if n == 0 {
		return sentinel
	}
	return nil
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
	m, err := instinctToModel(inst)
	if err != nil {
		return fmt.Errorf("shield/sqlite: create instinct: %w", err)
	}
	_, err = s.sdb.NewInsert(m).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: create instinct: %w", err)
	}
	return nil
}

func (s *Store) GetInstinct(ctx context.Context, instID id.InstinctID) (*instinct.Instinct, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	m := new(instinctModel)
	err := s.sdb.NewSelect(m).Where("id = ?", instID.String()).Where("tenant_id = ?", tenant).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrInstinctNotFound, "get instinct")
	}
	return instinctFromModel(m)
}

func (s *Store) GetInstinctByName(ctx context.Context, appID, name string) (*instinct.Instinct, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	m := new(instinctModel)
	err := s.sdb.NewSelect(m).
		Where("app_id = ?", appID).
		Where("tenant_id = ?", tenant).
		Where("name = ?", name).
		Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrInstinctNotFound, "get instinct by name")
	}
	return instinctFromModel(m)
}

func (s *Store) UpdateInstinct(ctx context.Context, inst *instinct.Instinct) error {
	if err := claimTenant(ctx, &inst.TenantID); err != nil {
		return err
	}
	inst.UpdatedAt = now()
	m, err := instinctToModel(inst)
	if err != nil {
		return fmt.Errorf("shield/sqlite: update instinct: %w", err)
	}
	res, err := s.sdb.NewUpdate(m).WherePK().Where("tenant_id = ?", inst.TenantID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: update instinct: %w", err)
	}
	return updatedOrNotFound(res, shield.ErrInstinctNotFound, "update instinct")
}

func (s *Store) DeleteInstinct(ctx context.Context, instID id.InstinctID) error {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return tenantErr
	}
	_, err := s.sdb.NewDelete((*instinctModel)(nil)).Where("id = ?", instID.String()).Where("tenant_id = ?", tenant).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: delete instinct: %w", err)
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
	q := s.sdb.NewSelect(&models).Where("tenant_id = ?", tenant).OrderExpr("created_at ASC")
	if filter != nil {
		if filter.AppID != "" {
			q = q.Where("app_id = ?", filter.AppID)
		}
		if filter.Category != "" {
			q = q.Where("category = ?", string(filter.Category))
		}
		if filter.Enabled != nil {
			q = q.Where("enabled = ?", *filter.Enabled)
		}
		if filter.Limit > 0 {
			q = q.Limit(filter.Limit)
		}
		if filter.Offset > 0 {
			q = q.Offset(filter.Offset)
		}
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("shield/sqlite: list instincts: %w", err)
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
	m, err := awarenessToModel(a)
	if err != nil {
		return fmt.Errorf("shield/sqlite: create awareness: %w", err)
	}
	_, err = s.sdb.NewInsert(m).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: create awareness: %w", err)
	}
	return nil
}

func (s *Store) GetAwareness(ctx context.Context, aID id.AwarenessID) (*awareness.Awareness, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	m := new(awarenessModel)
	err := s.sdb.NewSelect(m).Where("id = ?", aID.String()).Where("tenant_id = ?", tenant).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrAwarenessNotFound, "get awareness")
	}
	return awarenessFromModel(m)
}

func (s *Store) GetAwarenessByName(ctx context.Context, appID, name string) (*awareness.Awareness, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	m := new(awarenessModel)
	err := s.sdb.NewSelect(m).
		Where("app_id = ?", appID).
		Where("tenant_id = ?", tenant).
		Where("name = ?", name).
		Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrAwarenessNotFound, "get awareness by name")
	}
	return awarenessFromModel(m)
}

func (s *Store) UpdateAwareness(ctx context.Context, a *awareness.Awareness) error {
	if err := claimTenant(ctx, &a.TenantID); err != nil {
		return err
	}
	a.UpdatedAt = now()
	m, err := awarenessToModel(a)
	if err != nil {
		return fmt.Errorf("shield/sqlite: update awareness: %w", err)
	}
	res, err := s.sdb.NewUpdate(m).WherePK().Where("tenant_id = ?", a.TenantID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: update awareness: %w", err)
	}
	return updatedOrNotFound(res, shield.ErrAwarenessNotFound, "update awareness")
}

func (s *Store) DeleteAwareness(ctx context.Context, aID id.AwarenessID) error {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return tenantErr
	}
	_, err := s.sdb.NewDelete((*awarenessModel)(nil)).Where("id = ?", aID.String()).Where("tenant_id = ?", tenant).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: delete awareness: %w", err)
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
	q := s.sdb.NewSelect(&models).Where("tenant_id = ?", tenant).OrderExpr("created_at ASC")
	if filter != nil {
		if filter.AppID != "" {
			q = q.Where("app_id = ?", filter.AppID)
		}
		if filter.Focus != "" {
			q = q.Where("focus = ?", string(filter.Focus))
		}
		if filter.Enabled != nil {
			q = q.Where("enabled = ?", *filter.Enabled)
		}
		if filter.Limit > 0 {
			q = q.Limit(filter.Limit)
		}
		if filter.Offset > 0 {
			q = q.Offset(filter.Offset)
		}
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("shield/sqlite: list awareness: %w", err)
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
	m, err := boundaryToModel(b)
	if err != nil {
		return fmt.Errorf("shield/sqlite: create boundary: %w", err)
	}
	_, err = s.sdb.NewInsert(m).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: create boundary: %w", err)
	}
	return nil
}

func (s *Store) GetBoundary(ctx context.Context, bID id.BoundaryID) (*boundary.Boundary, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	m := new(boundaryModel)
	err := s.sdb.NewSelect(m).Where("id = ?", bID.String()).Where("tenant_id = ?", tenant).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrBoundaryNotFound, "get boundary")
	}
	return boundaryFromModel(m)
}

func (s *Store) GetBoundaryByName(ctx context.Context, appID, name string) (*boundary.Boundary, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	m := new(boundaryModel)
	err := s.sdb.NewSelect(m).
		Where("app_id = ?", appID).
		Where("tenant_id = ?", tenant).
		Where("name = ?", name).
		Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrBoundaryNotFound, "get boundary by name")
	}
	return boundaryFromModel(m)
}

func (s *Store) UpdateBoundary(ctx context.Context, b *boundary.Boundary) error {
	if err := claimTenant(ctx, &b.TenantID); err != nil {
		return err
	}
	b.UpdatedAt = now()
	m, err := boundaryToModel(b)
	if err != nil {
		return fmt.Errorf("shield/sqlite: update boundary: %w", err)
	}
	res, err := s.sdb.NewUpdate(m).WherePK().Where("tenant_id = ?", b.TenantID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: update boundary: %w", err)
	}
	return updatedOrNotFound(res, shield.ErrBoundaryNotFound, "update boundary")
}

func (s *Store) DeleteBoundary(ctx context.Context, bID id.BoundaryID) error {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return tenantErr
	}
	_, err := s.sdb.NewDelete((*boundaryModel)(nil)).Where("id = ?", bID.String()).Where("tenant_id = ?", tenant).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: delete boundary: %w", err)
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
	q := s.sdb.NewSelect(&models).Where("tenant_id = ?", tenant).OrderExpr("created_at ASC")
	if filter != nil {
		if filter.AppID != "" {
			q = q.Where("app_id = ?", filter.AppID)
		}
		if filter.Enabled != nil {
			q = q.Where("enabled = ?", *filter.Enabled)
		}
		if filter.Limit > 0 {
			q = q.Limit(filter.Limit)
		}
		if filter.Offset > 0 {
			q = q.Offset(filter.Offset)
		}
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("shield/sqlite: list boundaries: %w", err)
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
	m, err := valuesToModel(v)
	if err != nil {
		return fmt.Errorf("shield/sqlite: create values: %w", err)
	}
	_, err = s.sdb.NewInsert(m).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: create values: %w", err)
	}
	return nil
}

func (s *Store) GetValues(ctx context.Context, vID id.ValueID) (*values.Values, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	m := new(valuesModel)
	err := s.sdb.NewSelect(m).Where("id = ?", vID.String()).Where("tenant_id = ?", tenant).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrValueNotFound, "get values")
	}
	return valuesFromModel(m)
}

func (s *Store) GetValuesByName(ctx context.Context, appID, name string) (*values.Values, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	m := new(valuesModel)
	err := s.sdb.NewSelect(m).
		Where("app_id = ?", appID).
		Where("tenant_id = ?", tenant).
		Where("name = ?", name).
		Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrValueNotFound, "get values by name")
	}
	return valuesFromModel(m)
}

func (s *Store) UpdateValues(ctx context.Context, v *values.Values) error {
	if err := claimTenant(ctx, &v.TenantID); err != nil {
		return err
	}
	v.UpdatedAt = now()
	m, err := valuesToModel(v)
	if err != nil {
		return fmt.Errorf("shield/sqlite: update values: %w", err)
	}
	res, err := s.sdb.NewUpdate(m).WherePK().Where("tenant_id = ?", v.TenantID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: update values: %w", err)
	}
	return updatedOrNotFound(res, shield.ErrValueNotFound, "update values")
}

func (s *Store) DeleteValues(ctx context.Context, vID id.ValueID) error {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return tenantErr
	}
	_, err := s.sdb.NewDelete((*valuesModel)(nil)).Where("id = ?", vID.String()).Where("tenant_id = ?", tenant).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: delete values: %w", err)
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
	q := s.sdb.NewSelect(&models).Where("tenant_id = ?", tenant).OrderExpr("created_at ASC")
	if filter != nil {
		if filter.AppID != "" {
			q = q.Where("app_id = ?", filter.AppID)
		}
		if filter.Enabled != nil {
			q = q.Where("enabled = ?", *filter.Enabled)
		}
		if filter.Limit > 0 {
			q = q.Limit(filter.Limit)
		}
		if filter.Offset > 0 {
			q = q.Offset(filter.Offset)
		}
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("shield/sqlite: list values: %w", err)
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
	m, err := judgmentToModel(j)
	if err != nil {
		return fmt.Errorf("shield/sqlite: create judgment: %w", err)
	}
	_, err = s.sdb.NewInsert(m).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: create judgment: %w", err)
	}
	return nil
}

func (s *Store) GetJudgment(ctx context.Context, jID id.JudgmentID) (*judgment.Judgment, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	m := new(judgmentModel)
	err := s.sdb.NewSelect(m).Where("id = ?", jID.String()).Where("tenant_id = ?", tenant).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrJudgmentNotFound, "get judgment")
	}
	return judgmentFromModel(m)
}

func (s *Store) GetJudgmentByName(ctx context.Context, appID, name string) (*judgment.Judgment, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	m := new(judgmentModel)
	err := s.sdb.NewSelect(m).
		Where("app_id = ?", appID).
		Where("tenant_id = ?", tenant).
		Where("name = ?", name).
		Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrJudgmentNotFound, "get judgment by name")
	}
	return judgmentFromModel(m)
}

func (s *Store) UpdateJudgment(ctx context.Context, j *judgment.Judgment) error {
	if err := claimTenant(ctx, &j.TenantID); err != nil {
		return err
	}
	j.UpdatedAt = now()
	m, err := judgmentToModel(j)
	if err != nil {
		return fmt.Errorf("shield/sqlite: update judgment: %w", err)
	}
	res, err := s.sdb.NewUpdate(m).WherePK().Where("tenant_id = ?", j.TenantID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: update judgment: %w", err)
	}
	return updatedOrNotFound(res, shield.ErrJudgmentNotFound, "update judgment")
}

func (s *Store) DeleteJudgment(ctx context.Context, jID id.JudgmentID) error {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return tenantErr
	}
	_, err := s.sdb.NewDelete((*judgmentModel)(nil)).Where("id = ?", jID.String()).Where("tenant_id = ?", tenant).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: delete judgment: %w", err)
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
	q := s.sdb.NewSelect(&models).Where("tenant_id = ?", tenant).OrderExpr("created_at ASC")
	if filter != nil {
		if filter.AppID != "" {
			q = q.Where("app_id = ?", filter.AppID)
		}
		if filter.Domain != "" {
			q = q.Where("domain = ?", string(filter.Domain))
		}
		if filter.Enabled != nil {
			q = q.Where("enabled = ?", *filter.Enabled)
		}
		if filter.Limit > 0 {
			q = q.Limit(filter.Limit)
		}
		if filter.Offset > 0 {
			q = q.Offset(filter.Offset)
		}
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("shield/sqlite: list judgments: %w", err)
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
	m, err := reflexToModel(r)
	if err != nil {
		return fmt.Errorf("shield/sqlite: create reflex: %w", err)
	}
	_, err = s.sdb.NewInsert(m).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: create reflex: %w", err)
	}
	return nil
}

func (s *Store) GetReflex(ctx context.Context, rID id.ReflexID) (*reflex.Reflex, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	m := new(reflexModel)
	err := s.sdb.NewSelect(m).Where("id = ?", rID.String()).Where("tenant_id = ?", tenant).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrReflexNotFound, "get reflex")
	}
	return reflexFromModel(m)
}

func (s *Store) GetReflexByName(ctx context.Context, appID, name string) (*reflex.Reflex, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	m := new(reflexModel)
	err := s.sdb.NewSelect(m).
		Where("app_id = ?", appID).
		Where("tenant_id = ?", tenant).
		Where("name = ?", name).
		Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrReflexNotFound, "get reflex by name")
	}
	return reflexFromModel(m)
}

func (s *Store) UpdateReflex(ctx context.Context, r *reflex.Reflex) error {
	if err := claimTenant(ctx, &r.TenantID); err != nil {
		return err
	}
	r.UpdatedAt = now()
	m, err := reflexToModel(r)
	if err != nil {
		return fmt.Errorf("shield/sqlite: update reflex: %w", err)
	}
	res, err := s.sdb.NewUpdate(m).WherePK().Where("tenant_id = ?", r.TenantID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: update reflex: %w", err)
	}
	return updatedOrNotFound(res, shield.ErrReflexNotFound, "update reflex")
}

func (s *Store) DeleteReflex(ctx context.Context, rID id.ReflexID) error {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return tenantErr
	}
	_, err := s.sdb.NewDelete((*reflexModel)(nil)).Where("id = ?", rID.String()).Where("tenant_id = ?", tenant).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: delete reflex: %w", err)
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
	q := s.sdb.NewSelect(&models).Where("tenant_id = ?", tenant).OrderExpr("created_at ASC")
	if filter != nil {
		if filter.AppID != "" {
			q = q.Where("app_id = ?", filter.AppID)
		}
		if filter.Enabled != nil {
			q = q.Where("enabled = ?", *filter.Enabled)
		}
		if filter.Limit > 0 {
			q = q.Limit(filter.Limit)
		}
		if filter.Offset > 0 {
			q = q.Offset(filter.Offset)
		}
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("shield/sqlite: list reflexes: %w", err)
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
	m, err := profileToModel(p)
	if err != nil {
		return fmt.Errorf("shield/sqlite: create profile: %w", err)
	}
	_, err = s.sdb.NewInsert(m).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: create profile: %w", err)
	}
	return nil
}

func (s *Store) GetProfile(ctx context.Context, pID id.SafetyProfileID) (*profile.SafetyProfile, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	m := new(profileModel)
	err := s.sdb.NewSelect(m).Where("id = ?", pID.String()).Where("tenant_id = ?", tenant).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrProfileNotFound, "get profile")
	}
	return profileFromModel(m)
}

func (s *Store) GetProfileByName(ctx context.Context, appID, name string) (*profile.SafetyProfile, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	m := new(profileModel)
	err := s.sdb.NewSelect(m).
		Where("app_id = ?", appID).
		Where("tenant_id = ?", tenant).
		Where("name = ?", name).
		Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrProfileNotFound, "get profile by name")
	}
	return profileFromModel(m)
}

func (s *Store) UpdateProfile(ctx context.Context, p *profile.SafetyProfile) error {
	if err := claimTenant(ctx, &p.TenantID); err != nil {
		return err
	}
	p.UpdatedAt = now()
	m, err := profileToModel(p)
	if err != nil {
		return fmt.Errorf("shield/sqlite: update profile: %w", err)
	}
	res, err := s.sdb.NewUpdate(m).WherePK().Where("tenant_id = ?", p.TenantID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: update profile: %w", err)
	}
	return updatedOrNotFound(res, shield.ErrProfileNotFound, "update profile")
}

func (s *Store) DeleteProfile(ctx context.Context, pID id.SafetyProfileID) error {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return tenantErr
	}
	_, err := s.sdb.NewDelete((*profileModel)(nil)).Where("id = ?", pID.String()).Where("tenant_id = ?", tenant).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: delete profile: %w", err)
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
	q := s.sdb.NewSelect(&models).Where("tenant_id = ?", tenant).OrderExpr("created_at ASC")
	if filter != nil {
		if filter.AppID != "" {
			q = q.Where("app_id = ?", filter.AppID)
		}
		if filter.Enabled != nil {
			q = q.Where("enabled = ?", *filter.Enabled)
		}
		if filter.Limit > 0 {
			q = q.Limit(filter.Limit)
		}
		if filter.Offset > 0 {
			q = q.Offset(filter.Offset)
		}
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("shield/sqlite: list profiles: %w", err)
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
	m, err := scanToModel(result)
	if err != nil {
		return fmt.Errorf("shield/sqlite: create scan: %w", err)
	}
	_, err = s.sdb.NewInsert(m).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: create scan: %w", err)
	}
	return nil
}

func (s *Store) GetScan(ctx context.Context, scanID id.ScanID) (*scan.Result, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	m := new(scanResultModel)
	err := s.sdb.NewSelect(m).Where("id = ?", scanID.String()).Where("tenant_id = ?", tenant).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrScanNotFound, "get scan")
	}
	return scanFromModel(m)
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
	q := s.sdb.NewSelect(&models).Where("tenant_id = ?", tenant).OrderExpr("created_at DESC")
	if filter != nil {
		if filter.AppID != "" {
			q = q.Where("app_id = ?", filter.AppID)
		}
		if filter.Direction != "" {
			q = q.Where("direction = ?", string(filter.Direction))
		}
		if filter.Decision != "" {
			q = q.Where("decision = ?", string(filter.Decision))
		}
		if filter.Limit > 0 {
			q = q.Limit(filter.Limit)
		}
		if filter.Offset > 0 {
			q = q.Offset(filter.Offset)
		}
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("shield/sqlite: list scans: %w", err)
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
	var models []scanResultModel
	q := s.sdb.NewSelect(&models).Where("tenant_id = ?", tenant)
	if filter != nil {
		if filter.AppID != "" {
			q = q.Where("app_id = ?", filter.AppID)
		}
		if filter.From != "" {
			q = q.Where("created_at >= ?", filter.From)
		}
		if filter.To != "" {
			q = q.Where("created_at <= ?", filter.To)
		}
	}
	if err := q.Scan(ctx); err != nil {
		if isNoRows(err) {
			return emptyScanStats(), nil
		}
		return nil, fmt.Errorf("shield/sqlite: scan stats: %w", err)
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
	if err := store.ScopeWritable(ctx, pol.ScopeKey, string(pol.ScopeLevel)); err != nil {
		return err
	}
	n := now()
	pol.CreatedAt = n
	pol.UpdatedAt = n
	m, err := policyToModel(pol)
	if err != nil {
		return fmt.Errorf("shield/sqlite: create policy: %w", err)
	}
	_, err = s.sdb.NewInsert(m).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: create policy: %w", err)
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
	m := new(policyModel)
	err := s.sdb.NewSelect(m).Where("id = ?", polID.String()).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrPolicyNotFound, "get policy")
	}
	if !store.ScopeVisible(ctx, m.ScopeKey, m.ScopeLevel) {
		return nil, shield.ErrPolicyNotFound
	}
	return m, nil
}

func (s *Store) GetPolicyByName(ctx context.Context, scopeKey, name string) (*policy.Policy, error) {
	levels, levelErr := store.ScopeLevels(ctx, scopeKey, "")
	if levelErr != nil {
		return nil, levelErr
	}
	m := new(policyModel)
	q := s.sdb.NewSelect(m).
		Where("scope_key = ?", scopeKey).
		Where("name = ?", name)
	if levels != nil {
		clause, args := whereIn("scope_level", levels)
		q = q.Where(clause, args...)
	}
	if err := q.Scan(ctx); err != nil {
		return nil, notFoundOrWrap(err, shield.ErrPolicyNotFound, "get policy by name")
	}
	return policyFromModel(m)
}

func (s *Store) UpdatePolicy(ctx context.Context, pol *policy.Policy) error {
	current, err := s.visiblePolicy(ctx, pol.ID)
	if err != nil {
		return err
	}
	// A tenant may only write its own org scope, both where the policy is now
	// and where the update would put it (store.ScopeWritable).
	if writeErr := store.ScopeWritable(ctx, current.ScopeKey, current.ScopeLevel); writeErr != nil {
		return writeErr
	}
	if writeErr := store.ScopeWritable(ctx, pol.ScopeKey, string(pol.ScopeLevel)); writeErr != nil {
		return writeErr
	}
	pol.UpdatedAt = now()
	m, err := policyToModel(pol)
	if err != nil {
		return fmt.Errorf("shield/sqlite: update policy: %w", err)
	}
	res, err := s.sdb.NewUpdate(m).WherePK().
		Where("scope_key = ?", current.ScopeKey).
		Where("scope_level = ?", current.ScopeLevel).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: update policy: %w", err)
	}
	return updatedOrNotFound(res, shield.ErrPolicyNotFound, "update policy")
}

// DeletePolicy is idempotent: a missing policy and one the context cannot see
// both return nil, and the second is left in place. A visible policy the
// context may not write (an app-level policy under a tenant) is refused with
// ErrTenantMismatch rather than skipped.
func (s *Store) DeletePolicy(ctx context.Context, polID id.PolicyID) error {
	current, err := s.visiblePolicy(ctx, polID)
	if errors.Is(err, shield.ErrPolicyNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if writeErr := store.ScopeWritable(ctx, current.ScopeKey, current.ScopeLevel); writeErr != nil {
		return writeErr
	}
	_, err = s.sdb.NewDelete((*policyModel)(nil)).
		Where("id = ?", polID.String()).
		Where("scope_key = ?", current.ScopeKey).
		Where("scope_level = ?", current.ScopeLevel).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: delete policy: %w", err)
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
	q := s.sdb.NewSelect(&models).Where("scope_key = ?", filter.ScopeKey).OrderExpr("created_at ASC")
	if levels != nil {
		clause, args := whereIn("scope_level", levels)
		q = q.Where(clause, args...)
	}
	if filter.ScopeLevel != "" {
		q = q.Where("scope_level = ?", string(filter.ScopeLevel))
	}
	if filter.Enabled != nil {
		q = q.Where("enabled = ?", *filter.Enabled)
	}
	if filter.Limit > 0 {
		q = q.Limit(filter.Limit)
	}
	if filter.Offset > 0 {
		q = q.Offset(filter.Offset)
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("shield/sqlite: list policies: %w", err)
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
	err := s.sdb.NewSelect(&models).
		Where("scope_key = ?", scopeKey).
		Where("scope_level = ?", string(level)).
		Where("enabled = ?", true).
		OrderExpr("created_at ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("shield/sqlite: get policies for scope: %w", err)
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
	// The policy must be one the tenant can see; a foreign or missing policy
	// is ErrPolicyNotFound.
	if _, visibleErr := s.visiblePolicy(shield.WithTenant(ctx, tenant), polID); visibleErr != nil {
		return visibleErr
	}
	m := &policyTenantModel{
		TenantID:  tenant,
		PolicyID:  polID.String(),
		CreatedAt: now(),
	}
	_, err = s.sdb.NewInsert(m).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: assign policy to tenant: %w", err)
	}
	return nil
}

func (s *Store) UnassignFromTenant(ctx context.Context, tenantID string, polID id.PolicyID) error {
	tenant, err := store.Tenant(ctx, tenantID)
	if err != nil {
		return err
	}
	// A foreign or missing policy has nothing to unassign: nil, and no write.
	_, visibleErr := s.visiblePolicy(shield.WithTenant(ctx, tenant), polID)
	if errors.Is(visibleErr, shield.ErrPolicyNotFound) {
		return nil
	}
	if visibleErr != nil {
		return visibleErr
	}
	_, err = s.sdb.NewDelete((*policyTenantModel)(nil)).
		Where("tenant_id = ?", tenant).
		Where("policy_id = ?", polID.String()).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: unassign policy from tenant: %w", err)
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
	_, err := s.sdb.NewInsert(&models).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: store pii tokens: %w", err)
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
	clause, args := whereIn("id", ids)
	err := s.sdb.NewSelect(&models).Where(clause, args...).Where("tenant_id = ?", tenant).Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("shield/sqlite: load pii tokens: %w", err)
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
	err := s.sdb.NewSelect(&models).
		Where("scan_id = ?", scanID.String()).
		Where("tenant_id = ?", tenant).
		OrderExpr("created_at ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("shield/sqlite: load pii tokens by scan: %w", err)
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
	clause, args := whereIn("id", ids)
	_, err := s.sdb.NewDelete((*piiTokenModel)(nil)).Where(clause, args...).Where("tenant_id = ?", tenant).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: delete pii tokens: %w", err)
	}
	return nil
}

func (s *Store) DeletePIITokensByTenant(ctx context.Context, tenantID string) error {
	tenant, err := store.Tenant(ctx, tenantID)
	if err != nil {
		return err
	}
	_, err = s.sdb.NewDelete((*piiTokenModel)(nil)).Where("tenant_id = ?", tenant).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: delete pii tokens by tenant: %w", err)
	}
	return nil
}

// PurgePIITokens is an operator retention sweep: it removes expired tokens in
// every tenant and so takes no tenant.
func (s *Store) PurgePIITokens(ctx context.Context, olderThan time.Time) (int64, error) {
	res, err := s.sdb.NewDelete((*piiTokenModel)(nil)).
		Where("expires_at IS NOT NULL").
		Where("expires_at < ?", olderThan).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("shield/sqlite: purge pii tokens: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("shield/sqlite: purge pii tokens rows affected: %w", err)
	}
	return rows, nil
}

func (s *Store) PIIStats(ctx context.Context, tenantID string) (*pii.Stats, error) {
	tenant, tenantErr := store.Tenant(ctx, tenantID)
	if tenantErr != nil {
		return nil, tenantErr
	}
	var models []piiTokenModel
	if err := s.sdb.NewSelect(&models).Where("tenant_id = ?", tenant).Scan(ctx); err != nil {
		if isNoRows(err) {
			return &pii.Stats{
				ByType:   make(map[string]int64),
				ByTenant: make(map[string]int64),
			}, nil
		}
		return nil, fmt.Errorf("shield/sqlite: pii stats: %w", err)
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
	if err := store.ScopeWritable(ctx, report.ScopeKey, report.ScopeLevel); err != nil {
		return err
	}
	n := now()
	report.CreatedAt = n
	report.UpdatedAt = n
	m, err := complianceToModel(report)
	if err != nil {
		return fmt.Errorf("shield/sqlite: create compliance report: %w", err)
	}
	_, err = s.sdb.NewInsert(m).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: create compliance report: %w", err)
	}
	return nil
}

func (s *Store) GetReport(ctx context.Context, reportID id.ComplianceReportID) (*compliance.Report, error) {
	key, level, ok := store.ReportScope(ctx)
	if !ok {
		return nil, shield.ErrComplianceNotFound
	}
	m := new(complianceReportModel)
	err := s.sdb.NewSelect(m).Where("id = ?", reportID.String()).
		Where("scope_key = ?", key).Where("scope_level = ?", level).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrComplianceNotFound, "get compliance report")
	}
	return complianceFromModel(m)
}

func (s *Store) ListReports(ctx context.Context, filter *compliance.ListFilter) ([]*compliance.Report, error) {
	if filter == nil {
		return nil, shield.ErrTenantRequired
	}
	levels, levelErr := store.ReportLevels(ctx, filter.ScopeKey)
	if levelErr != nil {
		return nil, levelErr
	}
	var models []complianceReportModel
	q := s.sdb.NewSelect(&models).Where("scope_key = ?", filter.ScopeKey).OrderExpr("generated_at DESC")
	if levels != nil {
		clause, args := whereIn("scope_level", levels)
		q = q.Where(clause, args...)
	}
	if filter.Framework != "" {
		q = q.Where("framework = ?", string(filter.Framework))
	}
	if filter.Limit > 0 {
		q = q.Limit(filter.Limit)
	}
	if filter.Offset > 0 {
		q = q.Offset(filter.Offset)
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("shield/sqlite: list compliance reports: %w", err)
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
