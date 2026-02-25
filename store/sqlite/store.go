package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/sqlitedriver"
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

// ──────────────────────────────────────────────────
// Instinct operations
// ──────────────────────────────────────────────────

func (s *Store) CreateInstinct(ctx context.Context, inst *instinct.Instinct) error {
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
	m := new(instinctModel)
	err := s.sdb.NewSelect(m).Where("id = ?", instID.String()).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrInstinctNotFound, "get instinct")
	}
	return instinctFromModel(m)
}

func (s *Store) GetInstinctByName(ctx context.Context, appID, name string) (*instinct.Instinct, error) {
	m := new(instinctModel)
	err := s.sdb.NewSelect(m).
		Where("app_id = ?", appID).
		Where("name = ?", name).
		Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrInstinctNotFound, "get instinct by name")
	}
	return instinctFromModel(m)
}

func (s *Store) UpdateInstinct(ctx context.Context, inst *instinct.Instinct) error {
	inst.UpdatedAt = now()
	m, err := instinctToModel(inst)
	if err != nil {
		return fmt.Errorf("shield/sqlite: update instinct: %w", err)
	}
	_, err = s.sdb.NewUpdate(m).WherePK().Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: update instinct: %w", err)
	}
	return nil
}

func (s *Store) DeleteInstinct(ctx context.Context, instID id.InstinctID) error {
	_, err := s.sdb.NewDelete((*instinctModel)(nil)).Where("id = ?", instID.String()).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: delete instinct: %w", err)
	}
	return nil
}

func (s *Store) ListInstincts(ctx context.Context, filter *instinct.ListFilter) ([]*instinct.Instinct, error) {
	var models []instinctModel
	q := s.sdb.NewSelect(&models).OrderExpr("created_at ASC")
	if filter != nil {
		if filter.AppID != "" {
			q = q.Where("app_id = ?", filter.AppID)
		}
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
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
	m := new(awarenessModel)
	err := s.sdb.NewSelect(m).Where("id = ?", aID.String()).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrAwarenessNotFound, "get awareness")
	}
	return awarenessFromModel(m)
}

func (s *Store) GetAwarenessByName(ctx context.Context, appID, name string) (*awareness.Awareness, error) {
	m := new(awarenessModel)
	err := s.sdb.NewSelect(m).
		Where("app_id = ?", appID).
		Where("name = ?", name).
		Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrAwarenessNotFound, "get awareness by name")
	}
	return awarenessFromModel(m)
}

func (s *Store) UpdateAwareness(ctx context.Context, a *awareness.Awareness) error {
	a.UpdatedAt = now()
	m, err := awarenessToModel(a)
	if err != nil {
		return fmt.Errorf("shield/sqlite: update awareness: %w", err)
	}
	_, err = s.sdb.NewUpdate(m).WherePK().Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: update awareness: %w", err)
	}
	return nil
}

func (s *Store) DeleteAwareness(ctx context.Context, aID id.AwarenessID) error {
	_, err := s.sdb.NewDelete((*awarenessModel)(nil)).Where("id = ?", aID.String()).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: delete awareness: %w", err)
	}
	return nil
}

func (s *Store) ListAwareness(ctx context.Context, filter *awareness.ListFilter) ([]*awareness.Awareness, error) {
	var models []awarenessModel
	q := s.sdb.NewSelect(&models).OrderExpr("created_at ASC")
	if filter != nil {
		if filter.AppID != "" {
			q = q.Where("app_id = ?", filter.AppID)
		}
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
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
	m := new(boundaryModel)
	err := s.sdb.NewSelect(m).Where("id = ?", bID.String()).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrBoundaryNotFound, "get boundary")
	}
	return boundaryFromModel(m)
}

func (s *Store) GetBoundaryByName(ctx context.Context, appID, name string) (*boundary.Boundary, error) {
	m := new(boundaryModel)
	err := s.sdb.NewSelect(m).
		Where("app_id = ?", appID).
		Where("name = ?", name).
		Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrBoundaryNotFound, "get boundary by name")
	}
	return boundaryFromModel(m)
}

func (s *Store) UpdateBoundary(ctx context.Context, b *boundary.Boundary) error {
	b.UpdatedAt = now()
	m, err := boundaryToModel(b)
	if err != nil {
		return fmt.Errorf("shield/sqlite: update boundary: %w", err)
	}
	_, err = s.sdb.NewUpdate(m).WherePK().Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: update boundary: %w", err)
	}
	return nil
}

func (s *Store) DeleteBoundary(ctx context.Context, bID id.BoundaryID) error {
	_, err := s.sdb.NewDelete((*boundaryModel)(nil)).Where("id = ?", bID.String()).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: delete boundary: %w", err)
	}
	return nil
}

func (s *Store) ListBoundaries(ctx context.Context, filter *boundary.ListFilter) ([]*boundary.Boundary, error) {
	var models []boundaryModel
	q := s.sdb.NewSelect(&models).OrderExpr("created_at ASC")
	if filter != nil {
		if filter.AppID != "" {
			q = q.Where("app_id = ?", filter.AppID)
		}
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
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
	m := new(valuesModel)
	err := s.sdb.NewSelect(m).Where("id = ?", vID.String()).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrValueNotFound, "get values")
	}
	return valuesFromModel(m)
}

func (s *Store) GetValuesByName(ctx context.Context, appID, name string) (*values.Values, error) {
	m := new(valuesModel)
	err := s.sdb.NewSelect(m).
		Where("app_id = ?", appID).
		Where("name = ?", name).
		Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrValueNotFound, "get values by name")
	}
	return valuesFromModel(m)
}

func (s *Store) UpdateValues(ctx context.Context, v *values.Values) error {
	v.UpdatedAt = now()
	m, err := valuesToModel(v)
	if err != nil {
		return fmt.Errorf("shield/sqlite: update values: %w", err)
	}
	_, err = s.sdb.NewUpdate(m).WherePK().Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: update values: %w", err)
	}
	return nil
}

func (s *Store) DeleteValues(ctx context.Context, vID id.ValueID) error {
	_, err := s.sdb.NewDelete((*valuesModel)(nil)).Where("id = ?", vID.String()).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: delete values: %w", err)
	}
	return nil
}

func (s *Store) ListValues(ctx context.Context, filter *values.ListFilter) ([]*values.Values, error) {
	var models []valuesModel
	q := s.sdb.NewSelect(&models).OrderExpr("created_at ASC")
	if filter != nil {
		if filter.AppID != "" {
			q = q.Where("app_id = ?", filter.AppID)
		}
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
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
	m := new(judgmentModel)
	err := s.sdb.NewSelect(m).Where("id = ?", jID.String()).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrJudgmentNotFound, "get judgment")
	}
	return judgmentFromModel(m)
}

func (s *Store) GetJudgmentByName(ctx context.Context, appID, name string) (*judgment.Judgment, error) {
	m := new(judgmentModel)
	err := s.sdb.NewSelect(m).
		Where("app_id = ?", appID).
		Where("name = ?", name).
		Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrJudgmentNotFound, "get judgment by name")
	}
	return judgmentFromModel(m)
}

func (s *Store) UpdateJudgment(ctx context.Context, j *judgment.Judgment) error {
	j.UpdatedAt = now()
	m, err := judgmentToModel(j)
	if err != nil {
		return fmt.Errorf("shield/sqlite: update judgment: %w", err)
	}
	_, err = s.sdb.NewUpdate(m).WherePK().Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: update judgment: %w", err)
	}
	return nil
}

func (s *Store) DeleteJudgment(ctx context.Context, jID id.JudgmentID) error {
	_, err := s.sdb.NewDelete((*judgmentModel)(nil)).Where("id = ?", jID.String()).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: delete judgment: %w", err)
	}
	return nil
}

func (s *Store) ListJudgments(ctx context.Context, filter *judgment.ListFilter) ([]*judgment.Judgment, error) {
	var models []judgmentModel
	q := s.sdb.NewSelect(&models).OrderExpr("created_at ASC")
	if filter != nil {
		if filter.AppID != "" {
			q = q.Where("app_id = ?", filter.AppID)
		}
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
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
	m := new(reflexModel)
	err := s.sdb.NewSelect(m).Where("id = ?", rID.String()).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrReflexNotFound, "get reflex")
	}
	return reflexFromModel(m)
}

func (s *Store) GetReflexByName(ctx context.Context, appID, name string) (*reflex.Reflex, error) {
	m := new(reflexModel)
	err := s.sdb.NewSelect(m).
		Where("app_id = ?", appID).
		Where("name = ?", name).
		Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrReflexNotFound, "get reflex by name")
	}
	return reflexFromModel(m)
}

func (s *Store) UpdateReflex(ctx context.Context, r *reflex.Reflex) error {
	r.UpdatedAt = now()
	m, err := reflexToModel(r)
	if err != nil {
		return fmt.Errorf("shield/sqlite: update reflex: %w", err)
	}
	_, err = s.sdb.NewUpdate(m).WherePK().Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: update reflex: %w", err)
	}
	return nil
}

func (s *Store) DeleteReflex(ctx context.Context, rID id.ReflexID) error {
	_, err := s.sdb.NewDelete((*reflexModel)(nil)).Where("id = ?", rID.String()).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: delete reflex: %w", err)
	}
	return nil
}

func (s *Store) ListReflexes(ctx context.Context, filter *reflex.ListFilter) ([]*reflex.Reflex, error) {
	var models []reflexModel
	q := s.sdb.NewSelect(&models).OrderExpr("created_at ASC")
	if filter != nil {
		if filter.AppID != "" {
			q = q.Where("app_id = ?", filter.AppID)
		}
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
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
	m := new(profileModel)
	err := s.sdb.NewSelect(m).Where("id = ?", pID.String()).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrProfileNotFound, "get profile")
	}
	return profileFromModel(m)
}

func (s *Store) GetProfileByName(ctx context.Context, appID, name string) (*profile.SafetyProfile, error) {
	m := new(profileModel)
	err := s.sdb.NewSelect(m).
		Where("app_id = ?", appID).
		Where("name = ?", name).
		Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrProfileNotFound, "get profile by name")
	}
	return profileFromModel(m)
}

func (s *Store) UpdateProfile(ctx context.Context, p *profile.SafetyProfile) error {
	p.UpdatedAt = now()
	m, err := profileToModel(p)
	if err != nil {
		return fmt.Errorf("shield/sqlite: update profile: %w", err)
	}
	_, err = s.sdb.NewUpdate(m).WherePK().Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: update profile: %w", err)
	}
	return nil
}

func (s *Store) DeleteProfile(ctx context.Context, pID id.SafetyProfileID) error {
	_, err := s.sdb.NewDelete((*profileModel)(nil)).Where("id = ?", pID.String()).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: delete profile: %w", err)
	}
	return nil
}

func (s *Store) ListProfiles(ctx context.Context, filter *profile.ListFilter) ([]*profile.SafetyProfile, error) {
	var models []profileModel
	q := s.sdb.NewSelect(&models).OrderExpr("created_at ASC")
	if filter != nil {
		if filter.AppID != "" {
			q = q.Where("app_id = ?", filter.AppID)
		}
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
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
	m := new(scanResultModel)
	err := s.sdb.NewSelect(m).Where("id = ?", scanID.String()).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrScanNotFound, "get scan")
	}
	return scanFromModel(m)
}

func (s *Store) ListScans(ctx context.Context, filter *scan.ListFilter) ([]*scan.Result, error) {
	var models []scanResultModel
	q := s.sdb.NewSelect(&models).OrderExpr("created_at DESC")
	if filter != nil {
		if filter.AppID != "" {
			q = q.Where("app_id = ?", filter.AppID)
		}
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
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
	var models []scanResultModel
	q := s.sdb.NewSelect(&models)
	if filter != nil {
		if filter.AppID != "" {
			q = q.Where("app_id = ?", filter.AppID)
		}
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
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
	m := new(policyModel)
	err := s.sdb.NewSelect(m).Where("id = ?", polID.String()).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrPolicyNotFound, "get policy")
	}
	return policyFromModel(m)
}

func (s *Store) GetPolicyByName(ctx context.Context, scopeKey, name string) (*policy.Policy, error) {
	m := new(policyModel)
	err := s.sdb.NewSelect(m).
		Where("scope_key = ?", scopeKey).
		Where("name = ?", name).
		Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrPolicyNotFound, "get policy by name")
	}
	return policyFromModel(m)
}

func (s *Store) UpdatePolicy(ctx context.Context, pol *policy.Policy) error {
	pol.UpdatedAt = now()
	m, err := policyToModel(pol)
	if err != nil {
		return fmt.Errorf("shield/sqlite: update policy: %w", err)
	}
	_, err = s.sdb.NewUpdate(m).WherePK().Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: update policy: %w", err)
	}
	return nil
}

func (s *Store) DeletePolicy(ctx context.Context, polID id.PolicyID) error {
	_, err := s.sdb.NewDelete((*policyModel)(nil)).Where("id = ?", polID.String()).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: delete policy: %w", err)
	}
	return nil
}

func (s *Store) ListPolicies(ctx context.Context, filter *policy.ListFilter) ([]*policy.Policy, error) {
	var models []policyModel
	q := s.sdb.NewSelect(&models).OrderExpr("created_at ASC")
	if filter != nil {
		if filter.ScopeKey != "" {
			q = q.Where("scope_key = ?", filter.ScopeKey)
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
	m := &policyTenantModel{
		TenantID:  tenantID,
		PolicyID:  polID.String(),
		CreatedAt: now(),
	}
	_, err := s.sdb.NewInsert(m).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: assign policy to tenant: %w", err)
	}
	return nil
}

func (s *Store) UnassignFromTenant(ctx context.Context, tenantID string, polID id.PolicyID) error {
	_, err := s.sdb.NewDelete((*policyTenantModel)(nil)).
		Where("tenant_id = ?", tenantID).
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
	if len(tokenIDs) == 0 {
		return nil, nil
	}
	ids := make([]string, len(tokenIDs))
	for i, tid := range tokenIDs {
		ids[i] = tid.String()
	}
	var models []piiTokenModel
	err := s.sdb.NewSelect(&models).Where("id IN (?)", ids).Scan(ctx)
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
	var models []piiTokenModel
	err := s.sdb.NewSelect(&models).
		Where("scan_id = ?", scanID.String()).
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
	if len(tokenIDs) == 0 {
		return nil
	}
	ids := make([]string, len(tokenIDs))
	for i, tid := range tokenIDs {
		ids[i] = tid.String()
	}
	_, err := s.sdb.NewDelete((*piiTokenModel)(nil)).Where("id IN (?)", ids).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: delete pii tokens: %w", err)
	}
	return nil
}

func (s *Store) DeletePIITokensByTenant(ctx context.Context, tenantID string) error {
	_, err := s.sdb.NewDelete((*piiTokenModel)(nil)).Where("tenant_id = ?", tenantID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/sqlite: delete pii tokens by tenant: %w", err)
	}
	return nil
}

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
	var models []piiTokenModel
	q := s.sdb.NewSelect(&models)
	if tenantID != "" {
		q = q.Where("tenant_id = ?", tenantID)
	}
	if err := q.Scan(ctx); err != nil {
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
	m := new(complianceReportModel)
	err := s.sdb.NewSelect(m).Where("id = ?", reportID.String()).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrComplianceNotFound, "get compliance report")
	}
	return complianceFromModel(m)
}

func (s *Store) ListReports(ctx context.Context, filter *compliance.ListFilter) ([]*compliance.Report, error) {
	var models []complianceReportModel
	q := s.sdb.NewSelect(&models).OrderExpr("generated_at DESC")
	if filter != nil {
		if filter.ScopeKey != "" {
			q = q.Where("scope_key = ?", filter.ScopeKey)
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
