package postgres

import (
	"context"
	"fmt"

	"github.com/xraph/shield"
	"github.com/xraph/shield/id"
	"github.com/xraph/shield/reflex"
)

func (s *Store) CreateReflex(ctx context.Context, r *reflex.Reflex) error {
	n := now()
	r.CreatedAt = n
	r.UpdatedAt = n
	m := reflexToModel(r)
	_, err := s.pgdb.NewInsert(m).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: create reflex: %w", err)
	}
	return nil
}

func (s *Store) GetReflex(ctx context.Context, rID id.ReflexID) (*reflex.Reflex, error) {
	m := new(reflexModel)
	err := s.pgdb.NewSelect(m).Where("id = ?", rID.String()).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrReflexNotFound, "get reflex")
	}
	return reflexFromModel(m), nil
}

func (s *Store) GetReflexByName(ctx context.Context, appID, name string) (*reflex.Reflex, error) {
	m := new(reflexModel)
	err := s.pgdb.NewSelect(m).
		Where("app_id = ?", appID).
		Where("name = ?", name).
		Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrReflexNotFound, "get reflex by name")
	}
	return reflexFromModel(m), nil
}

func (s *Store) UpdateReflex(ctx context.Context, r *reflex.Reflex) error {
	r.UpdatedAt = now()
	m := reflexToModel(r)
	_, err := s.pgdb.NewUpdate(m).WherePK().Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: update reflex: %w", err)
	}
	return nil
}

func (s *Store) DeleteReflex(ctx context.Context, rID id.ReflexID) error {
	_, err := s.pgdb.NewDelete((*reflexModel)(nil)).Where("id = ?", rID.String()).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: delete reflex: %w", err)
	}
	return nil
}

func (s *Store) ListReflexes(ctx context.Context, filter *reflex.ListFilter) ([]*reflex.Reflex, error) {
	var models []reflexModel
	q := s.pgdb.NewSelect(&models).OrderExpr("created_at ASC")
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
		return nil, fmt.Errorf("shield/postgres: list reflexes: %w", err)
	}
	result := make([]*reflex.Reflex, len(models))
	for i := range models {
		result[i] = reflexFromModel(&models[i])
	}
	return result, nil
}
