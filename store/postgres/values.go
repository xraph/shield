package postgres

import (
	"context"
	"fmt"

	"github.com/xraph/shield"
	"github.com/xraph/shield/id"
	"github.com/xraph/shield/values"
)

func (s *Store) CreateValues(ctx context.Context, v *values.Values) error {
	n := now()
	v.CreatedAt = n
	v.UpdatedAt = n
	m := valuesToModel(v)
	_, err := s.pgdb.NewInsert(m).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: create values: %w", err)
	}
	return nil
}

func (s *Store) GetValues(ctx context.Context, vID id.ValueID) (*values.Values, error) {
	m := new(valuesModel)
	err := s.pgdb.NewSelect(m).Where("id = ?", vID.String()).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrValueNotFound, "get values")
	}
	return valuesFromModel(m), nil
}

func (s *Store) GetValuesByName(ctx context.Context, appID, name string) (*values.Values, error) {
	m := new(valuesModel)
	err := s.pgdb.NewSelect(m).
		Where("app_id = ?", appID).
		Where("name = ?", name).
		Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrValueNotFound, "get values by name")
	}
	return valuesFromModel(m), nil
}

func (s *Store) UpdateValues(ctx context.Context, v *values.Values) error {
	v.UpdatedAt = now()
	m := valuesToModel(v)
	_, err := s.pgdb.NewUpdate(m).WherePK().Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: update values: %w", err)
	}
	return nil
}

func (s *Store) DeleteValues(ctx context.Context, vID id.ValueID) error {
	_, err := s.pgdb.NewDelete((*valuesModel)(nil)).Where("id = ?", vID.String()).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: delete values: %w", err)
	}
	return nil
}

func (s *Store) ListValues(ctx context.Context, filter *values.ListFilter) ([]*values.Values, error) {
	var models []valuesModel
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
		return nil, fmt.Errorf("shield/postgres: list values: %w", err)
	}
	result := make([]*values.Values, len(models))
	for i := range models {
		result[i] = valuesFromModel(&models[i])
	}
	return result, nil
}
