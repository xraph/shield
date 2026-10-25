package postgres

import (
	"context"
	"fmt"

	"github.com/xraph/shield"
	"github.com/xraph/shield/id"
	"github.com/xraph/shield/store"
	"github.com/xraph/shield/values"
)

func (s *Store) CreateValues(ctx context.Context, v *values.Values) error {
	if err := claimTenant(ctx, &v.TenantID); err != nil {
		return err
	}
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
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	m := new(valuesModel)
	err := s.pgdb.NewSelect(m).Where("id = ?", vID.String()).Where("tenant_id = ?", tenant).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrValueNotFound, "get values")
	}
	return valuesFromModel(m), nil
}

func (s *Store) GetValuesByName(ctx context.Context, appID, name string) (*values.Values, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	m := new(valuesModel)
	err := s.pgdb.NewSelect(m).
		Where("app_id = ?", appID).
		Where("tenant_id = ?", tenant).
		Where("name = ?", name).
		Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrValueNotFound, "get values by name")
	}
	return valuesFromModel(m), nil
}

func (s *Store) UpdateValues(ctx context.Context, v *values.Values) error {
	if err := claimTenant(ctx, &v.TenantID); err != nil {
		return err
	}
	v.UpdatedAt = now()
	m := valuesToModel(v)
	res, err := s.pgdb.NewUpdate(m).WherePK().Where("tenant_id = ?", v.TenantID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: update values: %w", err)
	}
	return updatedOrNotFound(res, shield.ErrValueNotFound, "update values")
}

func (s *Store) DeleteValues(ctx context.Context, vID id.ValueID) error {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return tenantErr
	}
	_, err := s.pgdb.NewDelete((*valuesModel)(nil)).Where("id = ?", vID.String()).Where("tenant_id = ?", tenant).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: delete values: %w", err)
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
	q := s.pgdb.NewSelect(&models).Where("tenant_id = ?", tenant).OrderExpr("created_at ASC")
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
		return nil, fmt.Errorf("shield/postgres: list values: %w", err)
	}
	result := make([]*values.Values, len(models))
	for i := range models {
		result[i] = valuesFromModel(&models[i])
	}
	return result, nil
}
