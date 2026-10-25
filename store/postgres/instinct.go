package postgres

import (
	"context"
	"fmt"

	"github.com/xraph/shield"
	"github.com/xraph/shield/id"
	"github.com/xraph/shield/instinct"
	"github.com/xraph/shield/store"
)

func (s *Store) CreateInstinct(ctx context.Context, inst *instinct.Instinct) error {
	if err := claimTenant(ctx, &inst.TenantID); err != nil {
		return err
	}
	n := now()
	inst.CreatedAt = n
	inst.UpdatedAt = n
	m := instinctToModel(inst)
	_, err := s.pgdb.NewInsert(m).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: create instinct: %w", err)
	}
	return nil
}

func (s *Store) GetInstinct(ctx context.Context, instID id.InstinctID) (*instinct.Instinct, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	m := new(instinctModel)
	err := s.pgdb.NewSelect(m).Where("id = ?", instID.String()).Where("tenant_id = ?", tenant).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrInstinctNotFound, "get instinct")
	}
	return instinctFromModel(m), nil
}

func (s *Store) GetInstinctByName(ctx context.Context, appID, name string) (*instinct.Instinct, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	m := new(instinctModel)
	err := s.pgdb.NewSelect(m).
		Where("app_id = ?", appID).
		Where("tenant_id = ?", tenant).
		Where("name = ?", name).
		Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrInstinctNotFound, "get instinct by name")
	}
	return instinctFromModel(m), nil
}

func (s *Store) UpdateInstinct(ctx context.Context, inst *instinct.Instinct) error {
	if err := claimTenant(ctx, &inst.TenantID); err != nil {
		return err
	}
	inst.UpdatedAt = now()
	m := instinctToModel(inst)
	res, err := s.pgdb.NewUpdate(m).WherePK().Where("tenant_id = ?", inst.TenantID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: update instinct: %w", err)
	}
	return updatedOrNotFound(res, shield.ErrInstinctNotFound, "update instinct")
}

func (s *Store) DeleteInstinct(ctx context.Context, instID id.InstinctID) error {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return tenantErr
	}
	_, err := s.pgdb.NewDelete((*instinctModel)(nil)).Where("id = ?", instID.String()).Where("tenant_id = ?", tenant).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: delete instinct: %w", err)
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
	q := s.pgdb.NewSelect(&models).Where("tenant_id = ?", tenant).OrderExpr("created_at ASC")
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
		return nil, fmt.Errorf("shield/postgres: list instincts: %w", err)
	}
	result := make([]*instinct.Instinct, len(models))
	for i := range models {
		result[i] = instinctFromModel(&models[i])
	}
	return result, nil
}
