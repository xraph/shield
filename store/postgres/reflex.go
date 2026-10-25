package postgres

import (
	"context"
	"fmt"

	"github.com/xraph/shield"
	"github.com/xraph/shield/id"
	"github.com/xraph/shield/reflex"
	"github.com/xraph/shield/store"
)

func (s *Store) CreateReflex(ctx context.Context, r *reflex.Reflex) error {
	if err := claimTenant(ctx, &r.TenantID); err != nil {
		return err
	}
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
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	m := new(reflexModel)
	err := s.pgdb.NewSelect(m).Where("id = ?", rID.String()).Where("tenant_id = ?", tenant).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrReflexNotFound, "get reflex")
	}
	return reflexFromModel(m), nil
}

func (s *Store) GetReflexByName(ctx context.Context, appID, name string) (*reflex.Reflex, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	m := new(reflexModel)
	err := s.pgdb.NewSelect(m).
		Where("app_id = ?", appID).
		Where("tenant_id = ?", tenant).
		Where("name = ?", name).
		Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrReflexNotFound, "get reflex by name")
	}
	return reflexFromModel(m), nil
}

func (s *Store) UpdateReflex(ctx context.Context, r *reflex.Reflex) error {
	if err := claimTenant(ctx, &r.TenantID); err != nil {
		return err
	}
	r.UpdatedAt = now()
	m := reflexToModel(r)
	res, err := s.pgdb.NewUpdate(m).WherePK().Where("tenant_id = ?", r.TenantID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: update reflex: %w", err)
	}
	return updatedOrNotFound(res, shield.ErrReflexNotFound, "update reflex")
}

func (s *Store) DeleteReflex(ctx context.Context, rID id.ReflexID) error {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return tenantErr
	}
	_, err := s.pgdb.NewDelete((*reflexModel)(nil)).Where("id = ?", rID.String()).Where("tenant_id = ?", tenant).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: delete reflex: %w", err)
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
		return nil, fmt.Errorf("shield/postgres: list reflexes: %w", err)
	}
	result := make([]*reflex.Reflex, len(models))
	for i := range models {
		result[i] = reflexFromModel(&models[i])
	}
	return result, nil
}
