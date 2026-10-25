package postgres

import (
	"context"
	"fmt"

	"github.com/xraph/shield"
	"github.com/xraph/shield/awareness"
	"github.com/xraph/shield/id"
	"github.com/xraph/shield/store"
)

func (s *Store) CreateAwareness(ctx context.Context, a *awareness.Awareness) error {
	if err := claimTenant(ctx, &a.TenantID); err != nil {
		return err
	}
	n := now()
	a.CreatedAt = n
	a.UpdatedAt = n
	m := awarenessToModel(a)
	_, err := s.pgdb.NewInsert(m).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: create awareness: %w", err)
	}
	return nil
}

func (s *Store) GetAwareness(ctx context.Context, aID id.AwarenessID) (*awareness.Awareness, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	m := new(awarenessModel)
	err := s.pgdb.NewSelect(m).Where("id = ?", aID.String()).Where("tenant_id = ?", tenant).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrAwarenessNotFound, "get awareness")
	}
	return awarenessFromModel(m), nil
}

func (s *Store) GetAwarenessByName(ctx context.Context, appID, name string) (*awareness.Awareness, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	m := new(awarenessModel)
	err := s.pgdb.NewSelect(m).
		Where("app_id = ?", appID).
		Where("tenant_id = ?", tenant).
		Where("name = ?", name).
		Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrAwarenessNotFound, "get awareness by name")
	}
	return awarenessFromModel(m), nil
}

func (s *Store) UpdateAwareness(ctx context.Context, a *awareness.Awareness) error {
	if err := claimTenant(ctx, &a.TenantID); err != nil {
		return err
	}
	a.UpdatedAt = now()
	m := awarenessToModel(a)
	res, err := s.pgdb.NewUpdate(m).WherePK().Where("tenant_id = ?", a.TenantID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: update awareness: %w", err)
	}
	return updatedOrNotFound(res, shield.ErrAwarenessNotFound, "update awareness")
}

func (s *Store) DeleteAwareness(ctx context.Context, aID id.AwarenessID) error {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return tenantErr
	}
	_, err := s.pgdb.NewDelete((*awarenessModel)(nil)).Where("id = ?", aID.String()).Where("tenant_id = ?", tenant).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: delete awareness: %w", err)
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
	q := s.pgdb.NewSelect(&models).Where("tenant_id = ?", tenant).OrderExpr("created_at ASC")
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
		return nil, fmt.Errorf("shield/postgres: list awareness: %w", err)
	}
	result := make([]*awareness.Awareness, len(models))
	for i := range models {
		result[i] = awarenessFromModel(&models[i])
	}
	return result, nil
}
