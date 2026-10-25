package postgres

import (
	"context"
	"fmt"

	"github.com/xraph/shield"
	"github.com/xraph/shield/boundary"
	"github.com/xraph/shield/id"
	"github.com/xraph/shield/store"
)

func (s *Store) CreateBoundary(ctx context.Context, b *boundary.Boundary) error {
	if err := claimTenant(ctx, &b.TenantID); err != nil {
		return err
	}
	n := now()
	b.CreatedAt = n
	b.UpdatedAt = n
	m := boundaryToModel(b)
	_, err := s.pgdb.NewInsert(m).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: create boundary: %w", err)
	}
	return nil
}

func (s *Store) GetBoundary(ctx context.Context, bID id.BoundaryID) (*boundary.Boundary, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	m := new(boundaryModel)
	err := s.pgdb.NewSelect(m).Where("id = ?", bID.String()).Where("tenant_id = ?", tenant).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrBoundaryNotFound, "get boundary")
	}
	return boundaryFromModel(m), nil
}

func (s *Store) GetBoundaryByName(ctx context.Context, appID, name string) (*boundary.Boundary, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	m := new(boundaryModel)
	err := s.pgdb.NewSelect(m).
		Where("app_id = ?", appID).
		Where("tenant_id = ?", tenant).
		Where("name = ?", name).
		Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrBoundaryNotFound, "get boundary by name")
	}
	return boundaryFromModel(m), nil
}

func (s *Store) UpdateBoundary(ctx context.Context, b *boundary.Boundary) error {
	if err := claimTenant(ctx, &b.TenantID); err != nil {
		return err
	}
	b.UpdatedAt = now()
	m := boundaryToModel(b)
	res, err := s.pgdb.NewUpdate(m).WherePK().Where("tenant_id = ?", b.TenantID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: update boundary: %w", err)
	}
	return updatedOrNotFound(res, shield.ErrBoundaryNotFound, "update boundary")
}

func (s *Store) DeleteBoundary(ctx context.Context, bID id.BoundaryID) error {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return tenantErr
	}
	_, err := s.pgdb.NewDelete((*boundaryModel)(nil)).Where("id = ?", bID.String()).Where("tenant_id = ?", tenant).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: delete boundary: %w", err)
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
	q := s.pgdb.NewSelect(&models).Where("tenant_id = ?", tenant).OrderExpr("created_at ASC")
	if filter != nil {
		if filter.AppID != "" {
			q = q.Where("app_id = ?", filter.AppID)
		}
		if filter.Scope != "" {
			q = q.Where("EXISTS (SELECT 1 FROM jsonb_array_elements(limits) AS l WHERE l->>'scope' = ?)", string(filter.Scope))
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
		return nil, fmt.Errorf("shield/postgres: list boundaries: %w", err)
	}
	result := make([]*boundary.Boundary, len(models))
	for i := range models {
		result[i] = boundaryFromModel(&models[i])
	}
	return result, nil
}
