package postgres

import (
	"context"
	"fmt"

	"github.com/xraph/shield"
	"github.com/xraph/shield/id"
	"github.com/xraph/shield/profile"
	"github.com/xraph/shield/store"
)

func (s *Store) CreateProfile(ctx context.Context, p *profile.SafetyProfile) error {
	if err := claimTenant(ctx, &p.TenantID); err != nil {
		return err
	}
	n := now()
	p.CreatedAt = n
	p.UpdatedAt = n
	m := profileToModel(p)
	_, err := s.pgdb.NewInsert(m).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: create profile: %w", err)
	}
	return nil
}

func (s *Store) GetProfile(ctx context.Context, pID id.SafetyProfileID) (*profile.SafetyProfile, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	m := new(profileModel)
	err := s.pgdb.NewSelect(m).Where("id = ?", pID.String()).Where("tenant_id = ?", tenant).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrProfileNotFound, "get profile")
	}
	return profileFromModel(m), nil
}

func (s *Store) GetProfileByName(ctx context.Context, appID, name string) (*profile.SafetyProfile, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	m := new(profileModel)
	err := s.pgdb.NewSelect(m).
		Where("app_id = ?", appID).
		Where("tenant_id = ?", tenant).
		Where("name = ?", name).
		Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrProfileNotFound, "get profile by name")
	}
	return profileFromModel(m), nil
}

func (s *Store) UpdateProfile(ctx context.Context, p *profile.SafetyProfile) error {
	if err := claimTenant(ctx, &p.TenantID); err != nil {
		return err
	}
	p.UpdatedAt = now()
	m := profileToModel(p)
	res, err := s.pgdb.NewUpdate(m).WherePK().Where("tenant_id = ?", p.TenantID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: update profile: %w", err)
	}
	return updatedOrNotFound(res, shield.ErrProfileNotFound, "update profile")
}

func (s *Store) DeleteProfile(ctx context.Context, pID id.SafetyProfileID) error {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return tenantErr
	}
	_, err := s.pgdb.NewDelete((*profileModel)(nil)).Where("id = ?", pID.String()).Where("tenant_id = ?", tenant).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: delete profile: %w", err)
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
		return nil, fmt.Errorf("shield/postgres: list profiles: %w", err)
	}
	result := make([]*profile.SafetyProfile, len(models))
	for i := range models {
		result[i] = profileFromModel(&models[i])
	}
	return result, nil
}
