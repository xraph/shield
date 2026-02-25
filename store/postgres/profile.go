package postgres

import (
	"context"
	"fmt"

	"github.com/xraph/shield"
	"github.com/xraph/shield/id"
	"github.com/xraph/shield/profile"
)

func (s *Store) CreateProfile(ctx context.Context, p *profile.SafetyProfile) error {
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
	m := new(profileModel)
	err := s.pgdb.NewSelect(m).Where("id = ?", pID.String()).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrProfileNotFound, "get profile")
	}
	return profileFromModel(m), nil
}

func (s *Store) GetProfileByName(ctx context.Context, appID, name string) (*profile.SafetyProfile, error) {
	m := new(profileModel)
	err := s.pgdb.NewSelect(m).
		Where("app_id = ?", appID).
		Where("name = ?", name).
		Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrProfileNotFound, "get profile by name")
	}
	return profileFromModel(m), nil
}

func (s *Store) UpdateProfile(ctx context.Context, p *profile.SafetyProfile) error {
	p.UpdatedAt = now()
	m := profileToModel(p)
	_, err := s.pgdb.NewUpdate(m).WherePK().Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: update profile: %w", err)
	}
	return nil
}

func (s *Store) DeleteProfile(ctx context.Context, pID id.SafetyProfileID) error {
	_, err := s.pgdb.NewDelete((*profileModel)(nil)).Where("id = ?", pID.String()).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: delete profile: %w", err)
	}
	return nil
}

func (s *Store) ListProfiles(ctx context.Context, filter *profile.ListFilter) ([]*profile.SafetyProfile, error) {
	var models []profileModel
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
		return nil, fmt.Errorf("shield/postgres: list profiles: %w", err)
	}
	result := make([]*profile.SafetyProfile, len(models))
	for i := range models {
		result[i] = profileFromModel(&models[i])
	}
	return result, nil
}
