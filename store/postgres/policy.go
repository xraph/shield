package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/xraph/shield"
	"github.com/xraph/shield/id"
	"github.com/xraph/shield/policy"
)

func (s *Store) CreatePolicy(ctx context.Context, pol *policy.Policy) error {
	n := now()
	pol.CreatedAt = n
	pol.UpdatedAt = n
	m := policyToModel(pol)
	_, err := s.pgdb.NewInsert(m).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: create policy: %w", err)
	}
	return nil
}

func (s *Store) GetPolicy(ctx context.Context, polID id.PolicyID) (*policy.Policy, error) {
	m := new(policyModel)
	err := s.pgdb.NewSelect(m).Where("id = ?", polID.String()).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrPolicyNotFound, "get policy")
	}
	return policyFromModel(m), nil
}

func (s *Store) GetPolicyByName(ctx context.Context, scopeKey, name string) (*policy.Policy, error) {
	m := new(policyModel)
	err := s.pgdb.NewSelect(m).
		Where("scope_key = ?", scopeKey).
		Where("name = ?", name).
		Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrPolicyNotFound, "get policy by name")
	}
	return policyFromModel(m), nil
}

func (s *Store) UpdatePolicy(ctx context.Context, pol *policy.Policy) error {
	pol.UpdatedAt = now()
	m := policyToModel(pol)
	_, err := s.pgdb.NewUpdate(m).WherePK().Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: update policy: %w", err)
	}
	return nil
}

func (s *Store) DeletePolicy(ctx context.Context, polID id.PolicyID) error {
	_, err := s.pgdb.NewDelete((*policyModel)(nil)).Where("id = ?", polID.String()).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: delete policy: %w", err)
	}
	return nil
}

func (s *Store) ListPolicies(ctx context.Context, filter *policy.ListFilter) ([]*policy.Policy, error) {
	var models []policyModel
	q := s.pgdb.NewSelect(&models).OrderExpr("created_at ASC")
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
		return nil, fmt.Errorf("shield/postgres: list policies: %w", err)
	}
	result := make([]*policy.Policy, len(models))
	for i := range models {
		result[i] = policyFromModel(&models[i])
	}
	return result, nil
}

func (s *Store) GetPoliciesForScope(ctx context.Context, scopeKey string, level policy.ScopeLevel) ([]*policy.Policy, error) {
	var models []policyModel
	err := s.pgdb.NewSelect(&models).
		Where("scope_key = ?", scopeKey).
		Where("scope_level = ?", string(level)).
		Where("enabled = ?", true).
		OrderExpr("created_at ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("shield/postgres: get policies for scope: %w", err)
	}
	result := make([]*policy.Policy, len(models))
	for i := range models {
		result[i] = policyFromModel(&models[i])
	}
	return result, nil
}

func (s *Store) AssignToTenant(ctx context.Context, tenantID string, polID id.PolicyID) error {
	m := &policyTenantModel{
		TenantID:  tenantID,
		PolicyID:  polID.String(),
		CreatedAt: time.Now().UTC(),
	}
	_, err := s.pgdb.NewInsert(m).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: assign policy to tenant: %w", err)
	}
	return nil
}

func (s *Store) UnassignFromTenant(ctx context.Context, tenantID string, polID id.PolicyID) error {
	_, err := s.pgdb.NewDelete((*policyTenantModel)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("policy_id = ?", polID.String()).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: unassign policy from tenant: %w", err)
	}
	return nil
}
