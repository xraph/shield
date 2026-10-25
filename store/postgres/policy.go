package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/xraph/shield"
	"github.com/xraph/shield/id"
	"github.com/xraph/shield/policy"
	"github.com/xraph/shield/store"
)

func (s *Store) CreatePolicy(ctx context.Context, pol *policy.Policy) error {
	if _, err := store.ScopeLevels(ctx, pol.ScopeKey, string(pol.ScopeLevel)); err != nil {
		return err
	}
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
	m, err := s.visiblePolicy(ctx, polID)
	if err != nil {
		return nil, err
	}
	return policyFromModel(m), nil
}

// visiblePolicy loads a policy the context may see. A missing policy and one
// in a scope the context cannot see both return ErrPolicyNotFound.
func (s *Store) visiblePolicy(ctx context.Context, polID id.PolicyID) (*policyModel, error) {
	m := new(policyModel)
	err := s.pgdb.NewSelect(m).Where("id = ?", polID.String()).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrPolicyNotFound, "get policy")
	}
	if !store.ScopeVisible(ctx, m.ScopeKey, m.ScopeLevel) {
		return nil, shield.ErrPolicyNotFound
	}
	return m, nil
}

func (s *Store) GetPolicyByName(ctx context.Context, scopeKey, name string) (*policy.Policy, error) {
	levels, levelErr := store.ScopeLevels(ctx, scopeKey, "")
	if levelErr != nil {
		return nil, levelErr
	}
	m := new(policyModel)
	q := s.pgdb.NewSelect(m).
		Where("scope_key = ?", scopeKey).
		Where("name = ?", name)
	if levels != nil {
		clause, args := whereIn("scope_level", levels)
		q = q.Where(clause, args...)
	}
	if err := q.Scan(ctx); err != nil {
		return nil, notFoundOrWrap(err, shield.ErrPolicyNotFound, "get policy by name")
	}
	return policyFromModel(m), nil
}

func (s *Store) UpdatePolicy(ctx context.Context, pol *policy.Policy) error {
	current, err := s.visiblePolicy(ctx, pol.ID)
	if err != nil {
		return err
	}
	if !store.ScopeVisible(ctx, pol.ScopeKey, string(pol.ScopeLevel)) {
		return shield.ErrTenantMismatch
	}
	pol.UpdatedAt = now()
	m := policyToModel(pol)
	res, err := s.pgdb.NewUpdate(m).WherePK().
		Where("scope_key = ?", current.ScopeKey).
		Where("scope_level = ?", current.ScopeLevel).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: update policy: %w", err)
	}
	return updatedOrNotFound(res, shield.ErrPolicyNotFound, "update policy")
}

// DeletePolicy is idempotent: a missing policy and one the context cannot see
// both return nil, and the second is left in place.
func (s *Store) DeletePolicy(ctx context.Context, polID id.PolicyID) error {
	current, err := s.visiblePolicy(ctx, polID)
	if errors.Is(err, shield.ErrPolicyNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = s.pgdb.NewDelete((*policyModel)(nil)).
		Where("id = ?", polID.String()).
		Where("scope_key = ?", current.ScopeKey).
		Where("scope_level = ?", current.ScopeLevel).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: delete policy: %w", err)
	}
	return nil
}

func (s *Store) ListPolicies(ctx context.Context, filter *policy.ListFilter) ([]*policy.Policy, error) {
	if filter == nil {
		return nil, shield.ErrTenantRequired
	}
	levels, levelErr := store.ScopeLevels(ctx, filter.ScopeKey, string(filter.ScopeLevel))
	if levelErr != nil {
		return nil, levelErr
	}
	var models []policyModel
	q := s.pgdb.NewSelect(&models).Where("scope_key = ?", filter.ScopeKey).OrderExpr("created_at ASC")
	if levels != nil {
		clause, args := whereIn("scope_level", levels)
		q = q.Where(clause, args...)
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
	if _, err := store.ScopeLevels(ctx, scopeKey, string(level)); err != nil {
		return nil, err
	}
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
	tenant, err := store.Tenant(ctx, tenantID)
	if err != nil {
		return err
	}
	m := &policyTenantModel{
		TenantID:  tenant,
		PolicyID:  polID.String(),
		CreatedAt: time.Now().UTC(),
	}
	_, err = s.pgdb.NewInsert(m).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: assign policy to tenant: %w", err)
	}
	return nil
}

func (s *Store) UnassignFromTenant(ctx context.Context, tenantID string, polID id.PolicyID) error {
	tenant, err := store.Tenant(ctx, tenantID)
	if err != nil {
		return err
	}
	_, err = s.pgdb.NewDelete((*policyTenantModel)(nil)).
		Where("tenant_id = ?", tenant).
		Where("policy_id = ?", polID.String()).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: unassign policy from tenant: %w", err)
	}
	return nil
}
