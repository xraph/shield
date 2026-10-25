package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/xraph/shield/id"
	"github.com/xraph/shield/pii"
	"github.com/xraph/shield/store"
)

func (s *Store) StorePIITokens(ctx context.Context, tokens []*pii.Token) error {
	if len(tokens) == 0 {
		return nil
	}
	n := now()
	models := make([]piiTokenModel, len(tokens))
	for i, t := range tokens {
		if err := claimTenant(ctx, &t.TenantID); err != nil {
			return err
		}
		t.CreatedAt = n
		t.UpdatedAt = n
		models[i] = *piiTokenToModel(t)
	}
	_, err := s.pgdb.NewInsert(&models).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: store pii tokens: %w", err)
	}
	return nil
}

func (s *Store) LoadPIITokens(ctx context.Context, tokenIDs []id.PIITokenID) ([]*pii.Token, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	if len(tokenIDs) == 0 {
		return nil, nil
	}
	ids := make([]string, len(tokenIDs))
	for i, tid := range tokenIDs {
		ids[i] = tid.String()
	}
	var models []piiTokenModel
	clause, args := whereIn("id", ids)
	err := s.pgdb.NewSelect(&models).Where(clause, args...).Where("tenant_id = ?", tenant).Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("shield/postgres: load pii tokens: %w", err)
	}
	result := make([]*pii.Token, len(models))
	for i := range models {
		result[i] = piiTokenFromModel(&models[i])
	}
	return result, nil
}

func (s *Store) LoadPIITokensByScan(ctx context.Context, scanID id.ScanID) ([]*pii.Token, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	var models []piiTokenModel
	err := s.pgdb.NewSelect(&models).
		Where("scan_id = ?", scanID.String()).
		Where("tenant_id = ?", tenant).
		OrderExpr("created_at ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("shield/postgres: load pii tokens by scan: %w", err)
	}
	result := make([]*pii.Token, len(models))
	for i := range models {
		result[i] = piiTokenFromModel(&models[i])
	}
	return result, nil
}

func (s *Store) DeletePIITokens(ctx context.Context, tokenIDs []id.PIITokenID) error {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return tenantErr
	}
	if len(tokenIDs) == 0 {
		return nil
	}
	ids := make([]string, len(tokenIDs))
	for i, tid := range tokenIDs {
		ids[i] = tid.String()
	}
	clause, args := whereIn("id", ids)
	_, err := s.pgdb.NewDelete((*piiTokenModel)(nil)).Where(clause, args...).Where("tenant_id = ?", tenant).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: delete pii tokens: %w", err)
	}
	return nil
}

func (s *Store) DeletePIITokensByTenant(ctx context.Context, tenantID string) error {
	tenant, err := store.Tenant(ctx, tenantID)
	if err != nil {
		return err
	}
	_, err = s.pgdb.NewDelete((*piiTokenModel)(nil)).Where("tenant_id = ?", tenant).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: delete pii tokens by tenant: %w", err)
	}
	return nil
}

// PurgePIITokens is an operator retention sweep: it removes expired tokens in
// every tenant and so takes no tenant.
func (s *Store) PurgePIITokens(ctx context.Context, olderThan time.Time) (int64, error) {
	res, err := s.pgdb.NewDelete((*piiTokenModel)(nil)).
		Where("expires_at IS NOT NULL").
		Where("expires_at < ?", olderThan).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("shield/postgres: purge pii tokens: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("shield/postgres: purge pii tokens rows affected: %w", err)
	}
	return rows, nil
}

func (s *Store) PIIStats(ctx context.Context, tenantID string) (*pii.Stats, error) {
	tenant, tenantErr := store.Tenant(ctx, tenantID)
	if tenantErr != nil {
		return nil, tenantErr
	}
	var models []piiTokenModel
	if err := s.pgdb.NewSelect(&models).Where("tenant_id = ?", tenant).Scan(ctx); err != nil {
		if isNoRows(err) {
			return &pii.Stats{
				ByType:   make(map[string]int64),
				ByTenant: make(map[string]int64),
			}, nil
		}
		return nil, fmt.Errorf("shield/postgres: pii stats: %w", err)
	}

	stats := &pii.Stats{
		TotalTokens: int64(len(models)),
		ByType:      make(map[string]int64),
		ByTenant:    make(map[string]int64),
	}
	for i := range models {
		stats.ByType[models[i].PIIType]++
		stats.ByTenant[models[i].TenantID]++
	}
	return stats, nil
}
