package postgres

import (
	"context"
	"fmt"

	"github.com/xraph/grove"

	"github.com/xraph/shield"
	"github.com/xraph/shield/id"
	"github.com/xraph/shield/scan"
	"github.com/xraph/shield/store"
)

func (s *Store) CreateScan(ctx context.Context, result *scan.Result) error {
	if err := claimTenant(ctx, &result.TenantID); err != nil {
		return err
	}
	n := now()
	result.CreatedAt = n
	result.UpdatedAt = n
	m := scanToModel(result)
	_, err := s.pgdb.NewInsert(m).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: create scan: %w", err)
	}
	return nil
}

func (s *Store) GetScan(ctx context.Context, scanID id.ScanID) (*scan.Result, error) {
	tenant, tenantErr := store.Tenant(ctx, "")
	if tenantErr != nil {
		return nil, tenantErr
	}
	m := new(scanModel)
	err := s.pgdb.NewSelect(m).Where("id = ?", scanID.String()).Where("tenant_id = ?", tenant).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrScanNotFound, "get scan")
	}
	return scanFromModel(m), nil
}

func (s *Store) ListScans(ctx context.Context, filter *scan.ListFilter) ([]*scan.Result, error) {
	var want string
	if filter != nil {
		want = filter.TenantID
	}
	tenant, tenantErr := store.Tenant(ctx, want)
	if tenantErr != nil {
		return nil, tenantErr
	}
	var models []scanModel
	q := s.pgdb.NewSelect(&models).Where("tenant_id = ?", tenant).OrderExpr("created_at DESC")
	if filter != nil {
		if filter.AppID != "" {
			q = q.Where("app_id = ?", filter.AppID)
		}
		if filter.Direction != "" {
			q = q.Where("direction = ?", string(filter.Direction))
		}
		if filter.Decision != "" {
			q = q.Where("decision = ?", string(filter.Decision))
		}
		if filter.Limit > 0 {
			q = q.Limit(filter.Limit)
		}
		if filter.Offset > 0 {
			q = q.Offset(filter.Offset)
		}
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("shield/postgres: list scans: %w", err)
	}
	result := make([]*scan.Result, len(models))
	for i := range models {
		result[i] = scanFromModel(&models[i])
	}
	return result, nil
}

func (s *Store) ScanStats(ctx context.Context, filter *scan.StatsFilter) (*scan.Stats, error) {
	var want string
	if filter != nil {
		want = filter.TenantID
	}
	tenant, tenantErr := store.Tenant(ctx, want)
	if tenantErr != nil {
		return nil, tenantErr
	}
	// Fetch direction+decision counts via GROUP BY. The row type names its own
	// table: scanning these rows through scanModel's fields panics in grove.
	var rows []struct {
		grove.BaseModel `grove:"table:shield_scans"`
		Direction       string `grove:"direction"`
		Decision        string `grove:"decision"`
		Count           int64  `grove:"count"`
	}
	q := s.pgdb.NewSelect(&rows).
		ColumnExpr("direction").
		ColumnExpr("decision").
		ColumnExpr("COUNT(*) AS count").
		Where("tenant_id = ?", tenant).
		GroupExpr("direction, decision")

	if filter != nil {
		if filter.AppID != "" {
			q = q.Where("app_id = ?", filter.AppID)
		}
		if filter.From != "" {
			q = q.Where("created_at >= ?", filter.From)
		}
		if filter.To != "" {
			q = q.Where("created_at <= ?", filter.To)
		}
	}

	if err := q.Scan(ctx); err != nil {
		if isNoRows(err) {
			return emptyScanStats(), nil
		}
		return nil, fmt.Errorf("shield/postgres: scan stats: %w", err)
	}

	stats := emptyScanStats()
	for _, r := range rows {
		stats.TotalScans += r.Count
		stats.ByDirection[r.Direction] += r.Count
		stats.ByDecision[r.Decision] += r.Count

		switch scan.Decision(r.Decision) {
		case scan.DecisionBlock:
			stats.BlockedCount += r.Count
		case scan.DecisionFlag:
			stats.FlaggedCount += r.Count
		case scan.DecisionAllow:
			stats.AllowedCount += r.Count
		}
	}
	return stats, nil
}

func emptyScanStats() *scan.Stats {
	return &scan.Stats{
		ByDirection: make(map[string]int64),
		ByDecision:  make(map[string]int64),
	}
}
