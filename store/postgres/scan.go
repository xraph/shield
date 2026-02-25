package postgres

import (
	"context"
	"fmt"

	"github.com/xraph/shield"
	"github.com/xraph/shield/id"
	"github.com/xraph/shield/scan"
)

func (s *Store) CreateScan(ctx context.Context, result *scan.Result) error {
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
	m := new(scanModel)
	err := s.pgdb.NewSelect(m).Where("id = ?", scanID.String()).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrScanNotFound, "get scan")
	}
	return scanFromModel(m), nil
}

func (s *Store) ListScans(ctx context.Context, filter *scan.ListFilter) ([]*scan.Result, error) {
	var models []scanModel
	q := s.pgdb.NewSelect(&models).OrderExpr("created_at DESC")
	if filter != nil {
		if filter.AppID != "" {
			q = q.Where("app_id = ?", filter.AppID)
		}
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
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
	// Use list-style query approach: fetch direction+decision counts via GROUP BY.
	type statsRow struct {
		Direction string `grove:"direction"`
		Decision  string `grove:"decision"`
		Count     int64  `grove:"count"`
	}

	q := s.pgdb.NewSelect((*scanModel)(nil)).
		ColumnExpr("direction").
		ColumnExpr("decision").
		ColumnExpr("COUNT(*) AS count").
		GroupExpr("direction, decision")

	if filter != nil {
		if filter.AppID != "" {
			q = q.Where("app_id = ?", filter.AppID)
		}
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
		}
		if filter.From != "" {
			q = q.Where("created_at >= ?", filter.From)
		}
		if filter.To != "" {
			q = q.Where("created_at <= ?", filter.To)
		}
	}

	var rows []statsRow
	if err := q.Scan(ctx, &rows); err != nil {
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
