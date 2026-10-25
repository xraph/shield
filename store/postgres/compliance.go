package postgres

import (
	"context"
	"fmt"

	"github.com/xraph/shield"
	"github.com/xraph/shield/compliance"
	"github.com/xraph/shield/id"
	"github.com/xraph/shield/store"
)

func (s *Store) CreateReport(ctx context.Context, report *compliance.Report) error {
	if _, err := store.ScopeLevels(ctx, report.ScopeKey, report.ScopeLevel); err != nil {
		return err
	}
	n := now()
	report.CreatedAt = n
	report.UpdatedAt = n
	m := complianceToModel(report)
	_, err := s.pgdb.NewInsert(m).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: create compliance report: %w", err)
	}
	return nil
}

func (s *Store) GetReport(ctx context.Context, reportID id.ComplianceReportID) (*compliance.Report, error) {
	m := new(complianceReportModel)
	err := s.pgdb.NewSelect(m).Where("id = ?", reportID.String()).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrComplianceNotFound, "get compliance report")
	}
	if !store.ScopeVisible(ctx, m.ScopeKey, m.ScopeLevel) {
		return nil, shield.ErrComplianceNotFound
	}
	return complianceFromModel(m), nil
}

func (s *Store) ListReports(ctx context.Context, filter *compliance.ListFilter) ([]*compliance.Report, error) {
	if filter == nil {
		return nil, shield.ErrTenantRequired
	}
	levels, levelErr := store.ScopeLevels(ctx, filter.ScopeKey, "")
	if levelErr != nil {
		return nil, levelErr
	}
	var models []complianceReportModel
	q := s.pgdb.NewSelect(&models).Where("scope_key = ?", filter.ScopeKey).OrderExpr("generated_at DESC")
	if levels != nil {
		clause, args := whereIn("scope_level", levels)
		q = q.Where(clause, args...)
	}
	if filter.Framework != "" {
		q = q.Where("framework = ?", string(filter.Framework))
	}
	if filter.Limit > 0 {
		q = q.Limit(filter.Limit)
	}
	if filter.Offset > 0 {
		q = q.Offset(filter.Offset)
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("shield/postgres: list compliance reports: %w", err)
	}
	result := make([]*compliance.Report, len(models))
	for i := range models {
		result[i] = complianceFromModel(&models[i])
	}
	return result, nil
}
