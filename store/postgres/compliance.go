package postgres

import (
	"context"
	"fmt"

	"github.com/xraph/shield"
	"github.com/xraph/shield/compliance"
	"github.com/xraph/shield/id"
)

func (s *Store) CreateReport(ctx context.Context, report *compliance.Report) error {
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
	return complianceFromModel(m), nil
}

func (s *Store) ListReports(ctx context.Context, filter *compliance.ListFilter) ([]*compliance.Report, error) {
	var models []complianceReportModel
	q := s.pgdb.NewSelect(&models).OrderExpr("generated_at DESC")
	if filter != nil {
		if filter.ScopeKey != "" {
			q = q.Where("scope_key = ?", filter.ScopeKey)
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
