package postgres

import (
	"context"
	"fmt"

	"github.com/xraph/shield"
	"github.com/xraph/shield/id"
	"github.com/xraph/shield/judgment"
)

func (s *Store) CreateJudgment(ctx context.Context, j *judgment.Judgment) error {
	n := now()
	j.CreatedAt = n
	j.UpdatedAt = n
	m := judgmentToModel(j)
	_, err := s.pgdb.NewInsert(m).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: create judgment: %w", err)
	}
	return nil
}

func (s *Store) GetJudgment(ctx context.Context, jID id.JudgmentID) (*judgment.Judgment, error) {
	m := new(judgmentModel)
	err := s.pgdb.NewSelect(m).Where("id = ?", jID.String()).Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrJudgmentNotFound, "get judgment")
	}
	return judgmentFromModel(m), nil
}

func (s *Store) GetJudgmentByName(ctx context.Context, appID, name string) (*judgment.Judgment, error) {
	m := new(judgmentModel)
	err := s.pgdb.NewSelect(m).
		Where("app_id = ?", appID).
		Where("name = ?", name).
		Scan(ctx)
	if err != nil {
		return nil, notFoundOrWrap(err, shield.ErrJudgmentNotFound, "get judgment by name")
	}
	return judgmentFromModel(m), nil
}

func (s *Store) UpdateJudgment(ctx context.Context, j *judgment.Judgment) error {
	j.UpdatedAt = now()
	m := judgmentToModel(j)
	_, err := s.pgdb.NewUpdate(m).WherePK().Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: update judgment: %w", err)
	}
	return nil
}

func (s *Store) DeleteJudgment(ctx context.Context, jID id.JudgmentID) error {
	_, err := s.pgdb.NewDelete((*judgmentModel)(nil)).Where("id = ?", jID.String()).Exec(ctx)
	if err != nil {
		return fmt.Errorf("shield/postgres: delete judgment: %w", err)
	}
	return nil
}

func (s *Store) ListJudgments(ctx context.Context, filter *judgment.ListFilter) ([]*judgment.Judgment, error) {
	var models []judgmentModel
	q := s.pgdb.NewSelect(&models).OrderExpr("created_at ASC")
	if filter != nil {
		if filter.AppID != "" {
			q = q.Where("app_id = ?", filter.AppID)
		}
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
		}
		if filter.Domain != "" {
			q = q.Where("domain = ?", string(filter.Domain))
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
		return nil, fmt.Errorf("shield/postgres: list judgments: %w", err)
	}
	result := make([]*judgment.Judgment, len(models))
	for i := range models {
		result[i] = judgmentFromModel(&models[i])
	}
	return result, nil
}
