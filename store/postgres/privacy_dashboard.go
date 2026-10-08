package postgres

import (
	"context"
	"encoding/json"
	"github.com/xraph/grove"
	"github.com/xraph/shield/id"
	"github.com/xraph/shield/store"
	"time"
)

type dashboardTokenModel struct {
	grove.BaseModel `grove:"table:shield_pii_tokens"`
	ID              string     `grove:"id" json:"id" bson:"_id"`
	ScanID          string     `grove:"scan_id" json:"scan_id" bson:"scan_id"`
	TenantID        string     `grove:"tenant_id" json:"tenant_id" bson:"tenant_id"`
	PIIType         string     `grove:"pii_type" json:"pii_type" bson:"pii_type"`
	Placeholder     string     `grove:"placeholder" json:"placeholder" bson:"placeholder"`
	ExpiresAt       *time.Time `grove:"expires_at" json:"expires_at" bson:"expires_at"`
	CreatedAt       time.Time  `grove:"created_at" json:"created_at" bson:"created_at"`
}

func (s *Store) DashboardTokens(ctx context.Context, scope store.Scope, scanID string, cutoff *time.Time, f store.Filter) (store.Page, error) {
	if err := scope.Validate(); err != nil {
		return store.Page{}, err
	}
	if err := f.Validate(); err != nil {
		return store.Page{}, err
	}
	if f.Limit == 0 {
		f.Limit = 25
	}
	if scanID != "" {
		if _, err := s.DashboardGet(ctx, scope, "scans", scanID); err != nil {
			return store.Page{}, err
		}
	}
	var rows []dashboardTokenModel
	q := s.pgdb.NewSelect(&rows).Where("tenant_id = ?", scope.TenantID)
	if scanID != "" {
		q = q.Where("scan_id = ?", scanID)
	}
	if cutoff != nil {
		q = q.Where("expires_at <= ?", *cutoff)
	}
	total, err := q.Count(ctx)
	if err != nil {
		return store.Page{}, err
	}
	err = q.OrderExpr("created_at ASC, id ASC").Limit(f.Limit).Offset(f.Offset).Scan(ctx)
	if err != nil {
		return store.Page{}, err
	}
	page := store.Page{Items: []json.RawMessage{}, Total: total, Limit: f.Limit, Offset: f.Offset}
	for _, row := range rows {
		raw, err := json.Marshal(row)
		if err != nil {
			return store.Page{}, err
		}
		page.Items = append(page.Items, raw)
	}
	page.HasMore = int64(f.Offset+len(rows)) < total
	return page, nil
}
func (s *Store) DashboardDeleteTokens(ctx context.Context, scope store.Scope, cutoff time.Time, keys []string) (int64, error) {
	if err := store.ValidateRetention(scope, cutoff, keys); err != nil {
		return 0, err
	}
	for _, key := range keys {
		if _, err := id.ParsePIITokenID(key); err != nil {
			return 0, err
		}
	}
	q := s.pgdb.NewDelete((*dashboardTokenModel)(nil)).Where("tenant_id = ?", scope.TenantID).Where("expires_at <= ?", cutoff)
	placeholders := ""
	args := make([]any, len(keys))
	for i, key := range keys {
		if i > 0 {
			placeholders += ","
		}
		placeholders += "?"
		args[i] = key
	}
	res, err := q.Where("id IN ("+placeholders+")", args...).Exec(ctx)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
