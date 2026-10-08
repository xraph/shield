package mongo

import (
	"context"
	"encoding/json"
	"github.com/xraph/grove"
	"github.com/xraph/shield/id"
	"github.com/xraph/shield/store"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
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
	filt := bson.M{"tenant_id": scope.TenantID}
	if scanID != "" {
		filt["scan_id"] = scanID
	}
	if cutoff != nil {
		filt["expires_at"] = bson.M{"$lte": *cutoff}
	}
	coll := s.mdb.Collection("shield_pii_tokens")
	total, err := coll.CountDocuments(ctx, filt)
	if err != nil {
		return store.Page{}, err
	}
	cur, err := coll.Find(ctx, filt, options.Find().SetProjection(bson.M{"encrypted_value": 0}).SetSort(bson.D{{Key: "created_at", Value: 1}, {Key: "_id", Value: 1}}).SetLimit(int64(f.Limit)).SetSkip(int64(f.Offset)))
	if err != nil {
		return store.Page{}, err
	}
	defer cur.Close(ctx)
	err = cur.All(ctx, &rows)
	if err != nil {
		return store.Page{}, err
	}
	page := store.Page{RefreshedAt: time.Now().UTC(), Items: []json.RawMessage{}, Total: total, Limit: f.Limit, Offset: f.Offset}
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
	res, err := s.mdb.Collection("shield_pii_tokens").DeleteMany(ctx, bson.M{"tenant_id": scope.TenantID, "expires_at": bson.M{"$lte": cutoff}, "_id": bson.M{"$in": keys}})
	if err != nil {
		return 0, err
	}
	return res.DeletedCount, nil
}
