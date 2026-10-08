package mongo

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/xraph/shield/awareness"
	"github.com/xraph/shield/boundary"
	"github.com/xraph/shield/compliance"
	"github.com/xraph/shield/id"
	"github.com/xraph/shield/instinct"
	"github.com/xraph/shield/judgment"
	"github.com/xraph/shield/policy"
	"github.com/xraph/shield/profile"
	"github.com/xraph/shield/reflex"
	"github.com/xraph/shield/scan"
	"github.com/xraph/shield/store"
	"github.com/xraph/shield/values"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"reflect"
	"regexp"
	"strings"
	"time"
)

var _ store.DashboardStore = (*Store)(nil)

func dashboardModel(kind string, raw json.RawMessage) (any, error) {
	switch kind {
	case "instincts":
		var row instinct.Instinct
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &row); err != nil {
				return nil, err
			}
		}
		return instinctToModel(&row), nil
	case "awareness":
		var row awareness.Awareness
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &row); err != nil {
				return nil, err
			}
		}
		return awarenessToModel(&row), nil
	case "boundaries":
		var row boundary.Boundary
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &row); err != nil {
				return nil, err
			}
		}
		return boundaryToModel(&row), nil
	case "values":
		var row values.Values
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &row); err != nil {
				return nil, err
			}
		}
		return valuesToModel(&row), nil
	case "judgments":
		var row judgment.Judgment
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &row); err != nil {
				return nil, err
			}
		}
		return judgmentToModel(&row), nil
	case "reflexes":
		var row reflex.Reflex
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &row); err != nil {
				return nil, err
			}
		}
		return reflexToModel(&row), nil
	case "profiles":
		var row profile.SafetyProfile
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &row); err != nil {
				return nil, err
			}
		}
		return profileToModel(&row), nil
	case "policies":
		var row policy.Policy
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &row); err != nil {
				return nil, err
			}
		}
		return policyToModel(&row), nil
	case "scans":
		var row scan.Result
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &row); err != nil {
				return nil, err
			}
		}
		return scanToModel(&row), nil
	case "compliance":
		var row compliance.Report
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &row); err != nil {
				return nil, err
			}
		}
		return complianceToModel(&row), nil
	}
	return nil, store.ErrCollection
}
func dashboardWire(model any) (json.RawMessage, error) {
	var row any
	var err error
	switch m := model.(type) {
	case *instinctModel:
		row, err = instinctFromModel(m)
	case *awarenessModel:
		row, err = awarenessFromModel(m)
	case *boundaryModel:
		row, err = boundaryFromModel(m)
	case *valuesModel:
		row, err = valuesFromModel(m)
	case *judgmentModel:
		row, err = judgmentFromModel(m)
	case *reflexModel:
		row, err = reflexFromModel(m)
	case *profileModel:
		row, err = profileFromModel(m)
	case *policyModel:
		row, err = policyFromModel(m)
	case *scanResultModel:
		row, err = scanFromModel(m)
	case *complianceReportModel:
		row, err = complianceFromModel(m)
	default:
		return nil, store.ErrCollection
	}
	if err != nil {
		return nil, err
	}
	raw, err := store.MarshalDashboard(row)
	if err != nil {
		return nil, err
	}
	var fields map[string]any
	if err = json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	if duration, ok := fields["duration"].(float64); ok {
		fields["duration_ms"] = duration / float64(time.Millisecond)
		delete(fields, "duration")
	}
	return json.Marshal(fields)
}
func dashboardPredicate(scope store.Scope, kind string) bson.M {
	if kind == "policies" || kind == "compliance" {
		key, level := scope.PolicyScope()
		return bson.M{"scope_key": key, "scope_level": level}
	}
	return bson.M{"app_id": scope.AppID, "tenant_id": scope.TenantID}
}
func dashboardCollection(kind string) string {
	if kind == "compliance" {
		return "shield_compliance_reports"
	}
	return "shield_" + kind
}
func (s *Store) DashboardList(ctx context.Context, scope store.Scope, kind string, f store.Filter) (store.Page, error) {
	if err := scope.Validate(); err != nil {
		return store.Page{}, err
	}
	if err := f.Validate(); err != nil {
		return store.Page{}, err
	}
	if f.Limit == 0 {
		f.Limit = 25
	}
	if f.Field != "" && !store.FilterColumn(kind, f.Field) {
		return store.Page{}, fmt.Errorf("invalid filter")
	}
	if f.Enabled != nil && !store.Editable(kind) {
		return store.Page{}, fmt.Errorf("invalid enabled filter")
	}
	if f.ReferenceKind != "" && (kind != "profiles" || !store.ValidReferenceKind(f.ReferenceKind)) {
		return store.Page{}, fmt.Errorf("invalid reference filter")
	}
	model, err := dashboardModel(kind, nil)
	if err != nil {
		return store.Page{}, err
	}
	models := reflect.New(reflect.SliceOf(reflect.TypeOf(model).Elem())).Interface()
	pred := dashboardPredicate(scope, kind)
	if f.Enabled != nil {
		pred["enabled"] = *f.Enabled
	}
	if f.Name != "" {
		pred["name"] = f.Name
	}
	if f.Field != "" {
		pred[f.Field] = f.Value
	}
	if f.Search != "" {
		pred["name"] = bson.M{"$regex": regexp.QuoteMeta(f.Search), "$options": "i"}
	}
	if f.ReferenceKind != "" {
		key := f.ReferenceKind
		if field := store.ReferenceField(key); field != "" {
			key += "." + field
		}
		pred[key] = f.ReferenceName
	}
	coll := s.mdb.Collection(dashboardCollection(kind))
	total, err := coll.CountDocuments(ctx, pred)
	if err != nil {
		return store.Page{}, err
	}
	direction := 1
	if kind == "scans" {
		direction = -1
	}
	cur, err := coll.Find(ctx, pred, options.Find().SetSort(bson.D{{Key: "created_at", Value: direction}, {Key: "_id", Value: direction}}).SetLimit(int64(f.Limit)).SetSkip(int64(f.Offset)))
	if err != nil {
		return store.Page{}, err
	}
	defer cur.Close(ctx)
	if err = cur.All(ctx, models); err != nil {
		return store.Page{}, err
	}
	page := store.Page{Items: []json.RawMessage{}, Total: total, Limit: f.Limit, Offset: f.Offset}
	v := reflect.ValueOf(models).Elem()
	for i := 0; i < v.Len(); i++ {
		raw, err := dashboardWire(v.Index(i).Addr().Interface())
		if err != nil {
			return store.Page{}, err
		}
		page.Items = append(page.Items, raw)
	}
	page.HasMore = int64(f.Offset+len(page.Items)) < total
	return page, nil
}
func (s *Store) DashboardGet(ctx context.Context, scope store.Scope, kind, key string) (json.RawMessage, error) {
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	if _, err := id.ParseWithPrefix(key, id.Prefix(store.Prefix(kind))); err != nil {
		return nil, err
	}
	model, err := dashboardModel(kind, nil)
	if err != nil {
		return nil, err
	}
	pred := dashboardPredicate(scope, kind)
	pred["_id"] = key
	err = s.mdb.Collection(dashboardCollection(kind)).FindOne(ctx, pred).Decode(model)
	if err != nil && err.Error() == "mongo: no documents in result" {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return dashboardWire(model)
}
func dashboardWrite(scope store.Scope, kind, key string, raw json.RawMessage, created any) (any, error) {
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	if !store.Editable(kind) {
		return nil, store.ErrCollection
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	if fields == nil {
		return nil, fmt.Errorf("expected object")
	}
	fields["id"] = key
	fields["app_id"] = scope.AppID
	fields["tenant_id"] = scope.TenantID
	if kind == "policies" {
		key, level := scope.PolicyScope()
		fields["scope_key"] = key
		fields["scope_level"] = level
	}
	fields["created_at"] = created
	fields["updated_at"] = time.Now().UTC()
	if fields["metadata"] == nil {
		fields["metadata"] = map[string]any{}
	}
	b, err := json.Marshal(fields)
	if err != nil {
		return nil, err
	}
	return dashboardModel(kind, b)
}
func (s *Store) DashboardCreate(ctx context.Context, scope store.Scope, kind string, raw json.RawMessage) (json.RawMessage, error) {
	if !store.Editable(kind) {
		return nil, store.ErrCollection
	}
	key := id.New(id.Prefix(store.Prefix(kind))).String()
	model, err := dashboardWrite(scope, kind, key, raw, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	_, err = s.mdb.Collection(dashboardCollection(kind)).InsertOne(ctx, model)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", kind, err)
	}
	return dashboardWire(model)
}
func (s *Store) DashboardUpdate(ctx context.Context, scope store.Scope, kind, key string, raw json.RawMessage) (json.RawMessage, error) {
	old, err := s.DashboardGet(ctx, scope, kind, key)
	if err != nil {
		return nil, err
	}
	var before, after map[string]any
	if err = json.Unmarshal(old, &before); err != nil {
		return nil, err
	}
	if err = json.Unmarshal(raw, &after); err != nil {
		return nil, err
	}
	if name, ok := after["name"]; ok && name != before["name"] {
		return nil, store.ErrConflict
	}
	for k, v := range after {
		before[k] = v
	}
	raw, err = json.Marshal(before)
	if err != nil {
		return nil, err
	}
	model, err := dashboardWrite(scope, kind, key, raw, before["created_at"])
	if err != nil {
		return nil, err
	}
	pred := dashboardPredicate(scope, kind)
	pred["_id"] = key
	set := bson.M{}
	v := reflect.ValueOf(model).Elem()
	typ := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := typ.Field(i)
		key := strings.Split(field.Tag.Get("bson"), ",")[0]
		if key == "" || key == "-" || key == "_id" || key == "tenant_ids" {
			continue
		}
		set[key] = v.Field(i).Interface()
	}
	res, err := s.mdb.Collection(dashboardCollection(kind)).UpdateOne(ctx, pred, bson.M{"$set": set})
	if err != nil {
		return nil, err
	}
	n := res.MatchedCount
	if err != nil {
		return nil, err
	}
	if n != 1 {
		return nil, store.ErrNotFound
	}
	return dashboardWire(model)
}
func (s *Store) DashboardDelete(ctx context.Context, scope store.Scope, kind, key string) error {
	if !store.Editable(kind) {
		return store.ErrCollection
	}
	if _, err := s.DashboardGet(ctx, scope, kind, key); err != nil {
		return err
	}
	model, err := dashboardModel(kind, nil)
	if err != nil {
		return err
	}
	_ = model
	pred := dashboardPredicate(scope, kind)
	pred["_id"] = key
	res, err := s.mdb.Collection(dashboardCollection(kind)).DeleteOne(ctx, pred)
	if err != nil {
		return err
	}
	n := res.DeletedCount
	if err != nil {
		return err
	}
	if n != 1 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) DashboardAssigned(ctx context.Context, scope store.Scope, key string) (bool, error) {
	if _, err := s.DashboardGet(ctx, scope, "policies", key); err != nil {
		return false, err
	}
	pred := dashboardPredicate(scope, "policies")
	pred["_id"] = key
	pred["tenant_ids"] = scope.TenantID
	n, err := s.mdb.Collection(colPolicies).CountDocuments(ctx, pred)
	return n > 0, err
}
func (s *Store) DashboardAssign(ctx context.Context, scope store.Scope, key string, assigned bool) error {
	if _, err := s.DashboardGet(ctx, scope, "policies", key); err != nil {
		return err
	}
	pred := dashboardPredicate(scope, "policies")
	pred["_id"] = key
	op := "$pull"
	if assigned {
		op = "$addToSet"
	}
	res, err := s.mdb.Collection(colPolicies).UpdateOne(ctx, pred, bson.M{op: bson.M{"tenant_ids": scope.TenantID}})
	if err != nil {
		return err
	}
	if res.MatchedCount != 1 {
		return store.ErrNotFound
	}
	return nil
}
