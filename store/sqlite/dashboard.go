package sqlite

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
	"reflect"
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
		return instinctToModel(&row)
	case "awareness":
		var row awareness.Awareness
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &row); err != nil {
				return nil, err
			}
		}
		return awarenessToModel(&row)
	case "boundaries":
		var row boundary.Boundary
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &row); err != nil {
				return nil, err
			}
		}
		return boundaryToModel(&row)
	case "values":
		var row values.Values
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &row); err != nil {
				return nil, err
			}
		}
		return valuesToModel(&row)
	case "judgments":
		var row judgment.Judgment
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &row); err != nil {
				return nil, err
			}
		}
		return judgmentToModel(&row)
	case "reflexes":
		var row reflex.Reflex
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &row); err != nil {
				return nil, err
			}
		}
		return reflexToModel(&row)
	case "profiles":
		var row profile.SafetyProfile
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &row); err != nil {
				return nil, err
			}
		}
		return profileToModel(&row)
	case "policies":
		var row policy.Policy
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &row); err != nil {
				return nil, err
			}
		}
		return policyToModel(&row)
	case "scans":
		var row scan.Result
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &row); err != nil {
				return nil, err
			}
		}
		return scanToModel(&row)
	case "compliance":
		var row compliance.Report
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &row); err != nil {
				return nil, err
			}
		}
		return complianceToModel(&row)
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
func dashboardPredicate(scope store.Scope, kind string) (string, []any) {
	if kind == "policies" || kind == "compliance" {
		key, level := scope.PolicyScope()
		return "scope_key = ? AND scope_level = ?", []any{key, level}
	}
	return "app_id = ? AND tenant_id = ?", []any{scope.AppID, scope.TenantID}
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
	pred, args := dashboardPredicate(scope, kind)
	q := s.sdb.NewSelect(models).Where(pred, args...)
	if f.Enabled != nil {
		q = q.Where("enabled = ?", *f.Enabled)
	}
	if f.Name != "" {
		q = q.Where("name = ?", f.Name)
	}
	if f.Field != "" {
		q = q.Where(f.Field+" = ?", f.Value)
	}
	if f.Search != "" {
		q = q.Where("LOWER(name) LIKE LOWER(?)", "%"+f.Search+"%")
	}
	if f.ReferenceKind != "" {
		expr := "ref.value"
		if field := store.ReferenceField(f.ReferenceKind); field != "" {
			expr = "json_extract(ref.value, '$." + field + "')"
		}
		q = q.Where("EXISTS (SELECT 1 FROM json_each(shield_profiles."+f.ReferenceKind+") AS ref WHERE "+expr+" = ?)", f.ReferenceName)
	}
	if f.Direction != "" {
		q = q.Where("direction = ?", f.Direction)
	}
	total, err := q.Count(ctx)
	if err != nil {
		return store.Page{}, err
	}
	order := "created_at ASC, id ASC"
	if kind == "scans" {
		order = "created_at DESC, id DESC"
	}
	if err = q.OrderExpr(order).Limit(f.Limit).Offset(f.Offset).Scan(ctx); err != nil {
		return store.Page{}, err
	}
	page := store.Page{RefreshedAt: time.Now().UTC(), Items: []json.RawMessage{}, Total: total, Limit: f.Limit, Offset: f.Offset}
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
	pred, args := dashboardPredicate(scope, kind)
	err = s.sdb.NewSelect(model).Where(pred, args...).Where("id = ?", key).Scan(ctx)
	if isNoRows(err) {
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
	_, err = s.sdb.NewInsert(model).Exec(ctx)
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
	pred, args := dashboardPredicate(scope, kind)
	res, err := s.sdb.NewUpdate(model).Where(pred, args...).Where("id = ?", key).Exec(ctx)
	if err != nil {
		return nil, err
	}
	n, err := res.RowsAffected()
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
	pred, args := dashboardPredicate(scope, kind)
	res, err := s.sdb.NewDelete(model).Where(pred, args...).Where("id = ?", key).Exec(ctx)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
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
	n, err := s.sdb.NewSelect((*policyTenantModel)(nil)).Where("tenant_id = ?", scope.TenantID).Where("policy_id = ?", key).Count(ctx)
	return n > 0, err
}
func (s *Store) DashboardAssign(ctx context.Context, scope store.Scope, key string, assigned bool) error {
	if _, err := s.DashboardGet(ctx, scope, "policies", key); err != nil {
		return err
	}
	if !assigned {
		_, err := s.sdb.NewDelete((*policyTenantModel)(nil)).Where("tenant_id = ?", scope.TenantID).Where("policy_id = ?", key).Exec(ctx)
		return err
	}
	m := &policyTenantModel{TenantID: scope.TenantID, PolicyID: key, CreatedAt: time.Now().UTC()}
	_, err := s.sdb.NewInsert(m).OnConflict("(tenant_id, policy_id) DO NOTHING").Exec(ctx)
	return err
}
