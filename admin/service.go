// Package admin validates dashboard operations before touching scoped stores.
package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/xraph/shield/engine"
	"github.com/xraph/shield/id"
	"github.com/xraph/shield/store"
	"strings"
	"sync"
	"time"
)

type Error struct {
	Code    string
	Message string
	Fields  map[string]string
}

func (e *Error) Error() string        { return e.Message }
func fail(code, message string) error { return &Error{Code: code, Message: message} }

type Actor struct {
	Subject                 string
	Scope                   store.Scope
	Read, Manage, Sensitive bool
}

func (a Actor) Check(write bool) error {
	if a.Subject == "" {
		return fail("UNAUTHENTICATED", "Sign in to use Shield")
	}
	if err := a.Scope.Validate(); err != nil {
		return fail("PERMISSION_DENIED", "An authorized tenant and app are required")
	}
	if !a.Read || write && !a.Manage {
		return fail("PERMISSION_DENIED", "Shield permission required")
	}
	return nil
}

type AuditEvent struct {
	Subject  string      `json:"subject"`
	Scope    store.Scope `json:"scope"`
	Action   string      `json:"action"`
	TokenIDs []string    `json:"token_ids"`
	Cutoff   time.Time   `json:"cutoff"`
	Affected int64       `json:"affected"`
}
type Audit func(context.Context, AuditEvent) error
type Service struct {
	db       store.DashboardStore
	engine   *engine.Engine
	audit    Audit
	mu       sync.Mutex
	previews map[string]Preview
}

func New(db store.DashboardStore, eng *engine.Engine, audit Audit) *Service {
	return &Service{db: db, engine: eng, audit: audit, previews: map[string]Preview{}}
}
func (s *Service) Engine() *engine.Engine { return s.engine }
func (s *Service) Ready() bool            { return s.db != nil && s.engine != nil }
func (s *Service) List(ctx context.Context, a Actor, kind string, f store.Filter) (store.Page, error) {
	if err := a.Check(false); err != nil {
		return store.Page{}, err
	}
	if !s.Ready() {
		return store.Page{}, fail("UNAVAILABLE", "Shield persistence is unavailable")
	}
	if err := f.Validate(); err != nil {
		return store.Page{}, fail("BAD_REQUEST", err.Error())
	}
	if f.Field != "" {
		if !store.FilterColumn(kind, f.Field) {
			return store.Page{}, fail("BAD_REQUEST", "Unsupported filter")
		}
		if err := validateFilter(kind, f.Field, f.Value); err != nil {
			return store.Page{}, err
		}
	}
	return s.db.DashboardList(ctx, a.Scope, kind, f)
}
func (s *Service) Get(ctx context.Context, a Actor, kind, key string) (json.RawMessage, error) {
	if err := a.Check(false); err != nil {
		return nil, err
	}
	if !s.Ready() {
		return nil, fail("UNAVAILABLE", "Shield persistence is unavailable")
	}
	if err := validateID(kind, key); err != nil {
		return nil, err
	}
	return s.db.DashboardGet(ctx, a.Scope, kind, key)
}
func validateID(kind, key string) error {
	prefix := store.Prefix(kind)
	if prefix == "" {
		return fail("BAD_REQUEST", "Unsupported collection")
	}
	if _, err := id.ParseWithPrefix(key, id.Prefix(prefix)); err != nil {
		return fail("BAD_REQUEST", "Invalid resource ID")
	}
	return nil
}
func decode(raw json.RawMessage) (map[string]any, error) {
	if len(raw) > 131072 {
		return nil, fail("BAD_REQUEST", "Configuration exceeds 128 KiB")
	}
	var row map[string]any
	if err := json.Unmarshal(raw, &row); err != nil || row == nil {
		return nil, fail("BAD_REQUEST", "Expected a configuration object")
	}
	return row, nil
}
func (s *Service) Create(ctx context.Context, a Actor, kind string, raw json.RawMessage) (json.RawMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := a.Check(true); err != nil {
		return nil, err
	}
	if !s.Ready() {
		return nil, fail("UNAVAILABLE", "Shield persistence is unavailable")
	}
	row, err := decode(raw)
	if err != nil {
		return nil, err
	}
	if err = validate(kind, row, nil); err != nil {
		return nil, err
	}
	if _, ok := row["enabled"]; !ok {
		row["enabled"] = true
	}
	if row["metadata"] == nil {
		row["metadata"] = map[string]any{}
	}
	if err = s.validateReferences(ctx, a, kind, row); err != nil {
		return nil, err
	}
	b, _ := json.Marshal(row)
	return s.db.DashboardCreate(ctx, a.Scope, kind, b)
}
func (s *Service) Update(ctx context.Context, a Actor, kind, key string, raw json.RawMessage) (json.RawMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := a.Check(true); err != nil {
		return nil, err
	}
	old, err := s.Get(ctx, a, kind, key)
	if err != nil {
		return nil, err
	}
	before, _ := decode(old)
	patch, err := decode(raw)
	if err != nil {
		return nil, err
	}
	for _, k := range []string{"name", "app_id", "tenant_id", "scope_key", "scope_level", "id", "created_at", "updated_at"} {
		if v, ok := patch[k]; ok && v != before[k] {
			return nil, fail("CONFLICT", k+" is immutable")
		}
		delete(patch, k)
	}
	merged := map[string]any{}
	for k, v := range before {
		merged[k] = v
	}
	for k, v := range patch {
		merged[k] = v
	}
	if err = validate(kind, merged, before); err != nil {
		return nil, err
	}
	if err = s.validateReferences(ctx, a, kind, merged); err != nil {
		return nil, err
	}
	b, _ := json.Marshal(patch)
	return s.db.DashboardUpdate(ctx, a.Scope, kind, key, b)
}
func (s *Service) Delete(ctx context.Context, a Actor, kind, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := a.Check(true); err != nil {
		return err
	}
	row, err := s.Get(ctx, a, kind, key)
	if err != nil {
		return err
	}
	var fields map[string]any
	_ = json.Unmarshal(row, &fields)
	if kind != "profiles" && kind != "policies" {
		refs, err := s.References(ctx, a, kind, fmt.Sprint(fields["name"]))
		if err != nil {
			return err
		}
		if len(refs) > 0 {
			return &Error{Code: "CONFLICT", Message: "Update referencing profiles before deleting this configuration", Fields: map[string]string{"references": strings.Join(refs, ", ")}}
		}
	}
	return s.db.DashboardDelete(ctx, a.Scope, kind, key)
}
func (s *Service) References(ctx context.Context, a Actor, kind, name string) ([]string, error) {
	if err := a.Check(false); err != nil {
		return nil, err
	}
	if !store.ValidReferenceKind(kind) {
		return nil, fail("BAD_REQUEST", "Invalid reference collection")
	}
	refs := []string{}
	page, err := s.List(ctx, a, "profiles", store.Filter{Limit: 100, ReferenceKind: kind, ReferenceName: name})
	if err != nil {
		return nil, err
	}
	for _, raw := range page.Items {
		var row struct {
			ID string `json:"id"`
		}
		if err = json.Unmarshal(raw, &row); err != nil {
			return nil, err
		}
		refs = append(refs, row.ID)
	}
	return refs, nil
}
func referenceNames(kind string, value any) []string {
	items, _ := value.([]any)
	out := []string{}
	for _, item := range items {
		if str, ok := item.(string); ok {
			out = append(out, str)
		} else if m, ok := item.(map[string]any); ok {
			field := map[string]string{"instincts": "instinct_name", "awareness": "awareness_name", "judgments": "judgment_name"}[kind]
			if name, ok := m[field].(string); ok {
				out = append(out, name)
			}
		}
	}
	return out
}
func (s *Service) validateReferences(ctx context.Context, a Actor, kind string, row map[string]any) error {
	if kind != "profiles" {
		return nil
	}
	for _, k := range []string{"instincts", "awareness", "boundaries", "values", "judgments", "reflexes"} {
		for _, name := range referenceNames(k, row[k]) {
			page, err := s.List(ctx, a, k, store.Filter{Limit: 1, Name: name})
			if err != nil {
				return err
			}
			if page.Total != 1 {
				return &Error{Code: "BAD_REQUEST", Message: "Profile references must exist in this tenant and app", Fields: map[string]string{k: "Unknown configuration: " + name}}
			}
		}
	}
	return nil
}
func (s *Service) Assigned(ctx context.Context, a Actor, key string) (bool, error) {
	if _, err := s.Get(ctx, a, "policies", key); err != nil {
		return false, err
	}
	db, ok := s.db.(store.AssignmentStore)
	if !ok {
		return false, fail("UNAVAILABLE", "Policy assignments are unavailable")
	}
	return db.DashboardAssigned(ctx, a.Scope, key)
}
func (s *Service) Assign(ctx context.Context, a Actor, key string, assigned bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := a.Check(true); err != nil {
		return err
	}
	if _, err := s.Get(ctx, a, "policies", key); err != nil {
		return err
	}
	db, ok := s.db.(store.AssignmentStore)
	if !ok {
		return fail("UNAVAILABLE", "Policy assignments are unavailable")
	}
	return db.DashboardAssign(ctx, a.Scope, key, assigned)
}
func (s *Service) Tokens(ctx context.Context, a Actor, scanID string, f store.Filter) (store.Page, error) {
	if err := a.Check(false); err != nil {
		return store.Page{}, err
	}
	db, ok := s.db.(store.PrivacyStore)
	if !ok {
		return store.Page{}, fail("UNAVAILABLE", "PII metadata is unavailable")
	}
	return db.DashboardTokens(ctx, a.Scope, scanID, nil, f)
}

type Preview struct {
	ID        string    `json:"id"`
	Cutoff    time.Time `json:"cutoff"`
	ExpiresAt time.Time `json:"expires_at"`
	TokenIDs  []string  `json:"token_ids"`
	Total     int64     `json:"total"`
	HasMore   bool      `json:"has_more"`
	subject   string
	scope     store.Scope
}

func (s *Service) RetentionPreview(ctx context.Context, a Actor) (Preview, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := a.Check(true); err != nil {
		return Preview{}, err
	}
	if !a.Sensitive {
		return Preview{}, fail("PERMISSION_DENIED", "PII retention permission required")
	}
	if s.audit == nil {
		return Preview{}, fail("UNAVAILABLE", "Configure an audit adapter before deleting PII")
	}
	db, ok := s.db.(store.PrivacyStore)
	if !ok {
		return Preview{}, fail("UNAVAILABLE", "PII retention is unavailable")
	}
	cutoff := time.Now().UTC()
	page, err := db.DashboardTokens(ctx, a.Scope, "", &cutoff, store.Filter{Limit: 100})
	if err != nil {
		return Preview{}, err
	}
	p := Preview{ID: id.New(id.PrefixCheck).String(), Cutoff: cutoff, ExpiresAt: cutoff.Add(5 * time.Minute), TokenIDs: []string{}, Total: page.Total, HasMore: page.HasMore, subject: a.Subject, scope: a.Scope}
	for _, raw := range page.Items {
		var token struct {
			ID string `json:"id"`
		}
		if err = json.Unmarshal(raw, &token); err != nil {
			return Preview{}, err
		}
		p.TokenIDs = append(p.TokenIDs, token.ID)
	}
	for key, old := range s.previews {
		if old.ExpiresAt.Before(cutoff) {
			delete(s.previews, key)
		}
	}
	s.previews[p.ID] = p
	return p, nil
}
func (s *Service) RetentionExecute(ctx context.Context, a Actor, key string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := a.Check(true); err != nil {
		return 0, err
	}
	if !a.Sensitive {
		return 0, fail("PERMISSION_DENIED", "PII retention permission required")
	}
	if s.audit == nil {
		return 0, fail("UNAVAILABLE", "Audit adapter is unavailable")
	}
	p, ok := s.previews[key]
	if !ok || p.subject != a.Subject || p.scope != a.Scope || p.ExpiresAt.Before(time.Now()) {
		return 0, fail("CONFLICT", "Retention preview expired; review a new preview")
	}
	if len(p.TokenIDs) == 0 {
		return 0, fail("BAD_REQUEST", "No expired tokens selected")
	}
	db, ok := s.db.(store.PrivacyStore)
	if !ok {
		return 0, fail("UNAVAILABLE", "PII retention is unavailable")
	}
	event := AuditEvent{Subject: a.Subject, Scope: a.Scope, Action: "pii.retention.requested", TokenIDs: p.TokenIDs, Cutoff: p.Cutoff}
	if err := s.audit(ctx, event); err != nil {
		return 0, fail("UNAVAILABLE", "Could not record retention audit; nothing was deleted")
	}
	n, err := db.DashboardDeleteTokens(ctx, a.Scope, p.Cutoff, p.TokenIDs)
	if err != nil {
		return 0, err
	}
	event.Action = "pii.retention.completed"
	event.Affected = n
	if err = s.audit(ctx, event); err != nil {
		return n, fail("INTERNAL", "Retention completed but its completion audit failed")
	}
	return n, nil
}
func (s *Service) PrivacyAvailable() bool { return s.audit != nil }
