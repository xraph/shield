package admin

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/sqlitedriver"

	"github.com/xraph/shield/engine"
	"github.com/xraph/shield/id"
	"github.com/xraph/shield/pii"
	"github.com/xraph/shield/store"
	"github.com/xraph/shield/store/sqlite"
)

func serviceForTest(t *testing.T) (*Service, Actor) {
	t.Helper()
	ctx := context.Background()
	d := sqlitedriver.New()
	if err := d.Open(ctx, ":memory:"); err != nil {
		t.Fatal(err)
	}
	db, _ := grove.Open(d)
	t.Cleanup(func() { _ = db.Close() })
	s := sqlite.New(db)
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	e, _ := engine.New(engine.WithStore(s))
	return New(s, e, nil), Actor{Subject: "admin", Scope: store.Scope{TenantID: "a", AppID: "a"}, Read: true, Manage: true, Sensitive: true}
}
func TestValidationReferencesAndPresence(t *testing.T) {
	s, a := serviceForTest(t)
	ctx := context.Background()
	bad := []string{`{"name":"x","category":"unknown","action":"block"}`, `{"name":"x","category":"injection","action":"block","strategies":[{"name":"x","weight":2}]}`, `{"name":"x","category":"injection","action":"block","app_id":"foreign"}`}
	for _, raw := range bad {
		if _, err := s.Create(ctx, a, "instincts", json.RawMessage(raw)); err == nil {
			t.Fatal("accepted invalid input", raw)
		}
	}
	if _, err := s.Create(ctx, a, "profiles", json.RawMessage(`{"name":"profile","instincts":[{"instinct_name":"missing"}]}`)); err == nil {
		t.Fatal("unknown reference accepted")
	}
	r, err := s.Create(ctx, a, "instincts", json.RawMessage(`{"name":"guard","category":"injection","sensitivity":"balanced","action":"block","enabled":true,"strategies":[{"name":"classifier","weight":0}]}`))
	if err != nil {
		t.Fatal(err)
	}
	var row map[string]any
	_ = json.Unmarshal(r, &row)
	key := row["id"].(string)
	_, err = s.Create(ctx, a, "profiles", json.RawMessage(`{"name":"profile","instincts":[{"instinct_name":"guard"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Delete(ctx, a, "instincts", key); err == nil {
		t.Fatal("referenced resource deleted")
	}
	r, err = s.Update(ctx, a, "instincts", key, json.RawMessage(`{"enabled":false,"strategies":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(r), `"enabled":false`) || !strings.Contains(string(r), `"strategies":[]`) {
		t.Fatal(string(r))
	}
	if _, err = s.Update(ctx, a, "instincts", key, json.RawMessage(`{"name":"renamed"}`)); err == nil {
		t.Fatal("rename accepted")
	}
	foreign := a
	foreign.Scope = store.Scope{TenantID: "b", AppID: "b"}
	if _, err = s.Get(ctx, foreign, "instincts", key); err == nil {
		t.Fatal("foreign read")
	}
	foreign = a
	foreign.Manage = false
	if _, err = s.Create(ctx, foreign, "profiles", json.RawMessage(`{"name":"denied"}`)); err == nil {
		t.Fatal("denied mutation")
	}
}
func TestPrivacyRequiresAuditAndImmutablePreview(t *testing.T) {
	s, a := serviceForTest(t)
	ctx := context.Background()
	if _, err := s.RetentionPreview(ctx, a); err == nil {
		t.Fatal("unaudited privacy command available")
	}
}

func TestRetentionAuditPreviewAndRetry(t *testing.T) {
	s, a := serviceForTest(t)
	ctx := context.Background()
	expired := time.Now().Add(-time.Hour)
	st := s.db.(store.Store)
	tok := &pii.Token{ID: id.NewPIITokenID(), ScanID: id.NewScanID(), TenantID: a.Scope.TenantID, PIIType: "email", Placeholder: "[EMAIL]", EncryptedValue: []byte("cipher"), ExpiresAt: &expired}
	if err := st.StorePIITokens(ctx, []*pii.Token{tok}); err != nil {
		t.Fatal(err)
	}
	events := []AuditEvent{}
	s.audit = func(_ context.Context, e AuditEvent) error { events = append(events, e); return nil }
	p, err := s.RetentionPreview(ctx, a)
	if err != nil || p.Total != 1 {
		t.Fatal(p, err)
	}
	other := a
	other.Subject = "other"
	if _, err = s.RetentionExecute(ctx, other, p.ID); err == nil {
		t.Fatal("foreign preview executed")
	}
	n, err := s.RetentionExecute(ctx, a, p.ID)
	if err != nil || n != 1 {
		t.Fatal(n, err)
	}
	n, err = s.RetentionExecute(ctx, a, p.ID)
	if err != nil || n != 0 {
		t.Fatal("retry expanded", n, err)
	}
	if len(events) != 4 || events[0].Action != "pii.retention.requested" {
		t.Fatal(events)
	}
	s.audit = func(context.Context, AuditEvent) error { return errors.New("audit offline") }
	if _, err = s.RetentionExecute(ctx, a, p.ID); err == nil {
		t.Fatal("audit failure hidden")
	}
}

func TestStaleEditorRevisionIsRejected(t *testing.T) {
	s, a := serviceForTest(t)
	ctx := context.Background()
	raw, err := s.Create(ctx, a, "boundaries", json.RawMessage(`{"name":"guard","enabled":true}`))
	if err != nil {
		t.Fatal(err)
	}
	var initial map[string]any
	_ = json.Unmarshal(raw, &initial)
	key := initial["id"].(string)
	revision := initial["updated_at"].(string)
	if _, err = s.Update(ctx, a, "boundaries", key, json.RawMessage(`{"enabled":false}`)); err != nil {
		t.Fatal(err)
	}
	_, err = s.Update(ctx, a, "boundaries", key, json.RawMessage(`{"description":"older tab"}`), revision)
	var conflict *Error
	if !errors.As(err, &conflict) || conflict.Code != "CONFLICT" {
		t.Fatalf("stale edit: %v", err)
	}
	current, _ := s.Get(ctx, a, "boundaries", key)
	if !strings.Contains(string(current), `"enabled":false`) {
		t.Fatal(string(current))
	}
}
