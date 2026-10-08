package contract

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xraph/forge/extensions/dashboard"
	auth "github.com/xraph/forge/extensions/dashboard/auth"
	dash "github.com/xraph/forge/extensions/dashboard/contract"
	"github.com/xraph/forge/extensions/dashboard/contract/dispatcher"
	"github.com/xraph/forge/extensions/dashboard/contract/idempotency"
	"github.com/xraph/forge/extensions/dashboard/contract/transport"
	"github.com/xraph/forge/extensions/dashboard/security"
	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/sqlitedriver"

	"github.com/xraph/shield/admin"
	"github.com/xraph/shield/engine"
	"github.com/xraph/shield/store/sqlite"
)

func TestAuthenticatedHTTPReadsCommandsAndReplay(t *testing.T) {
	ctx := context.Background()
	dbDriver := sqlitedriver.New()
	if err := dbDriver.Open(ctx, ":memory:"); err != nil {
		t.Fatal(err)
	}
	db, _ := grove.Open(dbDriver)
	t.Cleanup(func() { _ = db.Close() })
	st := sqlite.New(db)
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	eng, _ := engine.New(engine.WithStore(st))
	svc := admin.New(st, eng, nil)
	reg := dash.NewRegistry()
	wreg := dash.NewWardenRegistry()
	disp := dispatcher.NewWithOptions(nil, dispatcher.WithIdempotencyStore(dashboard.AdaptIdempotencyStore(idempotency.NewInMemoryStore())))
	if err := Register(disp, reg, wreg, Deps{Admin: svc}); err != nil {
		t.Fatal(err)
	}
	mgr := security.NewCSRFManager()
	csrf := mgr.GenerateToken()
	h := transport.NewHandlerWithCSRF(reg, wreg, disp, nil, mgr)
	user := &auth.UserInfo{Subject: "u", Claims: map[string]any{"tenant_id": "a", "app_id": "a", "shield_read": true, "shield_manage": true}}
	send := func(intent string, kind dash.Kind, payload string, key, token string, u *auth.UserInfo) *httptest.ResponseRecorder {
		t.Helper()
		body, _ := json.Marshal(dash.Request{Envelope: "v1", Kind: kind, Contributor: "shield", Intent: intent, IntentVersion: 1, Payload: json.RawMessage(payload), IdempotencyKey: key, CSRF: token})
		r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/dashboard/v1", bytes.NewReader(body))
		if u != nil {
			r = r.WithContext(auth.WithUser(r.Context(), u))
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, q := range []string{"capabilities", "overview", "layers.summary", "scans.stats", "config.detail", "pii.stats", "instincts.list", "awareness.list", "boundaries.list", "values.list", "judgments.list", "reflexes.list", "profiles.list", "policies.list", "scans.list", "compliance.list"} {
		w := send(q, dash.KindQuery, `{}`, "", "", user)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", q, w.Code, w.Body)
		}
	}
	w := send("instincts.create", dash.KindCommand, `{"row":{"name":"guard","category":"injection","sensitivity":"balanced","action":"block"}}`, "create-guard", "bad", user)
	if !strings.Contains(w.Body.String(), "UNAUTHENTICATED") {
		t.Fatal(w.Body.String())
	}
	payload := `{"row":{"name":"guard","category":"injection","sensitivity":"balanced","action":"block"}}`
	first := send("instincts.create", dash.KindCommand, payload, "create-guard", csrf, user)
	if first.Code != 200 {
		t.Fatal(first.Code, first.Body.String())
	}
	again := send("instincts.create", dash.KindCommand, payload, "create-guard", csrf, user)
	if again.Code != 200 || again.Body.String() != first.Body.String() {
		t.Fatal("idempotent replay differs", again.Body.String())
	}
	var created dash.Response
	_ = json.Unmarshal(first.Body.Bytes(), &created)
	var row struct {
		ID        string `json:"id"`
		UpdatedAt string `json:"updated_at"`
	}
	_ = json.Unmarshal(created.Data, &row)
	if len(created.Meta.Invalidates) == 0 {
		t.Fatal("missing invalidations")
	}
	fresh := send("instincts.detail", dash.KindQuery, `{"id":"`+row.ID+`"}`, "", "", user)
	_ = json.Unmarshal(fresh.Body.Bytes(), &created)
	_ = json.Unmarshal(created.Data, &row)
	changed := send("instincts.setEnabled", dash.KindCommand, `{"id":"`+row.ID+`","enabled":false}`, "disable", csrf, user)
	if changed.Code != 200 {
		t.Fatal(changed.Body.String())
	}
	stalePayload, _ := json.Marshal(map[string]any{"id": row.ID, "expected_updated_at": row.UpdatedAt, "row": map[string]any{"description": "stale edit"}})
	stale := send("instincts.update", dash.KindCommand, string(stalePayload), "stale-edit", csrf, user)
	if !strings.Contains(stale.Body.String(), "CONFLICT") {
		t.Fatal("stale HTTP save accepted", stale.Body.String())
	}

	foreign := &auth.UserInfo{Subject: "other", Claims: map[string]any{"tenant_id": "b", "app_id": "b", "shield_read": true, "shield_manage": true}}
	w = send("instincts.detail", dash.KindQuery, `{"id":"`+row.ID+`"}`, "", "", foreign)
	if !strings.Contains(w.Body.String(), "NOT_FOUND") {
		t.Fatal("foreign ID readable", w.Body.String())
	}
	w = send("instincts.delete", dash.KindCommand, `{"id":"`+row.ID+`"}`, "foreign-delete", csrf, foreign)
	if !strings.Contains(w.Body.String(), "NOT_FOUND") {
		t.Fatal("foreign ID deleted", w.Body.String())
	}
	w = send("instincts.list", dash.KindQuery, `{}`, "", "", nil)
	if w.Code == 200 {
		t.Fatal("anonymous read")
	}
	readonly := *user
	readonly.Claims = map[string]any{"tenant_id": "a", "app_id": "a", "shield_read": true}
	w = send("instincts.delete", dash.KindCommand, `{"id":"`+row.ID+`"}`, "denied", csrf, &readonly)
	if w.Code == 200 {
		t.Fatal("read-only mutation")
	}
}

func TestScanDirectionRequest(t *testing.T) {
	h := handler(Deps{Resolve: func(context.Context, dash.Principal) (admin.Actor, error) { return admin.Actor{}, nil }}, "scans.list")
	_, err := h(context.Background(), json.RawMessage(`{"direction":"input"}`), nil, dash.Principal{})
	var ce *dash.Error
	if errors.As(err, &ce) && ce.Code == dash.CodeBadRequest {
		t.Fatal("valid direction rejected during request decoding")
	}
}
