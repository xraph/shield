package admin

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/xraph/shield/id"
	"github.com/xraph/shield/pii"
	"github.com/xraph/shield/store"
)

const secret = "alice@example.com"

func purgeSpans(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	prev := otel.GetTracerProvider()
	rec := tracetest.NewSpanRecorder()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec)))
	t.Cleanup(func() { otel.SetTracerProvider(prev) })
	return rec
}

func spanAttrs(s sdktrace.ReadOnlySpan) map[attribute.Key]attribute.Value {
	m := map[attribute.Key]attribute.Value{}
	for _, kv := range s.Attributes() {
		m[kv.Key] = kv.Value
	}
	return m
}

func seedExpiredToken(t *testing.T, s *Service, a Actor) {
	t.Helper()
	expired := time.Now().Add(-time.Hour)
	tok := &pii.Token{ID: id.NewPIITokenID(), ScanID: id.NewScanID(), TenantID: a.Scope.TenantID, PIIType: "email", Placeholder: "[EMAIL]", EncryptedValue: []byte(secret), ExpiresAt: &expired}
	if err := s.db.(store.Store).StorePIITokens(context.Background(), []*pii.Token{tok}); err != nil {
		t.Fatal(err)
	}
}

func TestRetentionPurgeIsTraced(t *testing.T) {
	s, a := serviceForTest(t)
	a.Subject = secret
	seedExpiredToken(t, s, a)
	s.audit = func(context.Context, AuditEvent) error { return nil }
	ctx := context.Background()
	p, err := s.RetentionPreview(ctx, a)
	if err != nil {
		t.Fatal(err)
	}

	rec := purgeSpans(t)
	if _, err = s.RetentionExecute(ctx, a, "missing"); err == nil {
		t.Fatal("unknown preview executed")
	}
	if len(rec.Ended()) != 0 {
		t.Fatal("a refused purge started a span; the dispatch span covers it")
	}

	n, err := s.RetentionExecute(ctx, a, p.ID)
	if err != nil || n != 1 {
		t.Fatal(n, err)
	}
	var purge sdktrace.ReadOnlySpan
	for _, sp := range rec.Ended() {
		if sp.Name() == "purge pii tokens" {
			purge = sp
		}
	}
	if purge == nil {
		t.Fatal("no purge span")
	}
	at := spanAttrs(purge)
	if at["shield.retention.tokens_selected"].AsInt64() != 1 || at["shield.retention.tokens_deleted"].AsInt64() != 1 {
		t.Errorf("attributes = %v", at)
	}
	if purge.Status().Code == codes.Error {
		t.Errorf("status = %v", purge.Status())
	}
	// The token delete goes through grove, which nests its span here.
	children := 0
	for _, sp := range rec.Ended() {
		if sp == purge {
			continue
		}
		if sp.Parent().SpanID() != purge.SpanContext().SpanID() {
			t.Errorf("%q is not a child of the purge span", sp.Name())
		}
		children++
	}
	if children == 0 {
		t.Error("the token delete left no span under the purge span")
	}
	assertClean(t, rec)
}

func TestRetentionPurgeSpanNamesTheFailedStep(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fail  int // which audit call fails, 1 or 2
		class string
	}{
		{"request audit", 1, "audit_failed"},
		{"completion audit", 2, "completion_audit_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, a := serviceForTest(t)
			seedExpiredToken(t, s, a)
			calls := 0
			s.audit = func(context.Context, AuditEvent) error {
				calls++
				if calls == tc.fail {
					return errors.New("audit sink refused " + secret)
				}
				return nil
			}
			ctx := context.Background()
			p, err := s.RetentionPreview(ctx, a)
			if err != nil {
				t.Fatal(err)
			}
			rec := purgeSpans(t)
			if _, err = s.RetentionExecute(ctx, a, p.ID); err == nil {
				t.Fatal("audit failure hidden")
			}
			var purge sdktrace.ReadOnlySpan
			for _, sp := range rec.Ended() {
				if sp.Name() == "purge pii tokens" {
					purge = sp
				}
			}
			if purge == nil {
				t.Fatal("no purge span")
			}
			if purge.Status().Code != codes.Error || purge.Status().Description != tc.class {
				t.Errorf("status = %v, want %s", purge.Status(), tc.class)
			}
			ev := purge.Events()
			if len(ev) != 1 || ev[0].Name != "exception" || ev[0].Attributes[0].Value.AsString() != "*errors.errorString" {
				t.Errorf("events = %+v", ev)
			}
			_, deleted := spanAttrs(purge)["shield.retention.tokens_deleted"]
			if deleted != (tc.fail == 2) {
				t.Errorf("tokens_deleted present = %v", deleted)
			}
			assertClean(t, rec)
		})
	}
}

func assertClean(t *testing.T, rec *tracetest.SpanRecorder) {
	t.Helper()
	for _, sp := range rec.Ended() {
		kvs := append([]attribute.KeyValue{}, sp.Attributes()...)
		for _, ev := range sp.Events() {
			kvs = append(kvs, ev.Attributes...)
		}
		for _, kv := range kvs {
			if strings.Contains(kv.Value.String(), secret) {
				t.Errorf("span %q leaks %s in %s", sp.Name(), secret, kv.Key)
			}
		}
		if strings.Contains(sp.Status().Description, secret) {
			t.Errorf("span %q leaks %s in its status", sp.Name(), secret)
		}
	}
}
