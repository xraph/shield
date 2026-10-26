package engine

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
	"go.opentelemetry.io/otel/trace"

	"github.com/xraph/shield"
	"github.com/xraph/shield/awareness"
	"github.com/xraph/shield/id"
	"github.com/xraph/shield/internal/shieldtest"
	"github.com/xraph/shield/profile"
	"github.com/xraph/shield/scan"
	"github.com/xraph/shield/store"
	"github.com/xraph/shield/store/sqlite"
)

// secret stands in for anything that must never reach a span: scanned text,
// a tenant, an error message quoting a value.
const secret = "alice@example.com"

func recordSpans(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	prev := otel.GetTracerProvider()
	rec := tracetest.NewSpanRecorder()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec)))
	t.Cleanup(func() { otel.SetTracerProvider(prev) })
	return rec
}

func spansNamed(rec *tracetest.SpanRecorder, name string) []sdktrace.ReadOnlySpan {
	var out []sdktrace.ReadOnlySpan
	for _, s := range rec.Ended() {
		if s.Name() == name {
			out = append(out, s)
		}
	}
	return out
}

func attrs(s sdktrace.ReadOnlySpan) map[attribute.Key]attribute.Value {
	m := map[attribute.Key]attribute.Value{}
	for _, kv := range s.Attributes() {
		m[kv.Key] = kv.Value
	}
	return m
}

// assertNoSecret fails if secret appears in any attribute, event or status of
// any recorded span.
func assertNoSecret(t *testing.T, rec *tracetest.SpanRecorder) {
	t.Helper()
	for _, s := range rec.Ended() {
		check := func(where string, kvs []attribute.KeyValue) {
			for _, kv := range kvs {
				if strings.Contains(kv.Value.String(), secret) {
					t.Errorf("span %q leaks %s in %s %s", s.Name(), secret, where, kv.Key)
				}
			}
		}
		check("attribute", s.Attributes())
		for _, ev := range s.Events() {
			check("event "+ev.Name, ev.Attributes)
		}
		if strings.Contains(s.Status().Description, secret) {
			t.Errorf("span %q leaks %s in its status", s.Name(), secret)
		}
	}
}

type hookPlugin struct {
	startErr error
}

func (hookPlugin) Name() string { return "test-hooks" }
func (p hookPlugin) OnScanStarted(context.Context, id.ScanID, string, string) error {
	return p.startErr
}
func (hookPlugin) OnScanCompleted(context.Context, id.ScanID, string, int, time.Duration) error {
	return nil
}

// scanStore is a SQLite store whose scan writes return err instead of
// storing anything.
type scanStore struct {
	store.Store
	err error
}

func (s scanStore) CreateScan(context.Context, *scan.Result) error { return s.err }

// profiledStore returns a store holding profile "p" for tenant and app, with
// a PII awareness detector that redacts.
func profiledStore(t *testing.T, tenant, app string) *sqlite.Store {
	t.Helper()
	st := shieldtest.Store(t)
	ctx := shieldtest.Ctx(tenant, app)
	if err := st.CreateAwareness(ctx, &awareness.Awareness{ID: id.NewAwarenessID(), Name: "pii", AppID: app, Focus: awareness.FocusPII, Action: "redact", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	p := &profile.SafetyProfile{ID: id.NewSafetyProfileID(), Name: "p", AppID: app, Enabled: true,
		Awareness: []profile.AwarenessAssignment{{AwarenessName: "pii"}}}
	if err := st.CreateProfile(ctx, p); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestScanRunsUnderOneSpanWithPluginHooksNested(t *testing.T) {
	rec := recordSpans(t)
	e, _ := New(WithPlugin(hookPlugin{startErr: errors.New("plugin rejected " + secret)}), WithStore(scanStore{Store: profiledStore(t, secret, secret)}))

	ctx, parent := otel.Tracer("test").Start(context.Background(), "handle request")
	ctx = shield.WithTenant(shield.WithApp(ctx, secret), secret)
	res, err := e.ScanInput(ctx, &scan.Input{Text: "my email is " + secret, Profile: "p"})
	parent.End()
	if err != nil {
		t.Fatal(err)
	}

	scans := spansNamed(rec, "scan content")
	if len(scans) != 1 {
		t.Fatalf("want one scan span, got %d", len(scans))
	}
	sp := scans[0]
	if sp.SpanKind() != trace.SpanKindInternal || sp.Parent().SpanID() != parent.SpanContext().SpanID() {
		t.Fatalf("scan span kind %v, parent %v", sp.SpanKind(), sp.Parent().SpanID())
	}
	if sp.InstrumentationScope().Name != "github.com/xraph/shield" {
		t.Fatalf("scope = %q", sp.InstrumentationScope().Name)
	}
	a := attrs(sp)
	want := map[attribute.Key]any{
		"shield.scan.id":        res.ID.String(),
		"shield.scan.direction": "input",
		"shield.scan.decision":  "redact",
		"shield.scan.blocked":   false,
		"shield.scan.findings":  int64(1),
		"shield.scan.persisted": true,
	}
	for k, v := range want {
		if got := a[k].AsInterface(); got != v {
			t.Errorf("%s = %v, want %v", k, got, v)
		}
	}
	if sp.Status().Code == codes.Error {
		t.Fatalf("a failed plugin hook failed the scan span: %v", sp.Status())
	}

	hooks := spansNamed(rec, "run plugin hooks")
	if len(hooks) != 2 {
		t.Fatalf("want a hook span for scan_started and scan_completed, got %d", len(hooks))
	}
	byHook := map[string]sdktrace.ReadOnlySpan{}
	for _, h := range hooks {
		if h.Parent().SpanID() != sp.SpanContext().SpanID() {
			t.Errorf("hook span is not a child of the scan span")
		}
		ha := attrs(h)
		if ha["shield.plugin.count"].AsInt64() != 1 {
			t.Errorf("plugin count = %v", ha["shield.plugin.count"])
		}
		byHook[ha["shield.plugin.hook"].AsString()] = h
	}
	started, completed := byHook["scan_started"], byHook["scan_completed"]
	if started == nil || completed == nil {
		t.Fatalf("hook spans = %v", byHook)
	}
	if started.Status().Code != codes.Error || started.Status().Description != "plugin_hook_failed" {
		t.Errorf("failed hook status = %v", started.Status())
	}
	if attrs(started)["shield.plugin.failures"].AsInt64() != 1 {
		t.Errorf("failures = %v", attrs(started)["shield.plugin.failures"])
	}
	if ev := started.Events(); len(ev) != 1 || ev[0].Name != "exception" ||
		len(ev[0].Attributes) != 1 || ev[0].Attributes[0].Value.AsString() != "*errors.errorString" {
		t.Errorf("exception event = %+v", ev)
	}
	if completed.Status().Code == codes.Error {
		t.Errorf("successful hook marked failed")
	}

	assertNoSecret(t, rec)
}

func TestScanSpanMarksAFailedStoreWrite(t *testing.T) {
	rec := recordSpans(t)
	st := profiledStore(t, "tenant-a", "app-a")
	e, _ := New(WithStore(scanStore{Store: st, err: errors.New("insert failed for " + secret)}))
	if _, err := e.ScanOutput(shieldtest.Ctx("tenant-a", "app-a"), &scan.Input{Text: secret, Profile: "p"}); err != nil {
		t.Fatal("a failed store write must not fail the scan:", err)
	}
	scans := spansNamed(rec, "scan content")
	if len(scans) != 1 {
		t.Fatalf("want one scan span, got %d", len(scans))
	}
	sp := scans[0]
	if sp.Parent().IsValid() {
		t.Error("a scan with no caller span should be a root")
	}
	if sp.Status().Code != codes.Error || sp.Status().Description != "persist_failed" {
		t.Errorf("status = %v", sp.Status())
	}
	a := attrs(sp)
	if a["shield.scan.persisted"].AsBool() || a["shield.scan.direction"].AsString() != "output" {
		t.Errorf("attributes = %v", a)
	}
	if len(spansNamed(rec, "run plugin hooks")) != 0 {
		t.Error("hook span started with no plugins registered")
	}
	assertNoSecret(t, rec)
}

func TestFailedScanMarksTheSpanAndPersistsNothing(t *testing.T) {
	rec := recordSpans(t)
	e, _ := New()
	_, err := e.ScanInput(shieldtest.Ctx(secret, secret), &scan.Input{Text: "hello " + secret, Profile: "p"})
	if !errors.Is(err, shield.ErrNoStore) {
		t.Fatalf("err = %v", err)
	}
	sp := spansNamed(rec, "scan content")[0]
	if sp.Status().Code != codes.Error || sp.Status().Description != "scan_failed" {
		t.Errorf("status = %v", sp.Status())
	}
	if _, ok := attrs(sp)["shield.scan.persisted"]; ok {
		t.Error("persisted set on a failed scan")
	}
	assertNoSecret(t, rec)
}

func TestProfileAndLayersRunUnderTheScanSpan(t *testing.T) {
	rec := recordSpans(t)
	e, _ := New(WithStore(profiledStore(t, secret, secret)))
	ctx := shieldtest.Ctx(secret, secret)
	for range 2 {
		if _, err := e.ScanInput(ctx, &scan.Input{Text: "mail " + secret, Profile: "p", Source: secret, Untrusted: true}); err != nil {
			t.Fatal(err)
		}
	}
	scans := spansNamed(rec, "scan content")
	resolves := spansNamed(rec, "resolve profile")
	if len(scans) != 2 || len(resolves) != 2 {
		t.Fatalf("scan spans %d, resolve spans %d", len(scans), len(resolves))
	}
	for i, want := range []bool{false, true} {
		if got := attrs(resolves[i])["shield.profile.cached"].AsBool(); got != want {
			t.Errorf("scan %d cached = %v, want %v", i, got, want)
		}
		if resolves[i].Parent().SpanID() != scans[i].SpanContext().SpanID() {
			t.Errorf("resolve span %d is not a child of its scan span", i)
		}
	}
	var layers []string
	for _, l := range spansNamed(rec, "evaluate layer") {
		if l.Parent().SpanID() != scans[0].SpanContext().SpanID() {
			continue
		}
		layers = append(layers, attrs(l)["shield.scan.layer"].AsString())
	}
	want := []string{"instinct", "awareness", "boundary", "values", "judgment", "reflex", "policy"}
	if strings.Join(layers, ",") != strings.Join(want, ",") {
		t.Errorf("layers = %v, want %v", layers, want)
	}
	assertNoSecret(t, rec)
}
