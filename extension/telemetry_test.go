package extension

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/xraph/forge"

	"github.com/xraph/shield/engine"
	"github.com/xraph/shield/id"
	"github.com/xraph/shield/scan"
)

type failingStart struct{}

func (failingStart) Name() string { return "failing-start" }
func (failingStart) OnScanStarted(context.Context, id.ScanID, string, string) error {
	return errors.New("refused")
}

func scrape(t *testing.T, app forge.App) string {
	t.Helper()
	p, ok := app.Metrics().(interface{ PrometheusHandler() http.Handler })
	if !ok {
		t.Fatalf("app metrics %T have no Prometheus handler", app.Metrics())
	}
	rr := httptest.NewRecorder()
	p.PrometheusHandler().ServeHTTP(rr, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/_/metrics", nil))
	body, err := io.ReadAll(rr.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func series(body, prefix string) []string {
	var out []string
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, prefix) {
			out = append(out, line)
		}
	}
	return out
}

func TestRegisterWiresAppMetricsAndTracing(t *testing.T) {
	prevTP, prevProp := otel.GetTracerProvider(), otel.GetTextMapPropagator()
	t.Cleanup(func() {
		otel.SetTracerProvider(prevTP)
		otel.SetTextMapPropagator(prevProp)
	})

	app := forge.New(forge.WithAppName("shield-telemetry-test"), forge.WithAppLogger(forge.NewNoopLogger()),
		forge.WithEnableConfigAutoDiscovery(false))
	rec := tracetest.NewSpanRecorder()
	if err := forge.RegisterSpanProcessor(app, rec); err != nil {
		t.Fatal(err)
	}
	e := New(WithPlugin(failingStart{}))
	if err := e.Register(app); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	for range 2 {
		if _, err := e.Engine().ScanInput(ctx, &scan.Input{Text: "hello"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.Engine().ScanOutput(ctx, &scan.Input{Text: "hello"}); err != nil {
		t.Fatal(err)
	}

	body := scrape(t, app)
	for _, want := range []string{
		"# TYPE forge_shield_scans_completed_total counter",
		`forge_shield_scans_completed_total{decision="allow",direction="input"} 2`,
		`forge_shield_scans_completed_total{decision="allow",direction="output"} 1`,
		"# TYPE forge_shield_scan_duration_seconds histogram",
		`forge_shield_scan_duration_seconds_count{decision="allow",direction="input"} 2`,
		`forge_shield_scan_duration_seconds_count{decision="allow",direction="output"} 1`,
		"# TYPE forge_shield_plugin_hooks_failed_total counter",
		`forge_shield_plugin_hooks_failed_total{hook="scan_started"} 3`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape is missing %q", want)
		}
	}
	if got, want := len(series(body, `forge_shield_scan_duration_seconds_bucket{`)), 2*(len(engine.ScanDurationBuckets)+1); got != want {
		t.Errorf("bucket lines = %d, want %d", got, want)
	}
	if strings.Contains(body, "forge_shield_scan_started") || strings.Contains(body, "shield.scan") {
		t.Error("an old dotted counter is still on the scrape")
	}

	var scans int
	for _, s := range rec.Ended() {
		if s.Name() == "scan content" && s.InstrumentationScope().Name == "github.com/xraph/shield" {
			scans++
		}
	}
	if scans != 3 {
		t.Errorf("scan spans on forge's provider = %d, want 3", scans)
	}
}

func TestEngineOptionCanTurnMetricsOff(t *testing.T) {
	app := forge.New(forge.WithAppName("shield-metrics-off"), forge.WithAppLogger(forge.NewNoopLogger()),
		forge.WithEnableConfigAutoDiscovery(false))
	e := New(WithEngineOption(engine.WithMetrics(nil)))
	if err := e.Register(app); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Engine().ScanInput(context.Background(), &scan.Input{Text: "hello"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(scrape(t, app), "forge_shield_") {
		t.Error("shield recorded metrics after WithMetrics(nil)")
	}
}
