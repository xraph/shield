// Package engine provides the layered safety execution engine.
//
// The engine processes content through six cognitive layers, each
// modeled after human safety cognition:
//
//	Layer 1: INSTINCTS    (fastest, <10ms)   — Injection, Jailbreak, Exfiltration
//	Layer 2: AWARENESS    (perception, <50ms) — PII, Topic, Intent detection
//	Layer 3: BOUNDARIES   (binary, <5ms)      — Hard topic/action/data limits
//	Layer 4: VALUES       (ethical, <100ms)    — Toxicity, Brand, Honesty
//	Layer 5: JUDGMENT     (contextual, <500ms) — Grounding, Relevance, Compliance
//	Layer 6: REFLEXES     (policy, <10ms)      — Custom condition→action rules
//
// Every scan runs inside a tenant and evaluates one safety profile of that
// tenant, compiled from the store and cached (see Config.ProfileCacheTTL),
// then the tenant's policies. With Config.EnableShortCircuit a block ends
// the scan after the layer that found it.
package engine

import (
	"context"
	"errors"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	log "github.com/xraph/go-utils/log"
	gometrics "github.com/xraph/go-utils/metrics"

	"github.com/xraph/shield"
	"github.com/xraph/shield/id"
	"github.com/xraph/shield/internal/telemetry"
	"github.com/xraph/shield/plugin"
	"github.com/xraph/shield/scan"
	"github.com/xraph/shield/store"
)

// The metrics the engine records when WithMetrics is set. A Forge app scrapes
// them with a forge_ prefix: forge_shield_scans_completed_total and
// forge_shield_scan_duration_seconds. Both carry direction (input, output)
// and decision (allow, block, flag, redact).
const (
	ScansCompletedMetric = "shield_scans_completed_total"
	ScanDurationMetric   = "shield_scan_duration_seconds"
)

// ScanDurationBuckets are the histogram bounds for ScanDurationMetric, in
// seconds. They span the layer budgets, from a 5ms boundary check to a
// 500ms judgment, with headroom for storing the result.
var ScanDurationBuckets = []float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5}

// Engine is the core safety execution engine.
type Engine struct {
	store    store.Store
	registry *plugin.Registry
	config   shield.Config
	logger   log.Logger
	metrics  gometrics.Metrics
	profiles *profileCache
	rates    *rateCounter

	scansCompleted *telemetry.CounterVec
	scanDuration   *telemetry.HistogramVec
}

// Option configures the Engine.
type Option func(*Engine)

// WithStore sets the composite store.
func WithStore(s store.Store) Option {
	return func(e *Engine) { e.store = s }
}

// WithPlugin registers a lifecycle plugin.
func WithPlugin(p plugin.Plugin) Option {
	return func(e *Engine) { e.registry.Register(p) }
}

// WithConfig sets the engine configuration.
func WithConfig(cfg shield.Config) Option {
	return func(e *Engine) { e.config = cfg }
}

// WithLogger sets a custom logger. The plugin registry reports hook errors
// on it too.
func WithLogger(l log.Logger) Option {
	return func(e *Engine) { e.logger = l }
}

// WithMetrics records scan and plugin metrics on m: ScansCompletedMetric,
// ScanDurationMetric and plugin.HooksFailedMetric. In a Forge app pass
// app.Metrics(); the Shield Forge extension does this for you. A nil m, the
// default, records nothing.
func WithMetrics(m gometrics.Metrics) Option {
	return func(e *Engine) { e.metrics = m }
}

// New creates a new safety engine with the given options.
func New(opts ...Option) (*Engine, error) {
	e := &Engine{
		registry: plugin.NewRegistry(log.NewNoopLogger()),
		config:   shield.DefaultConfig(),
		logger:   log.NewNoopLogger(),
		profiles: newProfileCache(),
		rates:    newRateCounter(),
	}
	for _, opt := range opts {
		opt(e)
	}
	if e.config.MaxScanBytes <= 0 {
		e.config.MaxScanBytes = shield.DefaultMaxScanBytes
	}
	if e.config.ProfileCacheTTL == 0 {
		e.config.ProfileCacheTTL = shield.DefaultProfileCacheTTL
	}
	e.registry.SetLogger(e.logger)
	e.registry.SetMetrics(e.metrics)
	e.scansCompleted = telemetry.NewCounterVec(e.metrics, ScansCompletedMetric,
		"Safety scans completed, by direction and decision.", "direction", "decision")
	e.scanDuration = telemetry.NewHistogramVec(e.metrics, ScanDurationMetric,
		"Wall time of one safety scan, plugin hooks and storing the result included.",
		"s", ScanDurationBuckets, "direction", "decision")
	return e, nil
}

// ScanInput runs a safety scan on input content (user→agent).
func (e *Engine) ScanInput(ctx context.Context, input *scan.Input) (*scan.Result, error) {
	if input == nil {
		return nil, shield.ErrInvalidInput
	}
	input.Direction = scan.DirectionInput
	return e.executeScan(ctx, input)
}

// ScanOutput runs a safety scan on output content (agent→user).
func (e *Engine) ScanOutput(ctx context.Context, input *scan.Input) (*scan.Result, error) {
	if input == nil {
		return nil, shield.ErrInvalidInput
	}
	input.Direction = scan.DirectionOutput
	return e.executeScan(ctx, input)
}

// executeScan runs the layered safety evaluation.
//
// It checks, in order, the context tenant, the size limit and the store,
// then resolves the profile named by the input (or Config.DefaultProfile)
// and runs the layers. Any error fires the ScanFailed hook, marks the scan
// span failed and persists nothing.
//
// The scan runs under a "scan content" span. Its attributes are counts,
// enums and the scan ID; the scanned text, findings, tenant and profile name
// never go on it. Profile resolution, each layer, plugin hooks and the
// store write nest under it.
func (e *Engine) executeScan(ctx context.Context, input *scan.Input) (*scan.Result, error) {
	start := time.Now()
	scanID := id.NewScanID()

	ctx, span := telemetry.Tracer().Start(ctx, "scan content", trace.WithAttributes(
		attribute.String("shield.scan.id", scanID.String()),
		attribute.String("shield.scan.direction", string(input.Direction)),
	))
	defer span.End()

	e.registry.EmitScanStarted(ctx, scanID, string(input.Direction), input.Text)

	result, err := e.evaluate(ctx, scanID, input)
	if err != nil {
		e.registry.EmitScanFailed(ctx, scanID, err)
		telemetry.Fail(span, "scan_failed", err)
		return nil, err
	}
	result.Duration = time.Since(start)

	e.registry.EmitScanCompleted(ctx, scanID, string(result.Decision), len(result.Findings), result.Duration)
	if result.Blocked {
		e.registry.EmitScanBlocked(ctx, scanID, result.Reason())
	}

	// Persist result. A failed write doesn't fail the scan, but the span
	// says so: the dashboard will never show this scan.
	persistErr := e.persist(ctx, result)
	if persistErr != nil {
		e.logger.Warn("engine: failed to persist scan result", log.String("scan_id", scanID.String()), log.Error(persistErr))
		telemetry.Fail(span, "persist_failed", persistErr)
	}
	span.SetAttributes(attribute.Bool("shield.scan.persisted", persistErr == nil))

	span.SetAttributes(
		attribute.String("shield.scan.decision", string(result.Decision)),
		attribute.Bool("shield.scan.blocked", result.Blocked),
		attribute.Int("shield.scan.findings", len(result.Findings)),
	)
	direction, decision := string(result.Direction), string(result.Decision)
	e.scansCompleted.Inc(direction, decision)
	e.scanDuration.Observe(time.Since(start).Seconds(), direction, decision)

	return result, nil
}

// evaluate checks the scan's preconditions, resolves its profile and runs
// the layers.
func (e *Engine) evaluate(ctx context.Context, scanID id.ScanID, input *scan.Input) (*scan.Result, error) {
	tenant, err := store.Tenant(ctx, "")
	if err != nil {
		return nil, err
	}
	if inputSize(input) > e.config.MaxScanBytes {
		return nil, shield.ErrInputTooLarge
	}
	if e.store == nil {
		return nil, shield.ErrNoStore
	}
	name := input.Profile
	if name == "" {
		name = e.config.DefaultProfile
	}
	if name == "" {
		return nil, shield.ErrNoProfile
	}
	app := shield.AppFromContext(ctx)
	compiled, err := e.resolveProfile(ctx, tenant, app, name)
	if err != nil {
		return nil, err
	}
	e.registry.EmitSafetyProfileResolved(ctx, scanID, compiled.name)

	ev := &evaluation{
		scanID: scanID, tenant: tenant, app: app, input: input, profile: compiled,
		hits: map[*scan.Finding]*awarenessHit{},
	}
	for _, layer := range []struct {
		name string
		run  func(context.Context, *evaluation)
	}{
		{layerInstinct, e.runInstincts},
		{layerAwareness, e.runAwareness},
		{layerBoundary, e.runBoundaries},
		{layerValues, e.runValues},
		{layerJudgment, e.runJudgments},
		{layerReflex, e.runReflexes},
		{layerPolicy, e.runPolicies},
	} {
		e.evaluateLayer(ctx, ev, layer.name, layer.run)
		if ev.blocked && e.config.EnableShortCircuit {
			break
		}
	}

	result := &scan.Result{
		ID:           scanID,
		Direction:    input.Direction,
		TenantID:     tenant,
		AppID:        app,
		ProfileUsed:  compiled.name,
		PoliciesUsed: append([]string{}, ev.policiesUsed...),
		PIICount:     ev.piiCount(),
		Metadata:     ev.metadata(),
	}
	ev.decide(result)
	if !result.Blocked {
		for _, t := range ev.piiRedacted {
			e.registry.EmitPIIRedacted(ctx, scanID, t.typ, t.count)
		}
	}
	return result, nil
}

// inputSize is what a scan counts against Config.MaxScanBytes: the text
// plus every string value of the input context, which on_context reflexes
// match against.
func inputSize(input *scan.Input) int {
	n := len(input.Text)
	for _, v := range input.Context {
		if s, ok := v.(string); ok {
			n += len(s)
		}
	}
	return n
}

// evaluateLayer runs one layer under an "evaluate layer" span.
func (*Engine) evaluateLayer(ctx context.Context, ev *evaluation, name string, run func(context.Context, *evaluation)) {
	ctx, span := telemetry.Tracer().Start(ctx, "evaluate layer", trace.WithAttributes(
		attribute.String("shield.scan.layer", name),
	))
	defer span.End()
	before := len(ev.findings)
	run(ctx, ev)
	span.SetAttributes(attribute.Int("shield.scan.findings", len(ev.findings)-before))
}

// persist stores the result. Unless Config.StoreRedacted is set the stored
// row drops Redacted, and nil collections are stored empty.
func (e *Engine) persist(ctx context.Context, result *scan.Result) error {
	stored := *result
	if !e.config.StoreRedacted {
		stored.Redacted = ""
	}
	if stored.Findings == nil {
		stored.Findings = []*scan.Finding{}
	}
	if stored.PoliciesUsed == nil {
		stored.PoliciesUsed = []string{}
	}
	if stored.Metadata == nil {
		stored.Metadata = map[string]any{}
	}
	if err := e.store.CreateScan(ctx, &stored); err != nil {
		return err
	}
	result.Entity = stored.Entity
	return nil
}

// Health checks the health of the engine by pinging its store.
func (e *Engine) Health(ctx context.Context) error {
	if e.store != nil {
		return e.store.Ping(ctx)
	}
	return errors.New("shield: persistence is not configured")
}

// Store returns the composite store (may be nil if not configured).
func (e *Engine) Store() store.Store { return e.store }

// Stop gracefully shuts down the engine.
func (e *Engine) Stop(ctx context.Context) error {
	e.registry.EmitShutdown(ctx)
	return nil
}
