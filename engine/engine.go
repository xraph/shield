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
// Each layer can short-circuit: if instincts detect a prompt injection
// with high confidence, the engine skips deeper layers.
package engine

import (
	"context"
	"time"

	log "github.com/xraph/go-utils/log"

	"github.com/xraph/shield"
	"github.com/xraph/shield/id"
	"github.com/xraph/shield/plugin"
	"github.com/xraph/shield/scan"
	"github.com/xraph/shield/store"
)

// Engine is the core safety execution engine.
type Engine struct {
	store    store.Store
	registry *plugin.Registry
	config   shield.Config
	logger   log.Logger
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

// WithLogger sets a custom logger.
func WithLogger(l log.Logger) Option {
	return func(e *Engine) { e.logger = l }
}

// New creates a new safety engine with the given options.
func New(opts ...Option) (*Engine, error) {
	e := &Engine{
		registry: plugin.NewRegistry(log.NewNoopLogger()),
		config:   shield.DefaultConfig(),
		logger:   log.NewNoopLogger(),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e, nil
}

// ScanInput runs a safety scan on input content (user→agent).
func (e *Engine) ScanInput(ctx context.Context, input *scan.Input) (*scan.Result, error) {
	input.Direction = scan.DirectionInput
	return e.executeScan(ctx, input)
}

// ScanOutput runs a safety scan on output content (agent→user).
func (e *Engine) ScanOutput(ctx context.Context, input *scan.Input) (*scan.Result, error) {
	input.Direction = scan.DirectionOutput
	return e.executeScan(ctx, input)
}

// executeScan runs the layered safety evaluation.
func (e *Engine) executeScan(ctx context.Context, input *scan.Input) (*scan.Result, error) {
	start := time.Now()
	scanID := id.NewScanID()

	result := &scan.Result{
		ID:        scanID,
		Direction: input.Direction,
		Decision:  scan.DecisionAllow,
		TenantID:  shield.TenantFromContext(ctx),
		AppID:     shield.AppFromContext(ctx),
	}

	// Emit scan started
	e.registry.EmitScanStarted(ctx, scanID, string(input.Direction), input.Text)

	// Layer 1: INSTINCTS — fastest, pre-conscious threat detection
	// TODO: Execute registered instincts

	// Layer 2: AWARENESS — perception, what you notice
	// TODO: Execute registered awareness detectors

	// Layer 3: BOUNDARIES — hard limits, binary check
	// TODO: Execute registered boundaries

	// Layer 4: VALUES — ethical evaluation
	// TODO: Execute registered values

	// Layer 5: JUDGMENT — contextual assessment
	// TODO: Execute registered judgments

	// Layer 6: REFLEXES — policy-driven condition→action
	// TODO: Execute registered reflexes

	result.Duration = time.Since(start)

	// Emit scan completed
	e.registry.EmitScanCompleted(ctx, scanID, string(result.Decision), len(result.Findings), result.Duration)

	if result.Blocked {
		e.registry.EmitScanBlocked(ctx, scanID, string(result.Decision))
	}

	// Persist result
	if e.store != nil {
		if err := e.store.CreateScan(ctx, result); err != nil {
			e.logger.Warn("engine: failed to persist scan result", log.String("scan_id", scanID.String()), log.Error(err))
		}
	}

	return result, nil
}

// Health checks the health of the engine by pinging its store.
func (e *Engine) Health(ctx context.Context) error {
	if e.store != nil {
		return e.store.Ping(ctx)
	}
	return nil
}

// Store returns the composite store (may be nil if not configured).
func (e *Engine) Store() store.Store { return e.store }

// Stop gracefully shuts down the engine.
func (e *Engine) Stop(ctx context.Context) error {
	e.registry.EmitShutdown(ctx)
	return nil
}
