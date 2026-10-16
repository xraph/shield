package plugin

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	log "github.com/xraph/go-utils/log"

	"github.com/xraph/shield/id"
	"github.com/xraph/shield/internal/telemetry"
)

// The shield.plugin.hook span attribute values.
const (
	hookScanStarted           = "scan_started"
	hookScanCompleted         = "scan_completed"
	hookScanBlocked           = "scan_blocked"
	hookScanFailed            = "scan_failed"
	hookInstinctTriggered     = "instinct_triggered"
	hookAwarenessDetected     = "awareness_detected"
	hookJudgmentAssessed      = "judgment_assessed"
	hookValueViolated         = "value_violated"
	hookReflexFired           = "reflex_fired"
	hookBoundaryEnforced      = "boundary_enforced"
	hookPIIDetected           = "pii_detected"
	hookPIIRedacted           = "pii_redacted"
	hookPolicyEvaluated       = "policy_evaluated"
	hookSafetyProfileResolved = "safety_profile_resolved"
	hookShutdown              = "shutdown"
)

// entry pairs a plugin's name with one hook it implements.
type entry[H any] struct {
	name string
	hook H
}

// Registry holds registered plugins and dispatches lifecycle events.
// It type-caches plugins at registration time so emit calls iterate
// only over plugins that implement the relevant hook.
type Registry struct {
	plugins []Plugin
	logger  log.Logger

	scanStarted           []entry[ScanStarted]
	scanCompleted         []entry[ScanCompleted]
	scanBlocked           []entry[ScanBlocked]
	scanFailed            []entry[ScanFailed]
	instinctTriggered     []entry[InstinctTriggered]
	awarenessDetected     []entry[AwarenessDetected]
	judgmentAssessed      []entry[JudgmentAssessed]
	valueViolated         []entry[ValueViolated]
	reflexFired           []entry[ReflexFired]
	boundaryEnforced      []entry[BoundaryEnforced]
	piiDetected           []entry[PIIDetected]
	piiRedacted           []entry[PIIRedacted]
	policyEvaluated       []entry[PolicyEvaluated]
	safetyProfileResolved []entry[SafetyProfileResolved]
	shutdown              []entry[Shutdown]
}

// NewRegistry creates a new plugin registry.
func NewRegistry(logger log.Logger) *Registry {
	if logger == nil {
		logger = log.NewNoopLogger()
	}
	return &Registry{logger: logger}
}

// SetLogger replaces the logger hook errors are reported on. A nil l is
// ignored. Call it before the first Emit.
func (r *Registry) SetLogger(l log.Logger) {
	if l != nil {
		r.logger = l
	}
}

// run calls one hook on every plugin that implements it. When there is at
// least one, the calls share a "run plugin hooks" span under ctx, so a slow
// or failing plugin shows up inside the scan that triggered it. Hook errors
// are logged, never returned: a plugin can't fail a scan.
func run[H any](ctx context.Context, r *Registry, hook string, entries []entry[H], call func(context.Context, H) error) {
	if len(entries) == 0 {
		return
	}
	ctx, span := telemetry.Tracer().Start(ctx, "run plugin hooks", trace.WithAttributes(
		attribute.String("shield.plugin.hook", hook),
		attribute.Int("shield.plugin.count", len(entries)),
	))
	defer span.End()

	failures := 0
	for _, e := range entries {
		if err := call(ctx, e.hook); err != nil {
			failures++
			r.logger.Warn("plugin: hook error", log.String("hook", hook), log.String("plugin", e.name), log.Error(err))
			telemetry.Exception(span, err)
		}
	}
	if failures > 0 {
		span.SetAttributes(attribute.Int("shield.plugin.failures", failures))
		span.SetStatus(codes.Error, "plugin_hook_failed")
	}
}

// Register adds a plugin and type-caches its hook implementations.
func (r *Registry) Register(p Plugin) {
	r.plugins = append(r.plugins, p)
	name := p.Name()

	if h, ok := p.(ScanStarted); ok {
		r.scanStarted = append(r.scanStarted, entry[ScanStarted]{name, h})
	}
	if h, ok := p.(ScanCompleted); ok {
		r.scanCompleted = append(r.scanCompleted, entry[ScanCompleted]{name, h})
	}
	if h, ok := p.(ScanBlocked); ok {
		r.scanBlocked = append(r.scanBlocked, entry[ScanBlocked]{name, h})
	}
	if h, ok := p.(ScanFailed); ok {
		r.scanFailed = append(r.scanFailed, entry[ScanFailed]{name, h})
	}
	if h, ok := p.(InstinctTriggered); ok {
		r.instinctTriggered = append(r.instinctTriggered, entry[InstinctTriggered]{name, h})
	}
	if h, ok := p.(AwarenessDetected); ok {
		r.awarenessDetected = append(r.awarenessDetected, entry[AwarenessDetected]{name, h})
	}
	if h, ok := p.(JudgmentAssessed); ok {
		r.judgmentAssessed = append(r.judgmentAssessed, entry[JudgmentAssessed]{name, h})
	}
	if h, ok := p.(ValueViolated); ok {
		r.valueViolated = append(r.valueViolated, entry[ValueViolated]{name, h})
	}
	if h, ok := p.(ReflexFired); ok {
		r.reflexFired = append(r.reflexFired, entry[ReflexFired]{name, h})
	}
	if h, ok := p.(BoundaryEnforced); ok {
		r.boundaryEnforced = append(r.boundaryEnforced, entry[BoundaryEnforced]{name, h})
	}
	if h, ok := p.(PIIDetected); ok {
		r.piiDetected = append(r.piiDetected, entry[PIIDetected]{name, h})
	}
	if h, ok := p.(PIIRedacted); ok {
		r.piiRedacted = append(r.piiRedacted, entry[PIIRedacted]{name, h})
	}
	if h, ok := p.(PolicyEvaluated); ok {
		r.policyEvaluated = append(r.policyEvaluated, entry[PolicyEvaluated]{name, h})
	}
	if h, ok := p.(SafetyProfileResolved); ok {
		r.safetyProfileResolved = append(r.safetyProfileResolved, entry[SafetyProfileResolved]{name, h})
	}
	if h, ok := p.(Shutdown); ok {
		r.shutdown = append(r.shutdown, entry[Shutdown]{name, h})
	}
}

// ── Emit methods ─────────────────────────────────────

// EmitScanStarted notifies all plugins that implement ScanStarted.
func (r *Registry) EmitScanStarted(ctx context.Context, scanID id.ScanID, direction, text string) {
	run(ctx, r, hookScanStarted, r.scanStarted, func(ctx context.Context, h ScanStarted) error {
		return h.OnScanStarted(ctx, scanID, direction, text)
	})
}

// EmitScanCompleted notifies all plugins that implement ScanCompleted.
func (r *Registry) EmitScanCompleted(ctx context.Context, scanID id.ScanID, decision string, findingCount int, elapsed time.Duration) {
	run(ctx, r, hookScanCompleted, r.scanCompleted, func(ctx context.Context, h ScanCompleted) error {
		return h.OnScanCompleted(ctx, scanID, decision, findingCount, elapsed)
	})
}

// EmitScanBlocked notifies all plugins that implement ScanBlocked.
func (r *Registry) EmitScanBlocked(ctx context.Context, scanID id.ScanID, reason string) {
	run(ctx, r, hookScanBlocked, r.scanBlocked, func(ctx context.Context, h ScanBlocked) error {
		return h.OnScanBlocked(ctx, scanID, reason)
	})
}

// EmitScanFailed notifies all plugins that implement ScanFailed.
func (r *Registry) EmitScanFailed(ctx context.Context, scanID id.ScanID, err error) {
	run(ctx, r, hookScanFailed, r.scanFailed, func(ctx context.Context, h ScanFailed) error {
		return h.OnScanFailed(ctx, scanID, err)
	})
}

// EmitInstinctTriggered notifies all plugins that implement InstinctTriggered.
func (r *Registry) EmitInstinctTriggered(ctx context.Context, scanID id.ScanID, instinctName string, score float64) {
	run(ctx, r, hookInstinctTriggered, r.instinctTriggered, func(ctx context.Context, h InstinctTriggered) error {
		return h.OnInstinctTriggered(ctx, scanID, instinctName, score)
	})
}

// EmitAwarenessDetected notifies all plugins that implement AwarenessDetected.
func (r *Registry) EmitAwarenessDetected(ctx context.Context, scanID id.ScanID, detectorName string, findingCount int) {
	run(ctx, r, hookAwarenessDetected, r.awarenessDetected, func(ctx context.Context, h AwarenessDetected) error {
		return h.OnAwarenessDetected(ctx, scanID, detectorName, findingCount)
	})
}

// EmitJudgmentAssessed notifies all plugins that implement JudgmentAssessed.
func (r *Registry) EmitJudgmentAssessed(ctx context.Context, scanID id.ScanID, assessorName, riskLevel string, confidence float64) {
	run(ctx, r, hookJudgmentAssessed, r.judgmentAssessed, func(ctx context.Context, h JudgmentAssessed) error {
		return h.OnJudgmentAssessed(ctx, scanID, assessorName, riskLevel, confidence)
	})
}

// EmitValueViolated notifies all plugins that implement ValueViolated.
func (r *Registry) EmitValueViolated(ctx context.Context, scanID id.ScanID, valueName, severity string) {
	run(ctx, r, hookValueViolated, r.valueViolated, func(ctx context.Context, h ValueViolated) error {
		return h.OnValueViolated(ctx, scanID, valueName, severity)
	})
}

// EmitReflexFired notifies all plugins that implement ReflexFired.
func (r *Registry) EmitReflexFired(ctx context.Context, scanID id.ScanID, reflexName, action string) {
	run(ctx, r, hookReflexFired, r.reflexFired, func(ctx context.Context, h ReflexFired) error {
		return h.OnReflexFired(ctx, scanID, reflexName, action)
	})
}

// EmitBoundaryEnforced notifies all plugins that implement BoundaryEnforced.
func (r *Registry) EmitBoundaryEnforced(ctx context.Context, scanID id.ScanID, boundaryName string) {
	run(ctx, r, hookBoundaryEnforced, r.boundaryEnforced, func(ctx context.Context, h BoundaryEnforced) error {
		return h.OnBoundaryEnforced(ctx, scanID, boundaryName)
	})
}

// EmitPIIDetected notifies all plugins that implement PIIDetected.
func (r *Registry) EmitPIIDetected(ctx context.Context, scanID id.ScanID, piiType string, count int) {
	run(ctx, r, hookPIIDetected, r.piiDetected, func(ctx context.Context, h PIIDetected) error {
		return h.OnPIIDetected(ctx, scanID, piiType, count)
	})
}

// EmitPIIRedacted notifies all plugins that implement PIIRedacted.
func (r *Registry) EmitPIIRedacted(ctx context.Context, scanID id.ScanID, piiType string, count int) {
	run(ctx, r, hookPIIRedacted, r.piiRedacted, func(ctx context.Context, h PIIRedacted) error {
		return h.OnPIIRedacted(ctx, scanID, piiType, count)
	})
}

// EmitPolicyEvaluated notifies all plugins that implement PolicyEvaluated.
func (r *Registry) EmitPolicyEvaluated(ctx context.Context, scanID id.ScanID, policyName, decision string) {
	run(ctx, r, hookPolicyEvaluated, r.policyEvaluated, func(ctx context.Context, h PolicyEvaluated) error {
		return h.OnPolicyEvaluated(ctx, scanID, policyName, decision)
	})
}

// EmitSafetyProfileResolved notifies all plugins that implement SafetyProfileResolved.
func (r *Registry) EmitSafetyProfileResolved(ctx context.Context, scanID id.ScanID, profileName string) {
	run(ctx, r, hookSafetyProfileResolved, r.safetyProfileResolved, func(ctx context.Context, h SafetyProfileResolved) error {
		return h.OnSafetyProfileResolved(ctx, scanID, profileName)
	})
}

// EmitShutdown notifies all plugins that implement Shutdown.
func (r *Registry) EmitShutdown(ctx context.Context) {
	run(ctx, r, hookShutdown, r.shutdown, func(ctx context.Context, h Shutdown) error {
		return h.OnShutdown(ctx)
	})
}
