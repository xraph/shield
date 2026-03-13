package plugin

import (
	"context"
	"time"

	log "github.com/xraph/go-utils/log"

	"github.com/xraph/shield/id"
)

// ── Entry types for type-cached slices ───────────────

type scanStartedEntry struct {
	name string
	hook ScanStarted
}

type scanCompletedEntry struct {
	name string
	hook ScanCompleted
}

type scanBlockedEntry struct {
	name string
	hook ScanBlocked
}

type scanFailedEntry struct {
	name string
	hook ScanFailed
}

type instinctTriggeredEntry struct {
	name string
	hook InstinctTriggered
}

type awarenessDetectedEntry struct {
	name string
	hook AwarenessDetected
}

type judgmentAssessedEntry struct {
	name string
	hook JudgmentAssessed
}

type valueViolatedEntry struct {
	name string
	hook ValueViolated
}

type reflexFiredEntry struct {
	name string
	hook ReflexFired
}

type boundaryEnforcedEntry struct {
	name string
	hook BoundaryEnforced
}

type piiDetectedEntry struct {
	name string
	hook PIIDetected
}

type piiRedactedEntry struct {
	name string
	hook PIIRedacted
}

type policyEvaluatedEntry struct {
	name string
	hook PolicyEvaluated
}

type safetyProfileResolvedEntry struct {
	name string
	hook SafetyProfileResolved
}

type shutdownEntry struct {
	name string
	hook Shutdown
}

// Registry holds registered plugins and dispatches lifecycle events.
// It type-caches plugins at registration time so emit calls iterate
// only over plugins that implement the relevant hook.
type Registry struct {
	plugins []Plugin
	logger  log.Logger

	scanStarted           []scanStartedEntry
	scanCompleted         []scanCompletedEntry
	scanBlocked           []scanBlockedEntry
	scanFailed            []scanFailedEntry
	instinctTriggered     []instinctTriggeredEntry
	awarenessDetected     []awarenessDetectedEntry
	judgmentAssessed      []judgmentAssessedEntry
	valueViolated         []valueViolatedEntry
	reflexFired           []reflexFiredEntry
	boundaryEnforced      []boundaryEnforcedEntry
	piiDetected           []piiDetectedEntry
	piiRedacted           []piiRedactedEntry
	policyEvaluated       []policyEvaluatedEntry
	safetyProfileResolved []safetyProfileResolvedEntry
	shutdown              []shutdownEntry
}

// NewRegistry creates a new plugin registry.
func NewRegistry(logger log.Logger) *Registry {
	if logger == nil {
		logger = log.NewNoopLogger()
	}
	return &Registry{logger: logger}
}

// Register adds a plugin and type-caches its hook implementations.
func (r *Registry) Register(p Plugin) {
	r.plugins = append(r.plugins, p)
	name := p.Name()

	if h, ok := p.(ScanStarted); ok {
		r.scanStarted = append(r.scanStarted, scanStartedEntry{name, h})
	}
	if h, ok := p.(ScanCompleted); ok {
		r.scanCompleted = append(r.scanCompleted, scanCompletedEntry{name, h})
	}
	if h, ok := p.(ScanBlocked); ok {
		r.scanBlocked = append(r.scanBlocked, scanBlockedEntry{name, h})
	}
	if h, ok := p.(ScanFailed); ok {
		r.scanFailed = append(r.scanFailed, scanFailedEntry{name, h})
	}
	if h, ok := p.(InstinctTriggered); ok {
		r.instinctTriggered = append(r.instinctTriggered, instinctTriggeredEntry{name, h})
	}
	if h, ok := p.(AwarenessDetected); ok {
		r.awarenessDetected = append(r.awarenessDetected, awarenessDetectedEntry{name, h})
	}
	if h, ok := p.(JudgmentAssessed); ok {
		r.judgmentAssessed = append(r.judgmentAssessed, judgmentAssessedEntry{name, h})
	}
	if h, ok := p.(ValueViolated); ok {
		r.valueViolated = append(r.valueViolated, valueViolatedEntry{name, h})
	}
	if h, ok := p.(ReflexFired); ok {
		r.reflexFired = append(r.reflexFired, reflexFiredEntry{name, h})
	}
	if h, ok := p.(BoundaryEnforced); ok {
		r.boundaryEnforced = append(r.boundaryEnforced, boundaryEnforcedEntry{name, h})
	}
	if h, ok := p.(PIIDetected); ok {
		r.piiDetected = append(r.piiDetected, piiDetectedEntry{name, h})
	}
	if h, ok := p.(PIIRedacted); ok {
		r.piiRedacted = append(r.piiRedacted, piiRedactedEntry{name, h})
	}
	if h, ok := p.(PolicyEvaluated); ok {
		r.policyEvaluated = append(r.policyEvaluated, policyEvaluatedEntry{name, h})
	}
	if h, ok := p.(SafetyProfileResolved); ok {
		r.safetyProfileResolved = append(r.safetyProfileResolved, safetyProfileResolvedEntry{name, h})
	}
	if h, ok := p.(Shutdown); ok {
		r.shutdown = append(r.shutdown, shutdownEntry{name, h})
	}
}

// ── Emit methods ─────────────────────────────────────

// EmitScanStarted notifies all plugins that implement ScanStarted.
func (r *Registry) EmitScanStarted(ctx context.Context, scanID id.ScanID, direction, text string) {
	for _, e := range r.scanStarted {
		if err := e.hook.OnScanStarted(ctx, scanID, direction, text); err != nil {
			r.logger.Warn("plugin: hook error", log.String("hook", "ScanStarted"), log.String("plugin", e.name), log.Error(err))
		}
	}
}

// EmitScanCompleted notifies all plugins that implement ScanCompleted.
func (r *Registry) EmitScanCompleted(ctx context.Context, scanID id.ScanID, decision string, findingCount int, elapsed time.Duration) {
	for _, e := range r.scanCompleted {
		if err := e.hook.OnScanCompleted(ctx, scanID, decision, findingCount, elapsed); err != nil {
			r.logger.Warn("plugin: hook error", log.String("hook", "ScanCompleted"), log.String("plugin", e.name), log.Error(err))
		}
	}
}

// EmitScanBlocked notifies all plugins that implement ScanBlocked.
func (r *Registry) EmitScanBlocked(ctx context.Context, scanID id.ScanID, reason string) {
	for _, e := range r.scanBlocked {
		if err := e.hook.OnScanBlocked(ctx, scanID, reason); err != nil {
			r.logger.Warn("plugin: hook error", log.String("hook", "ScanBlocked"), log.String("plugin", e.name), log.Error(err))
		}
	}
}

// EmitScanFailed notifies all plugins that implement ScanFailed.
func (r *Registry) EmitScanFailed(ctx context.Context, scanID id.ScanID, err error) {
	for _, e := range r.scanFailed {
		if hookErr := e.hook.OnScanFailed(ctx, scanID, err); hookErr != nil {
			r.logger.Warn("plugin: hook error", log.String("hook", "ScanFailed"), log.String("plugin", e.name), log.Error(hookErr))
		}
	}
}

// EmitInstinctTriggered notifies all plugins that implement InstinctTriggered.
func (r *Registry) EmitInstinctTriggered(ctx context.Context, scanID id.ScanID, instinctName string, score float64) {
	for _, e := range r.instinctTriggered {
		if err := e.hook.OnInstinctTriggered(ctx, scanID, instinctName, score); err != nil {
			r.logger.Warn("plugin: hook error", log.String("hook", "InstinctTriggered"), log.String("plugin", e.name), log.Error(err))
		}
	}
}

// EmitAwarenessDetected notifies all plugins that implement AwarenessDetected.
func (r *Registry) EmitAwarenessDetected(ctx context.Context, scanID id.ScanID, detectorName string, findingCount int) {
	for _, e := range r.awarenessDetected {
		if err := e.hook.OnAwarenessDetected(ctx, scanID, detectorName, findingCount); err != nil {
			r.logger.Warn("plugin: hook error", log.String("hook", "AwarenessDetected"), log.String("plugin", e.name), log.Error(err))
		}
	}
}

// EmitJudgmentAssessed notifies all plugins that implement JudgmentAssessed.
func (r *Registry) EmitJudgmentAssessed(ctx context.Context, scanID id.ScanID, assessorName, riskLevel string, confidence float64) {
	for _, e := range r.judgmentAssessed {
		if err := e.hook.OnJudgmentAssessed(ctx, scanID, assessorName, riskLevel, confidence); err != nil {
			r.logger.Warn("plugin: hook error", log.String("hook", "JudgmentAssessed"), log.String("plugin", e.name), log.Error(err))
		}
	}
}

// EmitValueViolated notifies all plugins that implement ValueViolated.
func (r *Registry) EmitValueViolated(ctx context.Context, scanID id.ScanID, valueName, severity string) {
	for _, e := range r.valueViolated {
		if err := e.hook.OnValueViolated(ctx, scanID, valueName, severity); err != nil {
			r.logger.Warn("plugin: hook error", log.String("hook", "ValueViolated"), log.String("plugin", e.name), log.Error(err))
		}
	}
}

// EmitReflexFired notifies all plugins that implement ReflexFired.
func (r *Registry) EmitReflexFired(ctx context.Context, scanID id.ScanID, reflexName, action string) {
	for _, e := range r.reflexFired {
		if err := e.hook.OnReflexFired(ctx, scanID, reflexName, action); err != nil {
			r.logger.Warn("plugin: hook error", log.String("hook", "ReflexFired"), log.String("plugin", e.name), log.Error(err))
		}
	}
}

// EmitBoundaryEnforced notifies all plugins that implement BoundaryEnforced.
func (r *Registry) EmitBoundaryEnforced(ctx context.Context, scanID id.ScanID, boundaryName string) {
	for _, e := range r.boundaryEnforced {
		if err := e.hook.OnBoundaryEnforced(ctx, scanID, boundaryName); err != nil {
			r.logger.Warn("plugin: hook error", log.String("hook", "BoundaryEnforced"), log.String("plugin", e.name), log.Error(err))
		}
	}
}

// EmitPIIDetected notifies all plugins that implement PIIDetected.
func (r *Registry) EmitPIIDetected(ctx context.Context, scanID id.ScanID, piiType string, count int) {
	for _, e := range r.piiDetected {
		if err := e.hook.OnPIIDetected(ctx, scanID, piiType, count); err != nil {
			r.logger.Warn("plugin: hook error", log.String("hook", "PIIDetected"), log.String("plugin", e.name), log.Error(err))
		}
	}
}

// EmitPIIRedacted notifies all plugins that implement PIIRedacted.
func (r *Registry) EmitPIIRedacted(ctx context.Context, scanID id.ScanID, piiType string, count int) {
	for _, e := range r.piiRedacted {
		if err := e.hook.OnPIIRedacted(ctx, scanID, piiType, count); err != nil {
			r.logger.Warn("plugin: hook error", log.String("hook", "PIIRedacted"), log.String("plugin", e.name), log.Error(err))
		}
	}
}

// EmitPolicyEvaluated notifies all plugins that implement PolicyEvaluated.
func (r *Registry) EmitPolicyEvaluated(ctx context.Context, scanID id.ScanID, policyName, decision string) {
	for _, e := range r.policyEvaluated {
		if err := e.hook.OnPolicyEvaluated(ctx, scanID, policyName, decision); err != nil {
			r.logger.Warn("plugin: hook error", log.String("hook", "PolicyEvaluated"), log.String("plugin", e.name), log.Error(err))
		}
	}
}

// EmitSafetyProfileResolved notifies all plugins that implement SafetyProfileResolved.
func (r *Registry) EmitSafetyProfileResolved(ctx context.Context, scanID id.ScanID, profileName string) {
	for _, e := range r.safetyProfileResolved {
		if err := e.hook.OnSafetyProfileResolved(ctx, scanID, profileName); err != nil {
			r.logger.Warn("plugin: hook error", log.String("hook", "SafetyProfileResolved"), log.String("plugin", e.name), log.Error(err))
		}
	}
}

// EmitShutdown notifies all plugins that implement Shutdown.
func (r *Registry) EmitShutdown(ctx context.Context) {
	for _, e := range r.shutdown {
		if err := e.hook.OnShutdown(ctx); err != nil {
			r.logger.Warn("plugin: hook error", log.String("hook", "Shutdown"), log.String("plugin", e.name), log.Error(err))
		}
	}
}
