package ext

import (
	"context"
	"log/slog"
	"time"

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

// Registry holds registered extensions and dispatches lifecycle events.
// It type-caches extensions at registration time so emit calls iterate
// only over extensions that implement the relevant hook.
type Registry struct {
	extensions []Extension
	logger     *slog.Logger

	scanStarted           []scanStartedEntry
	scanCompleted         []scanCompletedEntry
	scanBlocked           []scanBlockedEntry
	scanFailed            []scanFailedEntry
	instinctTriggered     []instinctTriggeredEntry
	awarenessDetected     []awarenessDetectedEntry
	judgmentAssessed       []judgmentAssessedEntry
	valueViolated         []valueViolatedEntry
	reflexFired           []reflexFiredEntry
	boundaryEnforced      []boundaryEnforcedEntry
	piiDetected           []piiDetectedEntry
	piiRedacted           []piiRedactedEntry
	policyEvaluated       []policyEvaluatedEntry
	safetyProfileResolved []safetyProfileResolvedEntry
	shutdown              []shutdownEntry
}

// NewRegistry creates a new extension registry.
func NewRegistry(logger *slog.Logger) *Registry {
	if logger == nil {
		logger = slog.Default()
	}
	return &Registry{logger: logger}
}

// Register adds an extension and type-caches its hook implementations.
func (r *Registry) Register(e Extension) {
	r.extensions = append(r.extensions, e)
	name := e.Name()

	if h, ok := e.(ScanStarted); ok {
		r.scanStarted = append(r.scanStarted, scanStartedEntry{name, h})
	}
	if h, ok := e.(ScanCompleted); ok {
		r.scanCompleted = append(r.scanCompleted, scanCompletedEntry{name, h})
	}
	if h, ok := e.(ScanBlocked); ok {
		r.scanBlocked = append(r.scanBlocked, scanBlockedEntry{name, h})
	}
	if h, ok := e.(ScanFailed); ok {
		r.scanFailed = append(r.scanFailed, scanFailedEntry{name, h})
	}
	if h, ok := e.(InstinctTriggered); ok {
		r.instinctTriggered = append(r.instinctTriggered, instinctTriggeredEntry{name, h})
	}
	if h, ok := e.(AwarenessDetected); ok {
		r.awarenessDetected = append(r.awarenessDetected, awarenessDetectedEntry{name, h})
	}
	if h, ok := e.(JudgmentAssessed); ok {
		r.judgmentAssessed = append(r.judgmentAssessed, judgmentAssessedEntry{name, h})
	}
	if h, ok := e.(ValueViolated); ok {
		r.valueViolated = append(r.valueViolated, valueViolatedEntry{name, h})
	}
	if h, ok := e.(ReflexFired); ok {
		r.reflexFired = append(r.reflexFired, reflexFiredEntry{name, h})
	}
	if h, ok := e.(BoundaryEnforced); ok {
		r.boundaryEnforced = append(r.boundaryEnforced, boundaryEnforcedEntry{name, h})
	}
	if h, ok := e.(PIIDetected); ok {
		r.piiDetected = append(r.piiDetected, piiDetectedEntry{name, h})
	}
	if h, ok := e.(PIIRedacted); ok {
		r.piiRedacted = append(r.piiRedacted, piiRedactedEntry{name, h})
	}
	if h, ok := e.(PolicyEvaluated); ok {
		r.policyEvaluated = append(r.policyEvaluated, policyEvaluatedEntry{name, h})
	}
	if h, ok := e.(SafetyProfileResolved); ok {
		r.safetyProfileResolved = append(r.safetyProfileResolved, safetyProfileResolvedEntry{name, h})
	}
	if h, ok := e.(Shutdown); ok {
		r.shutdown = append(r.shutdown, shutdownEntry{name, h})
	}
}

// ── Emit methods ─────────────────────────────────────

// EmitScanStarted notifies all extensions that implement ScanStarted.
func (r *Registry) EmitScanStarted(ctx context.Context, scanID id.ScanID, direction string, text string) {
	for _, e := range r.scanStarted {
		if err := e.hook.OnScanStarted(ctx, scanID, direction, text); err != nil {
			r.logger.Warn("ext: hook error", "hook", "ScanStarted", "extension", e.name, "error", err)
		}
	}
}

// EmitScanCompleted notifies all extensions that implement ScanCompleted.
func (r *Registry) EmitScanCompleted(ctx context.Context, scanID id.ScanID, decision string, findingCount int, elapsed time.Duration) {
	for _, e := range r.scanCompleted {
		if err := e.hook.OnScanCompleted(ctx, scanID, decision, findingCount, elapsed); err != nil {
			r.logger.Warn("ext: hook error", "hook", "ScanCompleted", "extension", e.name, "error", err)
		}
	}
}

// EmitScanBlocked notifies all extensions that implement ScanBlocked.
func (r *Registry) EmitScanBlocked(ctx context.Context, scanID id.ScanID, reason string) {
	for _, e := range r.scanBlocked {
		if err := e.hook.OnScanBlocked(ctx, scanID, reason); err != nil {
			r.logger.Warn("ext: hook error", "hook", "ScanBlocked", "extension", e.name, "error", err)
		}
	}
}

// EmitScanFailed notifies all extensions that implement ScanFailed.
func (r *Registry) EmitScanFailed(ctx context.Context, scanID id.ScanID, err error) {
	for _, e := range r.scanFailed {
		if hookErr := e.hook.OnScanFailed(ctx, scanID, err); hookErr != nil {
			r.logger.Warn("ext: hook error", "hook", "ScanFailed", "extension", e.name, "error", hookErr)
		}
	}
}

// EmitInstinctTriggered notifies all extensions that implement InstinctTriggered.
func (r *Registry) EmitInstinctTriggered(ctx context.Context, scanID id.ScanID, instinctName string, score float64) {
	for _, e := range r.instinctTriggered {
		if err := e.hook.OnInstinctTriggered(ctx, scanID, instinctName, score); err != nil {
			r.logger.Warn("ext: hook error", "hook", "InstinctTriggered", "extension", e.name, "error", err)
		}
	}
}

// EmitAwarenessDetected notifies all extensions that implement AwarenessDetected.
func (r *Registry) EmitAwarenessDetected(ctx context.Context, scanID id.ScanID, detectorName string, findingCount int) {
	for _, e := range r.awarenessDetected {
		if err := e.hook.OnAwarenessDetected(ctx, scanID, detectorName, findingCount); err != nil {
			r.logger.Warn("ext: hook error", "hook", "AwarenessDetected", "extension", e.name, "error", err)
		}
	}
}

// EmitJudgmentAssessed notifies all extensions that implement JudgmentAssessed.
func (r *Registry) EmitJudgmentAssessed(ctx context.Context, scanID id.ScanID, assessorName string, riskLevel string, confidence float64) {
	for _, e := range r.judgmentAssessed {
		if err := e.hook.OnJudgmentAssessed(ctx, scanID, assessorName, riskLevel, confidence); err != nil {
			r.logger.Warn("ext: hook error", "hook", "JudgmentAssessed", "extension", e.name, "error", err)
		}
	}
}

// EmitValueViolated notifies all extensions that implement ValueViolated.
func (r *Registry) EmitValueViolated(ctx context.Context, scanID id.ScanID, valueName string, severity string) {
	for _, e := range r.valueViolated {
		if err := e.hook.OnValueViolated(ctx, scanID, valueName, severity); err != nil {
			r.logger.Warn("ext: hook error", "hook", "ValueViolated", "extension", e.name, "error", err)
		}
	}
}

// EmitReflexFired notifies all extensions that implement ReflexFired.
func (r *Registry) EmitReflexFired(ctx context.Context, scanID id.ScanID, reflexName string, action string) {
	for _, e := range r.reflexFired {
		if err := e.hook.OnReflexFired(ctx, scanID, reflexName, action); err != nil {
			r.logger.Warn("ext: hook error", "hook", "ReflexFired", "extension", e.name, "error", err)
		}
	}
}

// EmitBoundaryEnforced notifies all extensions that implement BoundaryEnforced.
func (r *Registry) EmitBoundaryEnforced(ctx context.Context, scanID id.ScanID, boundaryName string) {
	for _, e := range r.boundaryEnforced {
		if err := e.hook.OnBoundaryEnforced(ctx, scanID, boundaryName); err != nil {
			r.logger.Warn("ext: hook error", "hook", "BoundaryEnforced", "extension", e.name, "error", err)
		}
	}
}

// EmitPIIDetected notifies all extensions that implement PIIDetected.
func (r *Registry) EmitPIIDetected(ctx context.Context, scanID id.ScanID, piiType string, count int) {
	for _, e := range r.piiDetected {
		if err := e.hook.OnPIIDetected(ctx, scanID, piiType, count); err != nil {
			r.logger.Warn("ext: hook error", "hook", "PIIDetected", "extension", e.name, "error", err)
		}
	}
}

// EmitPIIRedacted notifies all extensions that implement PIIRedacted.
func (r *Registry) EmitPIIRedacted(ctx context.Context, scanID id.ScanID, piiType string, count int) {
	for _, e := range r.piiRedacted {
		if err := e.hook.OnPIIRedacted(ctx, scanID, piiType, count); err != nil {
			r.logger.Warn("ext: hook error", "hook", "PIIRedacted", "extension", e.name, "error", err)
		}
	}
}

// EmitPolicyEvaluated notifies all extensions that implement PolicyEvaluated.
func (r *Registry) EmitPolicyEvaluated(ctx context.Context, scanID id.ScanID, policyName string, decision string) {
	for _, e := range r.policyEvaluated {
		if err := e.hook.OnPolicyEvaluated(ctx, scanID, policyName, decision); err != nil {
			r.logger.Warn("ext: hook error", "hook", "PolicyEvaluated", "extension", e.name, "error", err)
		}
	}
}

// EmitSafetyProfileResolved notifies all extensions that implement SafetyProfileResolved.
func (r *Registry) EmitSafetyProfileResolved(ctx context.Context, scanID id.ScanID, profileName string) {
	for _, e := range r.safetyProfileResolved {
		if err := e.hook.OnSafetyProfileResolved(ctx, scanID, profileName); err != nil {
			r.logger.Warn("ext: hook error", "hook", "SafetyProfileResolved", "extension", e.name, "error", err)
		}
	}
}

// EmitShutdown notifies all extensions that implement Shutdown.
func (r *Registry) EmitShutdown(ctx context.Context) {
	for _, e := range r.shutdown {
		if err := e.hook.OnShutdown(ctx); err != nil {
			r.logger.Warn("ext: hook error", "hook", "Shutdown", "extension", e.name, "error", err)
		}
	}
}
