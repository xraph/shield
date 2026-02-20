// Package audithook bridges Shield lifecycle events to an audit trail backend.
//
// It defines a local Recorder interface so the package does not import
// Chronicle directly. Callers inject a RecorderFunc adapter that bridges
// to Chronicle at wiring time.
package audithook

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/xraph/shield/ext"
	"github.com/xraph/shield/id"
)

// Compile-time interface checks.
var (
	_ ext.Extension             = (*Extension)(nil)
	_ ext.ScanStarted           = (*Extension)(nil)
	_ ext.ScanCompleted         = (*Extension)(nil)
	_ ext.ScanBlocked           = (*Extension)(nil)
	_ ext.ScanFailed            = (*Extension)(nil)
	_ ext.InstinctTriggered     = (*Extension)(nil)
	_ ext.AwarenessDetected     = (*Extension)(nil)
	_ ext.JudgmentAssessed      = (*Extension)(nil)
	_ ext.ValueViolated         = (*Extension)(nil)
	_ ext.ReflexFired           = (*Extension)(nil)
	_ ext.BoundaryEnforced      = (*Extension)(nil)
	_ ext.PIIDetected           = (*Extension)(nil)
	_ ext.PIIRedacted           = (*Extension)(nil)
	_ ext.PolicyEvaluated       = (*Extension)(nil)
	_ ext.SafetyProfileResolved = (*Extension)(nil)
)

// Recorder is the interface that audit backends must implement.
// This matches chronicle.Emitter but is defined locally so that the
// audit_hook package does not import Chronicle directly — callers inject
// the concrete *chronicle.Chronicle at wiring time.
type Recorder interface {
	Record(ctx context.Context, event *AuditEvent) error
}

// AuditEvent is a local representation of an audit event.
// It mirrors chronicle/audit.Event but avoids a module dependency.
type AuditEvent struct {
	Action     string         `json:"action"`
	Resource   string         `json:"resource"`
	Category   string         `json:"category"`
	ResourceID string         `json:"resource_id,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	Outcome    string         `json:"outcome"`
	Severity   string         `json:"severity"`
	Reason     string         `json:"reason,omitempty"`
}

// RecorderFunc is an adapter to use a plain function as a Recorder.
type RecorderFunc func(ctx context.Context, event *AuditEvent) error

// Record implements Recorder.
func (f RecorderFunc) Record(ctx context.Context, event *AuditEvent) error {
	return f(ctx, event)
}

// Extension bridges Shield lifecycle events to an audit trail backend.
type Extension struct {
	recorder Recorder
	enabled  map[string]bool // nil = all enabled
	logger   *slog.Logger
}

// New creates an Extension that emits audit events through the provided Recorder.
func New(r Recorder, opts ...Option) *Extension {
	e := &Extension{
		recorder: r,
		logger:   slog.Default(),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Name implements ext.Extension.
func (e *Extension) Name() string { return "audit-hook" }

// ── Scan lifecycle hooks ──────────────────────────────

// OnScanStarted implements ext.ScanStarted.
func (e *Extension) OnScanStarted(ctx context.Context, scanID id.ScanID, direction string, _ string) error {
	return e.record(ctx, ActionScanStarted, SeverityInfo, OutcomeSuccess,
		ResourceScan, scanID.String(), CategorySafety, nil,
		"direction", direction,
	)
}

// OnScanCompleted implements ext.ScanCompleted.
func (e *Extension) OnScanCompleted(ctx context.Context, scanID id.ScanID, decision string, findingCount int, elapsed time.Duration) error {
	return e.record(ctx, ActionScanCompleted, SeverityInfo, OutcomeSuccess,
		ResourceScan, scanID.String(), CategorySafety, nil,
		"decision", decision,
		"finding_count", findingCount,
		"elapsed_ms", elapsed.Milliseconds(),
	)
}

// OnScanBlocked implements ext.ScanBlocked.
func (e *Extension) OnScanBlocked(ctx context.Context, scanID id.ScanID, reason string) error {
	return e.record(ctx, ActionScanBlocked, SeverityWarning, OutcomeSuccess,
		ResourceScan, scanID.String(), CategorySafety, nil,
		"reason", reason,
	)
}

// OnScanFailed implements ext.ScanFailed.
func (e *Extension) OnScanFailed(ctx context.Context, scanID id.ScanID, scanErr error) error {
	return e.record(ctx, ActionScanFailed, SeverityCritical, OutcomeFailure,
		ResourceScan, scanID.String(), CategorySafety, scanErr,
	)
}

// ── Safety primitive lifecycle hooks ──────────────────

// OnInstinctTriggered implements ext.InstinctTriggered.
func (e *Extension) OnInstinctTriggered(ctx context.Context, scanID id.ScanID, instinctName string, score float64) error {
	return e.record(ctx, ActionInstinctTriggered, SeverityWarning, OutcomeSuccess,
		ResourceInstinct, scanID.String(), CategorySafety, nil,
		"instinct", instinctName,
		"score", score,
	)
}

// OnAwarenessDetected implements ext.AwarenessDetected.
func (e *Extension) OnAwarenessDetected(ctx context.Context, scanID id.ScanID, detectorName string, findingCount int) error {
	return e.record(ctx, ActionAwarenessDetected, SeverityInfo, OutcomeSuccess,
		ResourceAwareness, scanID.String(), CategorySafety, nil,
		"detector", detectorName,
		"finding_count", findingCount,
	)
}

// OnJudgmentAssessed implements ext.JudgmentAssessed.
func (e *Extension) OnJudgmentAssessed(ctx context.Context, scanID id.ScanID, assessorName string, riskLevel string, confidence float64) error {
	return e.record(ctx, ActionJudgmentAssessed, SeverityInfo, OutcomeSuccess,
		ResourceJudgment, scanID.String(), CategorySafety, nil,
		"assessor", assessorName,
		"risk_level", riskLevel,
		"confidence", confidence,
	)
}

// OnValueViolated implements ext.ValueViolated.
func (e *Extension) OnValueViolated(ctx context.Context, scanID id.ScanID, valueName string, severity string) error {
	return e.record(ctx, ActionValueViolated, SeverityWarning, OutcomeSuccess,
		ResourceValue, scanID.String(), CategorySafety, nil,
		"value", valueName,
		"violation_severity", severity,
	)
}

// OnReflexFired implements ext.ReflexFired.
func (e *Extension) OnReflexFired(ctx context.Context, scanID id.ScanID, reflexName string, action string) error {
	return e.record(ctx, ActionReflexFired, SeverityInfo, OutcomeSuccess,
		ResourceReflex, scanID.String(), CategoryGovernance, nil,
		"reflex", reflexName,
		"action", action,
	)
}

// OnBoundaryEnforced implements ext.BoundaryEnforced.
func (e *Extension) OnBoundaryEnforced(ctx context.Context, scanID id.ScanID, boundaryName string) error {
	return e.record(ctx, ActionBoundaryEnforced, SeverityWarning, OutcomeSuccess,
		ResourceBoundary, scanID.String(), CategorySafety, nil,
		"boundary", boundaryName,
	)
}

// ── PII lifecycle hooks ───────────────────────────────

// OnPIIDetected implements ext.PIIDetected.
func (e *Extension) OnPIIDetected(ctx context.Context, scanID id.ScanID, piiType string, count int) error {
	return e.record(ctx, ActionPIIDetected, SeverityWarning, OutcomeSuccess,
		ResourcePII, scanID.String(), CategoryPrivacy, nil,
		"pii_type", piiType,
		"count", count,
	)
}

// OnPIIRedacted implements ext.PIIRedacted.
func (e *Extension) OnPIIRedacted(ctx context.Context, scanID id.ScanID, piiType string, count int) error {
	return e.record(ctx, ActionPIIRedacted, SeverityInfo, OutcomeSuccess,
		ResourcePII, scanID.String(), CategoryPrivacy, nil,
		"pii_type", piiType,
		"count", count,
	)
}

// ── Policy lifecycle hooks ────────────────────────────

// OnPolicyEvaluated implements ext.PolicyEvaluated.
func (e *Extension) OnPolicyEvaluated(ctx context.Context, scanID id.ScanID, policyName string, decision string) error {
	return e.record(ctx, ActionPolicyCreated, SeverityInfo, OutcomeSuccess,
		ResourcePolicy, scanID.String(), CategoryGovernance, nil,
		"policy", policyName,
		"decision", decision,
	)
}

// OnSafetyProfileResolved implements ext.SafetyProfileResolved.
func (e *Extension) OnSafetyProfileResolved(ctx context.Context, scanID id.ScanID, profileName string) error {
	return e.record(ctx, ActionProfileResolved, SeverityInfo, OutcomeSuccess,
		ResourceProfile, scanID.String(), CategorySafety, nil,
		"profile", profileName,
	)
}

// ── Internal helpers ──────────────────────────────────

// record builds and sends an audit event if the action is enabled.
func (e *Extension) record(
	ctx context.Context,
	action, severity, outcome string,
	resource, resourceID, category string,
	err error,
	kvPairs ...any,
) error {
	if e.enabled != nil && !e.enabled[action] {
		return nil
	}

	meta := make(map[string]any, len(kvPairs)/2+1)
	for i := 0; i+1 < len(kvPairs); i += 2 {
		key, ok := kvPairs[i].(string)
		if !ok {
			key = fmt.Sprintf("%v", kvPairs[i])
		}
		meta[key] = kvPairs[i+1]
	}

	var reason string
	if err != nil {
		reason = err.Error()
		meta["error"] = err.Error()
	}

	evt := &AuditEvent{
		Action:     action,
		Resource:   resource,
		Category:   category,
		ResourceID: resourceID,
		Metadata:   meta,
		Outcome:    outcome,
		Severity:   severity,
		Reason:     reason,
	}

	if recErr := e.recorder.Record(ctx, evt); recErr != nil {
		e.logger.Warn("audit_hook: failed to record audit event",
			"action", action,
			"resource_id", resourceID,
			"error", recErr,
		)
	}
	return nil
}
