// Package observability provides a metrics extension for Shield that records
// lifecycle event counts via go-utils MetricFactory.
package observability

import (
	"context"
	"time"

	gu "github.com/xraph/go-utils/metrics"

	"github.com/xraph/shield/ext"
	"github.com/xraph/shield/id"
)

// Compile-time interface checks.
var (
	_ ext.Extension           = (*MetricsExtension)(nil)
	_ ext.ScanStarted         = (*MetricsExtension)(nil)
	_ ext.ScanCompleted       = (*MetricsExtension)(nil)
	_ ext.ScanBlocked         = (*MetricsExtension)(nil)
	_ ext.ScanFailed          = (*MetricsExtension)(nil)
	_ ext.InstinctTriggered   = (*MetricsExtension)(nil)
	_ ext.AwarenessDetected   = (*MetricsExtension)(nil)
	_ ext.JudgmentAssessed    = (*MetricsExtension)(nil)
	_ ext.ValueViolated       = (*MetricsExtension)(nil)
	_ ext.ReflexFired         = (*MetricsExtension)(nil)
	_ ext.BoundaryEnforced    = (*MetricsExtension)(nil)
	_ ext.PIIDetected         = (*MetricsExtension)(nil)
	_ ext.PIIRedacted         = (*MetricsExtension)(nil)
	_ ext.PolicyEvaluated     = (*MetricsExtension)(nil)
	_ ext.SafetyProfileResolved = (*MetricsExtension)(nil)
)

// MetricsExtension records system-wide lifecycle metrics via go-utils MetricFactory.
// Register it as a Shield extension to automatically track scan rates,
// instinct triggers, boundary enforcements, and other safety events.
type MetricsExtension struct {
	ScanStartedCount           gu.Counter
	ScanCompletedCount         gu.Counter
	ScanBlockedCount           gu.Counter
	ScanFailedCount            gu.Counter
	InstinctTriggeredCount     gu.Counter
	AwarenessDetectedCount     gu.Counter
	JudgmentAssessedCount      gu.Counter
	ValueViolatedCount         gu.Counter
	ReflexFiredCount           gu.Counter
	BoundaryEnforcedCount      gu.Counter
	PIIDetectedCount           gu.Counter
	PIIRedactedCount           gu.Counter
	PolicyEvaluatedCount       gu.Counter
	SafetyProfileResolvedCount gu.Counter
}

// NewMetricsExtension creates a MetricsExtension using a default metrics collector.
func NewMetricsExtension() *MetricsExtension {
	return NewMetricsExtensionWithFactory(gu.NewMetricsCollector("shield/observability"))
}

// NewMetricsExtensionWithFactory creates a MetricsExtension with the provided MetricFactory.
// Use fapp.Metrics() in forge extensions, or gu.NewMetricsCollector for testing.
func NewMetricsExtensionWithFactory(factory gu.MetricFactory) *MetricsExtension {
	return &MetricsExtension{
		ScanStartedCount:           factory.Counter("shield.scan.started"),
		ScanCompletedCount:         factory.Counter("shield.scan.completed"),
		ScanBlockedCount:           factory.Counter("shield.scan.blocked"),
		ScanFailedCount:            factory.Counter("shield.scan.failed"),
		InstinctTriggeredCount:     factory.Counter("shield.instinct.triggered"),
		AwarenessDetectedCount:     factory.Counter("shield.awareness.detected"),
		JudgmentAssessedCount:      factory.Counter("shield.judgment.assessed"),
		ValueViolatedCount:         factory.Counter("shield.value.violated"),
		ReflexFiredCount:           factory.Counter("shield.reflex.fired"),
		BoundaryEnforcedCount:      factory.Counter("shield.boundary.enforced"),
		PIIDetectedCount:           factory.Counter("shield.pii.detected"),
		PIIRedactedCount:           factory.Counter("shield.pii.redacted"),
		PolicyEvaluatedCount:       factory.Counter("shield.policy.evaluated"),
		SafetyProfileResolvedCount: factory.Counter("shield.profile.resolved"),
	}
}

// Name implements ext.Extension.
func (m *MetricsExtension) Name() string { return "observability-metrics" }

// ── Scan lifecycle hooks ──────────────────────────────

// OnScanStarted implements ext.ScanStarted.
func (m *MetricsExtension) OnScanStarted(_ context.Context, _ id.ScanID, _ string, _ string) error {
	m.ScanStartedCount.Inc()
	return nil
}

// OnScanCompleted implements ext.ScanCompleted.
func (m *MetricsExtension) OnScanCompleted(_ context.Context, _ id.ScanID, _ string, _ int, _ time.Duration) error {
	m.ScanCompletedCount.Inc()
	return nil
}

// OnScanBlocked implements ext.ScanBlocked.
func (m *MetricsExtension) OnScanBlocked(_ context.Context, _ id.ScanID, _ string) error {
	m.ScanBlockedCount.Inc()
	return nil
}

// OnScanFailed implements ext.ScanFailed.
func (m *MetricsExtension) OnScanFailed(_ context.Context, _ id.ScanID, _ error) error {
	m.ScanFailedCount.Inc()
	return nil
}

// ── Safety primitive lifecycle hooks ──────────────────

// OnInstinctTriggered implements ext.InstinctTriggered.
func (m *MetricsExtension) OnInstinctTriggered(_ context.Context, _ id.ScanID, _ string, _ float64) error {
	m.InstinctTriggeredCount.Inc()
	return nil
}

// OnAwarenessDetected implements ext.AwarenessDetected.
func (m *MetricsExtension) OnAwarenessDetected(_ context.Context, _ id.ScanID, _ string, _ int) error {
	m.AwarenessDetectedCount.Inc()
	return nil
}

// OnJudgmentAssessed implements ext.JudgmentAssessed.
func (m *MetricsExtension) OnJudgmentAssessed(_ context.Context, _ id.ScanID, _ string, _ string, _ float64) error {
	m.JudgmentAssessedCount.Inc()
	return nil
}

// OnValueViolated implements ext.ValueViolated.
func (m *MetricsExtension) OnValueViolated(_ context.Context, _ id.ScanID, _ string, _ string) error {
	m.ValueViolatedCount.Inc()
	return nil
}

// OnReflexFired implements ext.ReflexFired.
func (m *MetricsExtension) OnReflexFired(_ context.Context, _ id.ScanID, _ string, _ string) error {
	m.ReflexFiredCount.Inc()
	return nil
}

// OnBoundaryEnforced implements ext.BoundaryEnforced.
func (m *MetricsExtension) OnBoundaryEnforced(_ context.Context, _ id.ScanID, _ string) error {
	m.BoundaryEnforcedCount.Inc()
	return nil
}

// OnPIIDetected implements ext.PIIDetected.
func (m *MetricsExtension) OnPIIDetected(_ context.Context, _ id.ScanID, _ string, _ int) error {
	m.PIIDetectedCount.Inc()
	return nil
}

// OnPIIRedacted implements ext.PIIRedacted.
func (m *MetricsExtension) OnPIIRedacted(_ context.Context, _ id.ScanID, _ string, _ int) error {
	m.PIIRedactedCount.Inc()
	return nil
}

// OnPolicyEvaluated implements ext.PolicyEvaluated.
func (m *MetricsExtension) OnPolicyEvaluated(_ context.Context, _ id.ScanID, _ string, _ string) error {
	m.PolicyEvaluatedCount.Inc()
	return nil
}

// OnSafetyProfileResolved implements ext.SafetyProfileResolved.
func (m *MetricsExtension) OnSafetyProfileResolved(_ context.Context, _ id.ScanID, _ string) error {
	m.SafetyProfileResolvedCount.Inc()
	return nil
}
