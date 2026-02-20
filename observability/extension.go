// Package observability provides a metrics extension for Shield that records
// lifecycle event counts via go-utils MetricFactory.
package observability

import (
	"context"
	"time"

	gu "github.com/xraph/go-utils/metrics"

	"github.com/xraph/shield/plugin"
	"github.com/xraph/shield/id"
)

// Compile-time interface checks.
var (
	_ plugin.Plugin           = (*MetricsExtension)(nil)
	_ plugin.ScanStarted         = (*MetricsExtension)(nil)
	_ plugin.ScanCompleted       = (*MetricsExtension)(nil)
	_ plugin.ScanBlocked         = (*MetricsExtension)(nil)
	_ plugin.ScanFailed          = (*MetricsExtension)(nil)
	_ plugin.InstinctTriggered   = (*MetricsExtension)(nil)
	_ plugin.AwarenessDetected   = (*MetricsExtension)(nil)
	_ plugin.JudgmentAssessed    = (*MetricsExtension)(nil)
	_ plugin.ValueViolated       = (*MetricsExtension)(nil)
	_ plugin.ReflexFired         = (*MetricsExtension)(nil)
	_ plugin.BoundaryEnforced    = (*MetricsExtension)(nil)
	_ plugin.PIIDetected         = (*MetricsExtension)(nil)
	_ plugin.PIIRedacted         = (*MetricsExtension)(nil)
	_ plugin.PolicyEvaluated     = (*MetricsExtension)(nil)
	_ plugin.SafetyProfileResolved = (*MetricsExtension)(nil)
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

// Name implements plugin.Plugin.
func (m *MetricsExtension) Name() string { return "observability-metrics" }

// ── Scan lifecycle hooks ──────────────────────────────

// OnScanStarted implements plugin.ScanStarted.
func (m *MetricsExtension) OnScanStarted(_ context.Context, _ id.ScanID, _ string, _ string) error {
	m.ScanStartedCount.Inc()
	return nil
}

// OnScanCompleted implements plugin.ScanCompleted.
func (m *MetricsExtension) OnScanCompleted(_ context.Context, _ id.ScanID, _ string, _ int, _ time.Duration) error {
	m.ScanCompletedCount.Inc()
	return nil
}

// OnScanBlocked implements plugin.ScanBlocked.
func (m *MetricsExtension) OnScanBlocked(_ context.Context, _ id.ScanID, _ string) error {
	m.ScanBlockedCount.Inc()
	return nil
}

// OnScanFailed implements plugin.ScanFailed.
func (m *MetricsExtension) OnScanFailed(_ context.Context, _ id.ScanID, _ error) error {
	m.ScanFailedCount.Inc()
	return nil
}

// ── Safety primitive lifecycle hooks ──────────────────

// OnInstinctTriggered implements plugin.InstinctTriggered.
func (m *MetricsExtension) OnInstinctTriggered(_ context.Context, _ id.ScanID, _ string, _ float64) error {
	m.InstinctTriggeredCount.Inc()
	return nil
}

// OnAwarenessDetected implements plugin.AwarenessDetected.
func (m *MetricsExtension) OnAwarenessDetected(_ context.Context, _ id.ScanID, _ string, _ int) error {
	m.AwarenessDetectedCount.Inc()
	return nil
}

// OnJudgmentAssessed implements plugin.JudgmentAssessed.
func (m *MetricsExtension) OnJudgmentAssessed(_ context.Context, _ id.ScanID, _ string, _ string, _ float64) error {
	m.JudgmentAssessedCount.Inc()
	return nil
}

// OnValueViolated implements plugin.ValueViolated.
func (m *MetricsExtension) OnValueViolated(_ context.Context, _ id.ScanID, _ string, _ string) error {
	m.ValueViolatedCount.Inc()
	return nil
}

// OnReflexFired implements plugin.ReflexFired.
func (m *MetricsExtension) OnReflexFired(_ context.Context, _ id.ScanID, _ string, _ string) error {
	m.ReflexFiredCount.Inc()
	return nil
}

// OnBoundaryEnforced implements plugin.BoundaryEnforced.
func (m *MetricsExtension) OnBoundaryEnforced(_ context.Context, _ id.ScanID, _ string) error {
	m.BoundaryEnforcedCount.Inc()
	return nil
}

// OnPIIDetected implements plugin.PIIDetected.
func (m *MetricsExtension) OnPIIDetected(_ context.Context, _ id.ScanID, _ string, _ int) error {
	m.PIIDetectedCount.Inc()
	return nil
}

// OnPIIRedacted implements plugin.PIIRedacted.
func (m *MetricsExtension) OnPIIRedacted(_ context.Context, _ id.ScanID, _ string, _ int) error {
	m.PIIRedactedCount.Inc()
	return nil
}

// OnPolicyEvaluated implements plugin.PolicyEvaluated.
func (m *MetricsExtension) OnPolicyEvaluated(_ context.Context, _ id.ScanID, _ string, _ string) error {
	m.PolicyEvaluatedCount.Inc()
	return nil
}

// OnSafetyProfileResolved implements plugin.SafetyProfileResolved.
func (m *MetricsExtension) OnSafetyProfileResolved(_ context.Context, _ id.ScanID, _ string) error {
	m.SafetyProfileResolvedCount.Inc()
	return nil
}
