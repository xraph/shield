// Package ext defines the Shield extension system with opt-in lifecycle hooks.
//
// Extensions implement the base Extension interface and optionally implement
// one or more lifecycle hook interfaces to receive events they care about.
// This follows the same pattern used by Weave and Cortex.
package ext

import (
	"context"
	"time"

	"github.com/xraph/shield/id"
)

// Extension is the base interface all Shield extensions must implement.
type Extension interface {
	Name() string
}

// ── Scan lifecycle hooks ─────────────────────────────

// ScanStarted is called when a safety scan begins.
type ScanStarted interface {
	OnScanStarted(ctx context.Context, scanID id.ScanID, direction string, text string) error
}

// ScanCompleted is called when a scan finishes successfully.
type ScanCompleted interface {
	OnScanCompleted(ctx context.Context, scanID id.ScanID, decision string, findingCount int, elapsed time.Duration) error
}

// ScanBlocked is called when a scan results in content being blocked.
type ScanBlocked interface {
	OnScanBlocked(ctx context.Context, scanID id.ScanID, reason string) error
}

// ScanFailed is called when a scan fails with an error.
type ScanFailed interface {
	OnScanFailed(ctx context.Context, scanID id.ScanID, err error) error
}

// ── Safety primitive lifecycle hooks ─────────────────

// InstinctTriggered is called when a safety instinct fires.
type InstinctTriggered interface {
	OnInstinctTriggered(ctx context.Context, scanID id.ScanID, instinctName string, score float64) error
}

// AwarenessDetected is called when awareness detects something notable.
type AwarenessDetected interface {
	OnAwarenessDetected(ctx context.Context, scanID id.ScanID, detectorName string, findingCount int) error
}

// JudgmentAssessed is called when a judgment assessor produces a risk assessment.
type JudgmentAssessed interface {
	OnJudgmentAssessed(ctx context.Context, scanID id.ScanID, assessorName string, riskLevel string, confidence float64) error
}

// ValueViolated is called when content violates a value rule.
type ValueViolated interface {
	OnValueViolated(ctx context.Context, scanID id.ScanID, valueName string, severity string) error
}

// ReflexFired is called when a safety reflex triggers an action.
type ReflexFired interface {
	OnReflexFired(ctx context.Context, scanID id.ScanID, reflexName string, action string) error
}

// BoundaryEnforced is called when a boundary prevents an action.
type BoundaryEnforced interface {
	OnBoundaryEnforced(ctx context.Context, scanID id.ScanID, boundaryName string) error
}

// ── PII lifecycle hooks ──────────────────────────────

// PIIDetected is called when PII is found in content.
type PIIDetected interface {
	OnPIIDetected(ctx context.Context, scanID id.ScanID, piiType string, count int) error
}

// PIIRedacted is called when PII is redacted from content.
type PIIRedacted interface {
	OnPIIRedacted(ctx context.Context, scanID id.ScanID, piiType string, count int) error
}

// ── Policy lifecycle hooks ───────────────────────────

// PolicyEvaluated is called when a policy is evaluated.
type PolicyEvaluated interface {
	OnPolicyEvaluated(ctx context.Context, scanID id.ScanID, policyName string, decision string) error
}

// ── SafetyProfile lifecycle hooks ────────────────────

// SafetyProfileResolved is called when a safety profile is resolved for a scan.
type SafetyProfileResolved interface {
	OnSafetyProfileResolved(ctx context.Context, scanID id.ScanID, profileName string) error
}

// ── Shutdown hook ────────────────────────────────────

// Shutdown is called during graceful shutdown.
type Shutdown interface {
	OnShutdown(ctx context.Context) error
}
