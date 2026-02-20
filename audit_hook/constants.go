package audithook

// Severity levels for audit events.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Outcome values for audit events.
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
)

// Action constants for Shield audit events.
const (
	ActionScanStarted       = "shield.scan.started"
	ActionScanCompleted     = "shield.scan.completed"
	ActionScanBlocked       = "shield.scan.blocked"
	ActionScanFailed        = "shield.scan.failed"
	ActionInstinctTriggered = "shield.instinct.triggered"
	ActionAwarenessDetected = "shield.awareness.detected"
	ActionJudgmentAssessed  = "shield.judgment.assessed"
	ActionValueViolated     = "shield.value.violated"
	ActionReflexFired       = "shield.reflex.fired"
	ActionBoundaryEnforced  = "shield.boundary.enforced"
	ActionPIIDetected       = "shield.pii.detected"
	ActionPIIRedacted       = "shield.pii.redacted"
	ActionPolicyCreated     = "shield.policy.created"
	ActionPolicyAssigned    = "shield.policy.assigned"
	ActionComplianceReport  = "shield.compliance.generated"
	ActionProfileResolved   = "shield.profile.resolved"
)

// Resource constants for audit events.
const (
	ResourceScan       = "scan"
	ResourceInstinct   = "instinct"
	ResourceAwareness  = "awareness"
	ResourceJudgment   = "judgment"
	ResourceValue      = "value"
	ResourceReflex     = "reflex"
	ResourceBoundary   = "boundary"
	ResourcePII        = "pii"
	ResourcePolicy     = "policy"
	ResourceCompliance = "compliance"
	ResourceProfile    = "profile"
)

// Category constants for audit events.
const (
	CategorySafety     = "safety"
	CategoryPrivacy    = "privacy"
	CategoryCompliance = "compliance"
	CategoryGovernance = "governance"
)
