// Package id provides TypeID-based identity types for all Shield entities.
//
// Every entity in Shield gets a type-prefixed, K-sortable, UUIDv7-based
// identifier. IDs are validated at parse time to ensure the prefix matches
// the expected type.
//
// Examples:
//
//	scan_01h2xcejqtf2nbrexx3vqjhp41
//	pol_01h2xcejqtf2nbrexx3vqjhp41
//	inst_01h455vb4pex5vsknk084sn02q
package id

import (
	"fmt"

	"go.jetify.com/typeid/v2"
)

// ──────────────────────────────────────────────────
// Prefix constants
// ──────────────────────────────────────────────────

const (
	// PrefixScan is the TypeID prefix for scan results.
	PrefixScan = "scan"

	// PrefixPolicy is the TypeID prefix for policies.
	PrefixPolicy = "pol"

	// PrefixFinding is the TypeID prefix for findings.
	PrefixFinding = "find"

	// PrefixPIIToken is the TypeID prefix for PII tokens.
	PrefixPIIToken = "pii"

	// PrefixComplianceReport is the TypeID prefix for compliance reports.
	PrefixComplianceReport = "crpt"

	// PrefixCheck is the TypeID prefix for safety checks.
	PrefixCheck = "schk"

	// PrefixInstinct is the TypeID prefix for instincts.
	PrefixInstinct = "inst"

	// PrefixJudgment is the TypeID prefix for judgments.
	PrefixJudgment = "jdg"

	// PrefixAwareness is the TypeID prefix for awareness detectors.
	PrefixAwareness = "awr"

	// PrefixValue is the TypeID prefix for values.
	PrefixValue = "val"

	// PrefixReflex is the TypeID prefix for reflexes.
	PrefixReflex = "rflx"

	// PrefixBoundary is the TypeID prefix for boundaries.
	PrefixBoundary = "bnd"

	// PrefixSafetyProfile is the TypeID prefix for safety profiles.
	PrefixSafetyProfile = "sprf"
)

// ──────────────────────────────────────────────────
// Type aliases for readability
// ──────────────────────────────────────────────────

// ScanID is a type-safe identifier for scan results (prefix: "scan").
type ScanID = typeid.TypeID

// PolicyID is a type-safe identifier for policies (prefix: "pol").
type PolicyID = typeid.TypeID

// FindingID is a type-safe identifier for findings (prefix: "find").
type FindingID = typeid.TypeID

// PIITokenID is a type-safe identifier for PII tokens (prefix: "pii").
type PIITokenID = typeid.TypeID

// ComplianceReportID is a type-safe identifier for compliance reports (prefix: "crpt").
type ComplianceReportID = typeid.TypeID

// CheckID is a type-safe identifier for safety checks (prefix: "schk").
type CheckID = typeid.TypeID

// InstinctID is a type-safe identifier for instincts (prefix: "inst").
type InstinctID = typeid.TypeID

// JudgmentID is a type-safe identifier for judgments (prefix: "jdg").
type JudgmentID = typeid.TypeID

// AwarenessID is a type-safe identifier for awareness detectors (prefix: "awr").
type AwarenessID = typeid.TypeID

// ValueID is a type-safe identifier for values (prefix: "val").
type ValueID = typeid.TypeID

// ReflexID is a type-safe identifier for reflexes (prefix: "rflx").
type ReflexID = typeid.TypeID

// BoundaryID is a type-safe identifier for boundaries (prefix: "bnd").
type BoundaryID = typeid.TypeID

// SafetyProfileID is a type-safe identifier for safety profiles (prefix: "sprf").
type SafetyProfileID = typeid.TypeID

// AnyID is a TypeID that accepts any valid prefix.
type AnyID = typeid.TypeID

// ──────────────────────────────────────────────────
// Constructors
// ──────────────────────────────────────────────────

// NewScanID returns a new random ScanID.
func NewScanID() ScanID { return must(typeid.Generate(PrefixScan)) }

// NewPolicyID returns a new random PolicyID.
func NewPolicyID() PolicyID { return must(typeid.Generate(PrefixPolicy)) }

// NewFindingID returns a new random FindingID.
func NewFindingID() FindingID { return must(typeid.Generate(PrefixFinding)) }

// NewPIITokenID returns a new random PIITokenID.
func NewPIITokenID() PIITokenID { return must(typeid.Generate(PrefixPIIToken)) }

// NewComplianceReportID returns a new random ComplianceReportID.
func NewComplianceReportID() ComplianceReportID { return must(typeid.Generate(PrefixComplianceReport)) }

// NewCheckID returns a new random CheckID.
func NewCheckID() CheckID { return must(typeid.Generate(PrefixCheck)) }

// NewInstinctID returns a new random InstinctID.
func NewInstinctID() InstinctID { return must(typeid.Generate(PrefixInstinct)) }

// NewJudgmentID returns a new random JudgmentID.
func NewJudgmentID() JudgmentID { return must(typeid.Generate(PrefixJudgment)) }

// NewAwarenessID returns a new random AwarenessID.
func NewAwarenessID() AwarenessID { return must(typeid.Generate(PrefixAwareness)) }

// NewValueID returns a new random ValueID.
func NewValueID() ValueID { return must(typeid.Generate(PrefixValue)) }

// NewReflexID returns a new random ReflexID.
func NewReflexID() ReflexID { return must(typeid.Generate(PrefixReflex)) }

// NewBoundaryID returns a new random BoundaryID.
func NewBoundaryID() BoundaryID { return must(typeid.Generate(PrefixBoundary)) }

// NewSafetyProfileID returns a new random SafetyProfileID.
func NewSafetyProfileID() SafetyProfileID { return must(typeid.Generate(PrefixSafetyProfile)) }

// ──────────────────────────────────────────────────
// Parsing (validates prefix at parse time)
// ──────────────────────────────────────────────────

// ParseScanID parses a string into a ScanID.
func ParseScanID(s string) (ScanID, error) { return parseWithPrefix(PrefixScan, s) }

// ParsePolicyID parses a string into a PolicyID.
func ParsePolicyID(s string) (PolicyID, error) { return parseWithPrefix(PrefixPolicy, s) }

// ParseFindingID parses a string into a FindingID.
func ParseFindingID(s string) (FindingID, error) { return parseWithPrefix(PrefixFinding, s) }

// ParsePIITokenID parses a string into a PIITokenID.
func ParsePIITokenID(s string) (PIITokenID, error) { return parseWithPrefix(PrefixPIIToken, s) }

// ParseComplianceReportID parses a string into a ComplianceReportID.
func ParseComplianceReportID(s string) (ComplianceReportID, error) {
	return parseWithPrefix(PrefixComplianceReport, s)
}

// ParseCheckID parses a string into a CheckID.
func ParseCheckID(s string) (CheckID, error) { return parseWithPrefix(PrefixCheck, s) }

// ParseInstinctID parses a string into an InstinctID.
func ParseInstinctID(s string) (InstinctID, error) { return parseWithPrefix(PrefixInstinct, s) }

// ParseJudgmentID parses a string into a JudgmentID.
func ParseJudgmentID(s string) (JudgmentID, error) { return parseWithPrefix(PrefixJudgment, s) }

// ParseAwarenessID parses a string into an AwarenessID.
func ParseAwarenessID(s string) (AwarenessID, error) { return parseWithPrefix(PrefixAwareness, s) }

// ParseValueID parses a string into a ValueID.
func ParseValueID(s string) (ValueID, error) { return parseWithPrefix(PrefixValue, s) }

// ParseReflexID parses a string into a ReflexID.
func ParseReflexID(s string) (ReflexID, error) { return parseWithPrefix(PrefixReflex, s) }

// ParseBoundaryID parses a string into a BoundaryID.
func ParseBoundaryID(s string) (BoundaryID, error) { return parseWithPrefix(PrefixBoundary, s) }

// ParseSafetyProfileID parses a string into a SafetyProfileID.
func ParseSafetyProfileID(s string) (SafetyProfileID, error) {
	return parseWithPrefix(PrefixSafetyProfile, s)
}

// ParseAny parses a string into an AnyID, accepting any valid prefix.
func ParseAny(s string) (AnyID, error) { return typeid.Parse(s) }

// ──────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────

// parseWithPrefix parses a TypeID and validates that its prefix matches expected.
func parseWithPrefix(expected, s string) (typeid.TypeID, error) {
	tid, err := typeid.Parse(s)
	if err != nil {
		return tid, err
	}
	if tid.Prefix() != expected {
		return tid, fmt.Errorf("id: expected prefix %q, got %q", expected, tid.Prefix())
	}
	return tid, nil
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
