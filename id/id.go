// Package id defines TypeID-based identity types for all Shield entities.
//
// Every entity in Shield uses a single ID struct with a prefix that identifies
// the entity type. IDs are K-sortable (UUIDv7-based), globally unique,
// and URL-safe in the format "prefix_suffix".
package id

import (
	"database/sql/driver"
	"fmt"

	"go.jetify.com/typeid/v2"
)

// Prefix identifies the entity type encoded in a TypeID.
type Prefix string

// Prefix constants for all Shield entity types.
const (
	PrefixScan             Prefix = "scan"
	PrefixPolicy           Prefix = "pol"
	PrefixFinding          Prefix = "find"
	PrefixPIIToken         Prefix = "pii"
	PrefixComplianceReport Prefix = "crpt"
	PrefixCheck            Prefix = "schk"
	PrefixInstinct         Prefix = "inst"
	PrefixJudgment         Prefix = "jdg"
	PrefixAwareness        Prefix = "awr"
	PrefixValue            Prefix = "val"
	PrefixReflex           Prefix = "rflx"
	PrefixBoundary         Prefix = "bnd"
	PrefixSafetyProfile    Prefix = "sprf"
)

// ID is the primary identifier type for all Shield entities.
// It wraps a TypeID providing a prefix-qualified, globally unique,
// sortable, URL-safe identifier in the format "prefix_suffix".
//
//nolint:recvcheck // Value receivers for read-only methods, pointer receivers for UnmarshalText/Scan.
type ID struct {
	inner typeid.TypeID
	valid bool
}

// Nil is the zero-value ID.
var Nil ID

// New generates a new globally unique ID with the given prefix.
// It panics if prefix is not a valid TypeID prefix (programming error).
func New(prefix Prefix) ID {
	tid, err := typeid.Generate(string(prefix))
	if err != nil {
		panic(fmt.Sprintf("id: invalid prefix %q: %v", prefix, err))
	}

	return ID{inner: tid, valid: true}
}

// Parse parses a TypeID string (e.g., "scan_01h2xcejqtf2nbrexx3vqjhp41")
// into an ID. Returns an error if the string is not valid.
func Parse(s string) (ID, error) {
	if s == "" {
		return Nil, fmt.Errorf("id: parse %q: empty string", s)
	}

	tid, err := typeid.Parse(s)
	if err != nil {
		return Nil, fmt.Errorf("id: parse %q: %w", s, err)
	}

	return ID{inner: tid, valid: true}, nil
}

// ParseWithPrefix parses a TypeID string and validates that its prefix
// matches the expected value.
func ParseWithPrefix(s string, expected Prefix) (ID, error) {
	parsed, err := Parse(s)
	if err != nil {
		return Nil, err
	}

	if parsed.Prefix() != expected {
		return Nil, fmt.Errorf("id: expected prefix %q, got %q", expected, parsed.Prefix())
	}

	return parsed, nil
}

// MustParse is like Parse but panics on error. Use for hardcoded ID values.
func MustParse(s string) ID {
	parsed, err := Parse(s)
	if err != nil {
		panic(fmt.Sprintf("id: must parse %q: %v", s, err))
	}

	return parsed
}

// MustParseWithPrefix is like ParseWithPrefix but panics on error.
func MustParseWithPrefix(s string, expected Prefix) ID {
	parsed, err := ParseWithPrefix(s, expected)
	if err != nil {
		panic(fmt.Sprintf("id: must parse with prefix %q: %v", expected, err))
	}

	return parsed
}

// ──────────────────────────────────────────────────
// Type aliases for backward compatibility
// ──────────────────────────────────────────────────

// ScanID is a type-safe identifier for scan results (prefix: "scan").
type ScanID = ID

// PolicyID is a type-safe identifier for policies (prefix: "pol").
type PolicyID = ID

// FindingID is a type-safe identifier for findings (prefix: "find").
type FindingID = ID

// PIITokenID is a type-safe identifier for PII tokens (prefix: "pii").
type PIITokenID = ID

// ComplianceReportID is a type-safe identifier for compliance reports (prefix: "crpt").
type ComplianceReportID = ID

// CheckID is a type-safe identifier for safety checks (prefix: "schk").
type CheckID = ID

// InstinctID is a type-safe identifier for instincts (prefix: "inst").
type InstinctID = ID

// JudgmentID is a type-safe identifier for judgments (prefix: "jdg").
type JudgmentID = ID

// AwarenessID is a type-safe identifier for awareness detectors (prefix: "awr").
type AwarenessID = ID

// ValueID is a type-safe identifier for values (prefix: "val").
type ValueID = ID

// ReflexID is a type-safe identifier for reflexes (prefix: "rflx").
type ReflexID = ID

// BoundaryID is a type-safe identifier for boundaries (prefix: "bnd").
type BoundaryID = ID

// SafetyProfileID is a type-safe identifier for safety profiles (prefix: "sprf").
type SafetyProfileID = ID

// AnyID is a type alias that accepts any valid prefix.
type AnyID = ID

// ──────────────────────────────────────────────────
// Convenience constructors
// ──────────────────────────────────────────────────

// NewScanID generates a new unique scan ID.
func NewScanID() ID { return New(PrefixScan) }

// NewPolicyID generates a new unique policy ID.
func NewPolicyID() ID { return New(PrefixPolicy) }

// NewFindingID generates a new unique finding ID.
func NewFindingID() ID { return New(PrefixFinding) }

// NewPIITokenID generates a new unique PII token ID.
func NewPIITokenID() ID { return New(PrefixPIIToken) }

// NewComplianceReportID generates a new unique compliance report ID.
func NewComplianceReportID() ID { return New(PrefixComplianceReport) }

// NewCheckID generates a new unique safety check ID.
func NewCheckID() ID { return New(PrefixCheck) }

// NewInstinctID generates a new unique instinct ID.
func NewInstinctID() ID { return New(PrefixInstinct) }

// NewJudgmentID generates a new unique judgment ID.
func NewJudgmentID() ID { return New(PrefixJudgment) }

// NewAwarenessID generates a new unique awareness ID.
func NewAwarenessID() ID { return New(PrefixAwareness) }

// NewValueID generates a new unique value ID.
func NewValueID() ID { return New(PrefixValue) }

// NewReflexID generates a new unique reflex ID.
func NewReflexID() ID { return New(PrefixReflex) }

// NewBoundaryID generates a new unique boundary ID.
func NewBoundaryID() ID { return New(PrefixBoundary) }

// NewSafetyProfileID generates a new unique safety profile ID.
func NewSafetyProfileID() ID { return New(PrefixSafetyProfile) }

// ──────────────────────────────────────────────────
// Convenience parsers
// ──────────────────────────────────────────────────

// ParseScanID parses a string and validates the "scan" prefix.
func ParseScanID(s string) (ID, error) { return ParseWithPrefix(s, PrefixScan) }

// ParsePolicyID parses a string and validates the "pol" prefix.
func ParsePolicyID(s string) (ID, error) { return ParseWithPrefix(s, PrefixPolicy) }

// ParseFindingID parses a string and validates the "find" prefix.
func ParseFindingID(s string) (ID, error) { return ParseWithPrefix(s, PrefixFinding) }

// ParsePIITokenID parses a string and validates the "pii" prefix.
func ParsePIITokenID(s string) (ID, error) { return ParseWithPrefix(s, PrefixPIIToken) }

// ParseComplianceReportID parses a string and validates the "crpt" prefix.
func ParseComplianceReportID(s string) (ID, error) { return ParseWithPrefix(s, PrefixComplianceReport) }

// ParseCheckID parses a string and validates the "schk" prefix.
func ParseCheckID(s string) (ID, error) { return ParseWithPrefix(s, PrefixCheck) }

// ParseInstinctID parses a string and validates the "inst" prefix.
func ParseInstinctID(s string) (ID, error) { return ParseWithPrefix(s, PrefixInstinct) }

// ParseJudgmentID parses a string and validates the "jdg" prefix.
func ParseJudgmentID(s string) (ID, error) { return ParseWithPrefix(s, PrefixJudgment) }

// ParseAwarenessID parses a string and validates the "awr" prefix.
func ParseAwarenessID(s string) (ID, error) { return ParseWithPrefix(s, PrefixAwareness) }

// ParseValueID parses a string and validates the "val" prefix.
func ParseValueID(s string) (ID, error) { return ParseWithPrefix(s, PrefixValue) }

// ParseReflexID parses a string and validates the "rflx" prefix.
func ParseReflexID(s string) (ID, error) { return ParseWithPrefix(s, PrefixReflex) }

// ParseBoundaryID parses a string and validates the "bnd" prefix.
func ParseBoundaryID(s string) (ID, error) { return ParseWithPrefix(s, PrefixBoundary) }

// ParseSafetyProfileID parses a string and validates the "sprf" prefix.
func ParseSafetyProfileID(s string) (ID, error) { return ParseWithPrefix(s, PrefixSafetyProfile) }

// ParseAny parses a string into an ID without type checking the prefix.
func ParseAny(s string) (ID, error) { return Parse(s) }

// ──────────────────────────────────────────────────
// ID methods
// ──────────────────────────────────────────────────

// String returns the full TypeID string representation (prefix_suffix).
// Returns an empty string for the Nil ID.
func (i ID) String() string {
	if !i.valid {
		return ""
	}

	return i.inner.String()
}

// Prefix returns the prefix component of this ID.
func (i ID) Prefix() Prefix {
	if !i.valid {
		return ""
	}

	return Prefix(i.inner.Prefix())
}

// IsNil reports whether this ID is the zero value.
func (i ID) IsNil() bool {
	return !i.valid
}

// MarshalText implements encoding.TextMarshaler.
func (i ID) MarshalText() ([]byte, error) {
	if !i.valid {
		return []byte{}, nil
	}

	return []byte(i.inner.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (i *ID) UnmarshalText(data []byte) error {
	if len(data) == 0 {
		*i = Nil

		return nil
	}

	parsed, err := Parse(string(data))
	if err != nil {
		return err
	}

	*i = parsed

	return nil
}

// Value implements driver.Valuer for database storage.
// Returns nil for the Nil ID so that optional foreign key columns store NULL.
func (i ID) Value() (driver.Value, error) {
	if !i.valid {
		return nil, nil //nolint:nilnil // nil is the canonical NULL for driver.Valuer
	}

	return i.inner.String(), nil
}

// Scan implements sql.Scanner for database retrieval.
func (i *ID) Scan(src any) error {
	if src == nil {
		*i = Nil

		return nil
	}

	switch v := src.(type) {
	case string:
		if v == "" {
			*i = Nil

			return nil
		}

		return i.UnmarshalText([]byte(v))
	case []byte:
		if len(v) == 0 {
			*i = Nil

			return nil
		}

		return i.UnmarshalText(v)
	default:
		return fmt.Errorf("id: cannot scan %T into ID", src)
	}
}
