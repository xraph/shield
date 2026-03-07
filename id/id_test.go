package id_test

import (
	"strings"
	"testing"

	"github.com/xraph/shield/id"
)

func TestConstructors(t *testing.T) {
	tests := []struct {
		name   string
		newFn  func() id.ID
		prefix string
	}{
		{"ScanID", id.NewScanID, "scan_"},
		{"PolicyID", id.NewPolicyID, "pol_"},
		{"FindingID", id.NewFindingID, "find_"},
		{"PIITokenID", id.NewPIITokenID, "pii_"},
		{"ComplianceReportID", id.NewComplianceReportID, "crpt_"},
		{"CheckID", id.NewCheckID, "schk_"},
		{"InstinctID", id.NewInstinctID, "inst_"},
		{"JudgmentID", id.NewJudgmentID, "jdg_"},
		{"AwarenessID", id.NewAwarenessID, "awr_"},
		{"ValueID", id.NewValueID, "val_"},
		{"ReflexID", id.NewReflexID, "rflx_"},
		{"BoundaryID", id.NewBoundaryID, "bnd_"},
		{"SafetyProfileID", id.NewSafetyProfileID, "sprf_"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.newFn().String()
			if !strings.HasPrefix(got, tt.prefix) {
				t.Errorf("expected prefix %q, got %q", tt.prefix, got)
			}
		})
	}
}

func TestNew(t *testing.T) {
	i := id.New(id.PrefixScan)
	if i.IsNil() {
		t.Fatal("expected non-nil ID")
	}
	if i.Prefix() != id.PrefixScan {
		t.Errorf("expected prefix %q, got %q", id.PrefixScan, i.Prefix())
	}
}

func TestParseRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		newFn   func() id.ID
		parseFn func(string) (id.ID, error)
	}{
		{"ScanID", id.NewScanID, id.ParseScanID},
		{"PolicyID", id.NewPolicyID, id.ParsePolicyID},
		{"FindingID", id.NewFindingID, id.ParseFindingID},
		{"PIITokenID", id.NewPIITokenID, id.ParsePIITokenID},
		{"ComplianceReportID", id.NewComplianceReportID, id.ParseComplianceReportID},
		{"CheckID", id.NewCheckID, id.ParseCheckID},
		{"InstinctID", id.NewInstinctID, id.ParseInstinctID},
		{"JudgmentID", id.NewJudgmentID, id.ParseJudgmentID},
		{"AwarenessID", id.NewAwarenessID, id.ParseAwarenessID},
		{"ValueID", id.NewValueID, id.ParseValueID},
		{"ReflexID", id.NewReflexID, id.ParseReflexID},
		{"BoundaryID", id.NewBoundaryID, id.ParseBoundaryID},
		{"SafetyProfileID", id.NewSafetyProfileID, id.ParseSafetyProfileID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := tt.newFn()
			parsed, err := tt.parseFn(original.String())
			if err != nil {
				t.Fatalf("parse failed: %v", err)
			}
			if parsed.String() != original.String() {
				t.Errorf("round-trip mismatch: %q != %q", parsed.String(), original.String())
			}
		})
	}
}

func TestCrossTypeRejection(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		parseFn func(string) (id.ID, error)
	}{
		{
			"ParseScanID rejects pol_ prefix",
			id.NewPolicyID().String(),
			id.ParseScanID,
		},
		{
			"ParsePolicyID rejects find_ prefix",
			id.NewFindingID().String(),
			id.ParsePolicyID,
		},
		{
			"ParseFindingID rejects pii_ prefix",
			id.NewPIITokenID().String(),
			id.ParseFindingID,
		},
		{
			"ParsePIITokenID rejects crpt_ prefix",
			id.NewComplianceReportID().String(),
			id.ParsePIITokenID,
		},
		{
			"ParseComplianceReportID rejects schk_ prefix",
			id.NewCheckID().String(),
			id.ParseComplianceReportID,
		},
		{
			"ParseCheckID rejects inst_ prefix",
			id.NewInstinctID().String(),
			id.ParseCheckID,
		},
		{
			"ParseInstinctID rejects jdg_ prefix",
			id.NewJudgmentID().String(),
			id.ParseInstinctID,
		},
		{
			"ParseJudgmentID rejects awr_ prefix",
			id.NewAwarenessID().String(),
			id.ParseJudgmentID,
		},
		{
			"ParseAwarenessID rejects val_ prefix",
			id.NewValueID().String(),
			id.ParseAwarenessID,
		},
		{
			"ParseValueID rejects rflx_ prefix",
			id.NewReflexID().String(),
			id.ParseValueID,
		},
		{
			"ParseReflexID rejects bnd_ prefix",
			id.NewBoundaryID().String(),
			id.ParseReflexID,
		},
		{
			"ParseBoundaryID rejects sprf_ prefix",
			id.NewSafetyProfileID().String(),
			id.ParseBoundaryID,
		},
		{
			"ParseSafetyProfileID rejects scan_ prefix",
			id.NewScanID().String(),
			id.ParseSafetyProfileID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.parseFn(tt.input)
			if err == nil {
				t.Errorf("expected error for cross-type parse of %q, got nil", tt.input)
			}
		})
	}
}

func TestParseAny(t *testing.T) {
	ids := []id.ID{
		id.NewScanID(),
		id.NewPolicyID(),
		id.NewFindingID(),
		id.NewPIITokenID(),
		id.NewComplianceReportID(),
		id.NewCheckID(),
		id.NewInstinctID(),
		id.NewJudgmentID(),
		id.NewAwarenessID(),
		id.NewValueID(),
		id.NewReflexID(),
		id.NewBoundaryID(),
		id.NewSafetyProfileID(),
	}

	for _, i := range ids {
		t.Run(i.String(), func(t *testing.T) {
			parsed, err := id.ParseAny(i.String())
			if err != nil {
				t.Fatalf("ParseAny(%q) failed: %v", i.String(), err)
			}
			if parsed.String() != i.String() {
				t.Errorf("round-trip mismatch: %q != %q", parsed.String(), i.String())
			}
		})
	}
}

func TestParseWithPrefix(t *testing.T) {
	i := id.NewScanID()
	parsed, err := id.ParseWithPrefix(i.String(), id.PrefixScan)
	if err != nil {
		t.Fatalf("ParseWithPrefix failed: %v", err)
	}
	if parsed.String() != i.String() {
		t.Errorf("mismatch: %q != %q", parsed.String(), i.String())
	}

	_, err = id.ParseWithPrefix(i.String(), id.PrefixPolicy)
	if err == nil {
		t.Error("expected error for wrong prefix")
	}
}

func TestParseEmpty(t *testing.T) {
	_, err := id.Parse("")
	if err == nil {
		t.Error("expected error for empty string")
	}
}

func TestNilID(t *testing.T) {
	var i id.ID
	if !i.IsNil() {
		t.Error("zero-value ID should be nil")
	}
	if i.String() != "" {
		t.Errorf("expected empty string, got %q", i.String())
	}
	if i.Prefix() != "" {
		t.Errorf("expected empty prefix, got %q", i.Prefix())
	}
}

func TestMarshalUnmarshalText(t *testing.T) {
	original := id.NewScanID()
	data, err := original.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText failed: %v", err)
	}

	var restored id.ID
	if unmarshalErr := restored.UnmarshalText(data); unmarshalErr != nil {
		t.Fatalf("UnmarshalText failed: %v", unmarshalErr)
	}
	if restored.String() != original.String() {
		t.Errorf("mismatch: %q != %q", restored.String(), original.String())
	}

	// Nil round-trip.
	var nilID id.ID
	data, err = nilID.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText(nil) failed: %v", err)
	}
	var restored2 id.ID
	if err := restored2.UnmarshalText(data); err != nil {
		t.Fatalf("UnmarshalText(nil) failed: %v", err)
	}
	if !restored2.IsNil() {
		t.Error("expected nil after round-trip of nil ID")
	}
}

func TestValueScan(t *testing.T) {
	original := id.NewPolicyID()
	val, err := original.Value()
	if err != nil {
		t.Fatalf("Value failed: %v", err)
	}

	var scanned id.ID
	if scanErr := scanned.Scan(val); scanErr != nil {
		t.Fatalf("Scan failed: %v", scanErr)
	}
	if scanned.String() != original.String() {
		t.Errorf("mismatch: %q != %q", scanned.String(), original.String())
	}

	// Nil round-trip.
	var nilID id.ID
	val, err = nilID.Value()
	if err != nil {
		t.Fatalf("Value(nil) failed: %v", err)
	}
	if val != nil {
		t.Errorf("expected nil value for nil ID, got %v", val)
	}

	var scanned2 id.ID
	if err := scanned2.Scan(nil); err != nil {
		t.Fatalf("Scan(nil) failed: %v", err)
	}
	if !scanned2.IsNil() {
		t.Error("expected nil after scan of nil")
	}
}

func TestUniqueness(t *testing.T) {
	a := id.NewScanID()
	b := id.NewScanID()
	if a.String() == b.String() {
		t.Errorf("two consecutive NewScanID() calls returned the same ID: %q", a.String())
	}
}

func TestBSONRoundTrip(t *testing.T) {
	original := id.NewScanID()

	bsonType, data, err := original.MarshalBSONValue()
	if err != nil {
		t.Fatalf("MarshalBSONValue failed: %v", err)
	}
	if bsonType != 0x02 {
		t.Fatalf("expected BSON string type 0x02, got 0x%02x", bsonType)
	}

	var restored id.ID
	if unmarshalErr := restored.UnmarshalBSONValue(bsonType, data); unmarshalErr != nil {
		t.Fatalf("UnmarshalBSONValue failed: %v", unmarshalErr)
	}
	if restored.String() != original.String() {
		t.Errorf("BSON round-trip mismatch: %q != %q", restored.String(), original.String())
	}

	var nilID id.ID
	bsonType, data, err = nilID.MarshalBSONValue()
	if err != nil {
		t.Fatalf("MarshalBSONValue(nil) failed: %v", err)
	}
	if bsonType != 0x0A {
		t.Fatalf("expected BSON null type 0x0A, got 0x%02x", bsonType)
	}

	var restored2 id.ID
	if unmarshalErr := restored2.UnmarshalBSONValue(bsonType, data); unmarshalErr != nil {
		t.Fatalf("UnmarshalBSONValue(nil) failed: %v", unmarshalErr)
	}
	if !restored2.IsNil() {
		t.Error("expected nil after BSON round-trip of nil ID")
	}
}

func TestBSONUnmarshalInvalidType(t *testing.T) {
	var restored id.ID
	err := restored.UnmarshalBSONValue(0x01, []byte{0x00, 0x00, 0x00, 0x00})
	if err == nil {
		t.Error("expected error for invalid BSON type, got nil")
	}
}
