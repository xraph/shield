package admin

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestUnchangedStoredNestedEnumsCanBeEdited(t *testing.T) {
	var before map[string]any
	_ = json.Unmarshal([]byte(`{"name":"existing","enabled":true,"detectors":[{"name":"legacy","focus":"future-focus","patterns":[]}],"focus":"pii","action":"flag"}`), &before)
	var row map[string]any
	b, _ := json.Marshal(before)
	_ = json.Unmarshal(b, &row)
	row["description"] = "changed"
	if err := validate("awareness", row, before); err != nil {
		t.Fatal(err)
	}
	row["detectors"].([]any)[0].(map[string]any)["focus"] = "different-unknown"
	if err := validate("awareness", row, before); err == nil {
		t.Fatal("changed unsupported enum accepted")
	}
}
func TestJSONConfigurationBound(t *testing.T) {
	var row map[string]any
	_ = json.Unmarshal([]byte(`{"name":"x","focus":"pii","action":"flag","metadata":{}}`), &row)
	row["metadata"] = map[string]any{"oversized": strings.Repeat("x", 16385)}
	if err := validate("awareness", row, nil); err == nil {
		t.Fatal("oversized JSON accepted")
	}
}
