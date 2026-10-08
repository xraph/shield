package admin

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
)

type Field struct {
	Key          string   `json:"key"`
	Label        string   `json:"label"`
	Type         string   `json:"type"`
	Options      []string `json:"options,omitempty"`
	Fields       []Field  `json:"fields,omitempty"`
	Required     bool     `json:"required,omitempty"`
	MaxLength    int      `json:"max_length,omitempty"`
	MaxItems     int      `json:"max_items,omitempty"`
	JSONBytesMax int      `json:"json_bytes_max,omitempty"`
	Minimum      *float64 `json:"minimum,omitempty"`
	Maximum      *float64 `json:"maximum,omitempty"`
}

func field(key, kind string, options ...string) Field {
	f := Field{Key: key, Label: strings.ReplaceAll(key, "_", " "), Type: kind, Options: options}
	switch kind {
	case "text", "reference", "select":
		f.MaxLength = 512
	case "textarea":
		f.MaxLength = 4096
	case "array", "references", "tags":
		f.MaxItems = 64
	case "json", "json_value":
		f.JSONBytesMax = 16384
	case "number", "integer":
		lo, hi := 0.0, 1.0
		if kind == "integer" {
			hi = 1000000
		}
		f.Minimum, f.Maximum = &lo, &hi
	}
	return f
}
func required(key string, options ...string) Field {
	f := field(key, "select", options...)
	f.Required = true
	return f
}
func list(key string, children ...Field) Field {
	f := field(key, "array")
	f.Fields = children
	return f
}

var actions = []string{"block", "flag", "warn", "alert", "redact", "vault", "log", "rewrite", "escalate", "throttle"}
var sensitivity = []string{"paranoid", "cautious", "balanced", "relaxed", "permissive"}
var domains = []string{"grounding", "relevance", "consistency", "compliance", "custom"}
var focus = []string{"pii", "topic", "sentiment", "intent", "language", "custom"}
var Schemas = map[string][]Field{
	"instincts":  {required("category", "injection", "exfiltration", "manipulation", "jailbreak"), required("sensitivity", sensitivity...), required("action", "block", "flag", "alert"), list("strategies", field("name", "text"), field("weight", "number"), field("config", "json"))},
	"awareness":  {required("focus", focus...), required("action", "redact", "flag", "block", "vault"), list("detectors", field("name", "text"), required("focus", focus...), field("patterns", "tags"), field("config", "json"))},
	"boundaries": {field("response", "textarea"), list("limits", required("scope", "topic", "action", "data", "output", "custom"), field("deny", "tags"), field("allow", "tags"), field("use_allow", "boolean"))},
	"values":     {required("severity", "info", "warning", "error", "critical"), required("action", "block", "flag", "warn"), list("rules", required("principle", "toxicity", "brand_safety", "honesty", "respect", "safety", "privacy", "custom"), field("threshold", "number"), field("categories", "tags"), field("guidelines", "tags"), field("config", "json"))},
	"judgments":  {required("domain", domains...), field("threshold", "number"), required("action", "flag", "block", "warn"), list("assessors", field("name", "text"), required("domain", domains...), field("weight", "number"), field("requires_context", "boolean"), field("config", "json"))},
	"reflexes":   {field("priority", "integer"), list("triggers", required("type", "on_score", "on_finding", "on_pattern", "on_context", "on_rate", "always"), field("pattern", "text"), field("threshold", "number"), field("window", "text")), list("actions", required("type", "block", "redact", "flag", "rewrite", "escalate", "log", "throttle"), field("target", "text"), field("value", "json_value"), field("fallback", "textarea"))},
	"profiles":   {list("instincts", field("instinct_name", "reference"), field("sensitivity", "select", sensitivity...)), list("awareness", field("awareness_name", "reference")), list("judgments", field("judgment_name", "reference"), field("threshold", "number")), field("boundaries", "references"), field("values", "references"), field("reflexes", "references")},
	"policies":   {list("rules", required("check_type", "instinct", "awareness", "boundary", "values", "judgment", "reflex"), field("condition", "text"), required("action", "block", "flag", "redact"), field("error_message", "textarea"), field("priority", "integer"))},
}

func validate(kind string, row, before map[string]any) error {
	fields, ok := Schemas[kind]
	if !ok {
		return fail("BAD_REQUEST", "Unsupported editable collection")
	}
	if before == nil {
		for _, key := range []string{"id", "app_id", "tenant_id", "scope_key", "scope_level", "created_at", "updated_at"} {
			if _, ok := row[key]; ok {
				return fail("BAD_REQUEST", key+" is assigned by the server")
			}
		}
	}
	name, ok := row["name"].(string)
	if !ok || len(name) == 0 || len(name) > 128 || strings.TrimSpace(name) != name {
		return fieldError("name", "Use a name from 1 to 128 characters without surrounding spaces")
	}
	allowed := map[string]bool{"name": true, "description": true, "enabled": true, "metadata": true, "id": before != nil, "app_id": before != nil, "tenant_id": before != nil, "scope_key": before != nil, "scope_level": before != nil, "created_at": before != nil, "updated_at": before != nil}
	for _, f := range fields {
		allowed[f.Key] = true
	}
	for key := range row {
		if !allowed[key] {
			return fieldError(key, "Unsupported field")
		}
	}
	common := []Field{field("description", "textarea"), field("enabled", "boolean"), field("metadata", "json")}
	return validateFields(append(common, fields...), row, before, "")
}
func fieldError(key, msg string) error {
	return &Error{Code: "BAD_REQUEST", Message: "Check the highlighted configuration fields", Fields: map[string]string{key: msg}}
}
func validateFields(fields []Field, row, before map[string]any, path string) error {
	for _, f := range fields {
		v, exists := row[f.Key]
		key := path + f.Key
		old := any(nil)
		if before != nil {
			old = before[f.Key]
		}
		if !exists {
			if f.Required {
				return fieldError(key, "Choose a value")
			}
			continue
		}
		switch f.Type {
		case "text", "textarea", "select", "reference":
			str, ok := v.(string)
			if !ok {
				return fieldError(key, "Expected text")
			}
			max := 512
			if f.Type == "textarea" {
				max = 4096
			}
			if len(str) > max {
				return fieldError(key, fmt.Sprintf("Maximum %d characters", max))
			}
			if f.Required && str == "" {
				return fieldError(key, "Choose a value")
			}
			if len(f.Options) > 0 && str != "" {
				found := false
				for _, opt := range f.Options {
					found = found || str == opt
				}
				if !found && (before == nil || !reflect.DeepEqual(v, old)) {
					return fieldError(key, "Unsupported value")
				}
			}
			if f.Key == "pattern" && str != "" {
				if _, err := regexp.Compile(str); err != nil {
					return fieldError(key, "Invalid regular expression")
				}
			}
		case "boolean":
			if _, ok := v.(bool); !ok {
				return fieldError(key, "Expected true or false")
			}
		case "number", "integer":
			n, ok := v.(float64)
			if !ok {
				return fieldError(key, "Expected a number")
			}
			if f.Type == "number" && (n < 0 || n > 1) {
				return fieldError(key, "Use a value from 0 to 1")
			}
			if f.Type == "integer" && (n != float64(int(n)) || n < 0 || n > 1000000) {
				return fieldError(key, "Use a whole number from 0 to 1000000")
			}
		case "array", "tags", "references":
			items, ok := v.([]any)
			if !ok {
				return fieldError(key, "Expected a list")
			}
			if len(items) > 64 {
				return fieldError(key, "Maximum 64 entries")
			}
			for i, item := range items {
				p := fmt.Sprintf("%s.%d.", key, i)
				if f.Type == "array" {
					m, ok := item.(map[string]any)
					if !ok {
						return fieldError(key, "Expected structured entries")
					}
					allowed := map[string]bool{}
					for _, child := range f.Fields {
						allowed[child.Key] = true
					}
					for k := range m {
						if !allowed[k] {
							return fieldError(p+k, "Unsupported field")
						}
					}
					var oldItem map[string]any
					if oldItems, ok := old.([]any); ok {
						// Preserve an unchanged stored enum when the structured row stays in place or moves.
						if i < len(oldItems) {
							oldItem, _ = oldItems[i].(map[string]any)
						}
						for _, candidate := range oldItems {
							if reflect.DeepEqual(item, candidate) {
								oldItem, _ = candidate.(map[string]any)
								break
							}
						}
					}
					if err := validateFields(f.Fields, m, oldItem, p); err != nil {
						return err
					}
				} else {
					str, ok := item.(string)
					if !ok || len(str) > 1024 {
						return fieldError(key, "Expected text entries up to 1024 characters")
					}
					if f.Key == "patterns" {
						if _, err := regexp.Compile(str); err != nil {
							return fieldError(key, "Invalid regular expression")
						}
					}
				}
			}
		case "json", "json_value":
			encoded, err := json.Marshal(v)
			if err != nil || len(encoded) > 16384 {
				return fieldError(key, "Maximum 16 KiB of JSON")
			}
			if f.Type == "json_value" {
				continue
			}
			if v != nil {
				if _, ok := v.(map[string]any); !ok {
					return fieldError(key, "Expected a JSON object")
				}
			}
		}
	}
	return nil
}
func validateFilter(kind, field, value string) error {
	if value == "" {
		return nil
	}
	if kind == "scans" {
		opts := []string{"allow", "block", "flag", "redact"}
		if field == "direction" {
			opts = []string{"input", "output"}
		}
		for _, v := range opts {
			if v == value {
				return nil
			}
		}
		return fail("BAD_REQUEST", "Invalid scan filter")
	}
	if kind == "compliance" {
		for _, v := range []string{"eu_ai_act", "nist_ai_rmf", "soc2"} {
			if value == v {
				return nil
			}
		}
		return fail("BAD_REQUEST", "Invalid framework")
	}
	for _, f := range Schemas[kind] {
		if f.Key == field {
			for _, v := range f.Options {
				if v == value {
					return nil
				}
			}
		}
	}
	return fail("BAD_REQUEST", "Invalid filter value")
}

// InputSchema publishes the same limits used by the editor and service.
func InputSchema(kind string, update bool) map[string]any {
	properties := map[string]any{"name": map[string]any{"type": "string", "minLength": 1, "maxLength": 128}, "description": map[string]any{"type": "string", "maxLength": 4096}, "enabled": map[string]any{"type": "boolean"}, "metadata": map[string]any{"type": "object", "x-maxBytes": 16384}}
	for _, f := range Schemas[kind] {
		properties[f.Key] = fieldSchema(f)
	}
	row := map[string]any{"type": "object", "properties": properties, "additionalProperties": false, "x-maxBytes": 131072}
	if !update {
		required := []string{"name"}
		for _, f := range Schemas[kind] {
			if f.Required {
				required = append(required, f.Key)
			}
		}
		row["required"] = required
	}
	input := map[string]any{"type": "object", "properties": map[string]any{"row": row}, "required": []string{"row"}, "additionalProperties": false}
	if update {
		input["properties"].(map[string]any)["expected_updated_at"] = map[string]any{"type": "string", "maxLength": 64}
		input["properties"].(map[string]any)["id"] = map[string]any{"type": "string"}
		input["required"] = []string{"id", "row"}
	}
	return input
}
func fieldSchema(f Field) map[string]any {
	s := map[string]any{}
	switch f.Type {
	case "number", "integer":
		s["type"] = f.Type
		s["minimum"] = f.Minimum
		s["maximum"] = f.Maximum
	case "boolean":
		s["type"] = "boolean"
	case "json":
		s["type"] = "object"
	case "json_value": // Any JSON value, bounded by encoded size.
	case "array", "references", "tags":
		s["type"] = "array"
		s["maxItems"] = f.MaxItems
		if f.Type == "array" {
			p := map[string]any{}
			required := []string{}
			for _, c := range f.Fields {
				p[c.Key] = fieldSchema(c)
				if c.Required {
					required = append(required, c.Key)
				}
			}
			item := map[string]any{"type": "object", "properties": p, "additionalProperties": false}
			if len(required) > 0 {
				item["required"] = required
			}
			s["items"] = item
		} else {
			s["items"] = map[string]any{"type": "string", "maxLength": 1024}
		}
	default:
		s["type"] = "string"
	}
	if f.MaxLength > 0 {
		s["maxLength"] = f.MaxLength
	}
	if f.JSONBytesMax > 0 {
		s["x-maxBytes"] = f.JSONBytesMax
	}
	if len(f.Options) > 0 {
		s["enum"] = f.Options
	}
	return s
}
