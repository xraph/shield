package store

import (
	"context"
	"encoding"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"
)

var ErrScope = errors.New("shield: tenant and app scope are required")
var ErrNotFound = errors.New("shield: scoped resource not found")
var ErrCollection = errors.New("shield: unsupported dashboard collection")
var ErrConflict = errors.New("shield: resource conflict")

type Scope struct {
	TenantID    string `json:"tenant_id"`
	AppID       string `json:"app_id"`
	PolicyKey   string `json:"policy_key,omitempty"`
	PolicyLevel string `json:"policy_level,omitempty"`
}

func (s Scope) Validate() error {
	if (s.PolicyKey != "" || s.PolicyLevel != "") && (strings.TrimSpace(s.PolicyKey) == "" || (s.PolicyLevel != "app" && s.PolicyLevel != "org") || (s.PolicyLevel == "app" && s.PolicyKey != s.AppID)) {
		return ErrScope
	}
	if strings.TrimSpace(s.TenantID) == "" || strings.TrimSpace(s.AppID) == "" {
		return ErrScope
	}
	return nil
}

type Filter struct {
	Limit         int    `json:"limit"`
	Offset        int    `json:"offset"`
	Enabled       *bool  `json:"enabled,omitempty"`
	Name          string `json:"name,omitempty"`
	Field         string `json:"field,omitempty"`
	Value         string `json:"value,omitempty"`
	Search        string `json:"search,omitempty"`
	ReferenceKind string `json:"reference_kind,omitempty"`
	ReferenceName string `json:"reference_name,omitempty"`
}

func (f Filter) Validate() error {
	if f.Limit < 0 || f.Limit > 100 || f.Offset < 0 {
		return errors.New("shield: invalid pagination")
	}
	return nil
}

type Page struct {
	Items   []json.RawMessage `json:"items"`
	Total   int64             `json:"total"`
	Limit   int               `json:"limit"`
	Offset  int               `json:"offset"`
	HasMore bool              `json:"has_more"`
}

// DashboardStore is an additional, strict interface. Legacy engine methods retain
// their original contracts; dashboard calls must never broaden an empty scope.
type DashboardStore interface {
	DashboardList(context.Context, Scope, string, Filter) (Page, error)
	DashboardGet(context.Context, Scope, string, string) (json.RawMessage, error)
	DashboardCreate(context.Context, Scope, string, json.RawMessage) (json.RawMessage, error)
	DashboardUpdate(context.Context, Scope, string, string, json.RawMessage) (json.RawMessage, error)
	DashboardDelete(context.Context, Scope, string, string) error
}

func Prefix(kind string) string {
	return map[string]string{"instincts": "inst", "awareness": "awr", "boundaries": "bnd", "values": "val", "judgments": "jdg", "reflexes": "rflx", "profiles": "sprf", "policies": "pol", "scans": "scan", "compliance": "crpt"}[kind]
}
func Editable(kind string) bool { return Prefix(kind) != "" && kind != "scans" && kind != "compliance" }
func FilterColumn(kind, field string) bool {
	return map[string]string{"instincts": "category", "awareness": "focus", "judgments": "domain", "scans": "decision", "compliance": "framework"}[kind] == field && field != "" || kind == "scans" && field == "direction"
}

// MarshalDashboard keeps zero and empty values that domain omitempty tags hide.
// Dashboard editors need explicit false, zero and cleared arrays on reload.
func MarshalDashboard(v any) (json.RawMessage, error) {
	return json.Marshal(dashboardValue(reflect.ValueOf(v)))
}
func dashboardValue(v reflect.Value) any {
	if !v.IsValid() {
		return nil
	}
	if v.Kind() == reflect.Interface || v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		return dashboardValue(v.Elem())
	}
	if v.CanInterface() {
		if _, ok := v.Interface().(encoding.TextMarshaler); ok {
			return v.Interface()
		}
		if _, ok := v.Interface().(json.Marshaler); ok {
			return v.Interface()
		}
	}
	switch v.Kind() {
	case reflect.Struct:
		out := map[string]any{}
		typ := v.Type()
		for i := 0; i < v.NumField(); i++ {
			f := typ.Field(i)
			if !f.IsExported() {
				continue
			}
			key := strings.Split(f.Tag.Get("json"), ",")[0]
			if key == "-" {
				continue
			}
			value := dashboardValue(v.Field(i))
			if f.Anonymous && key == "" {
				if m, ok := value.(map[string]any); ok {
					for k, x := range m {
						out[k] = x
					}
				}
				continue
			}
			if key == "" {
				key = f.Name
			}
			out[key] = value
		}
		return out
	case reflect.Slice, reflect.Array:
		out := make([]any, v.Len())
		for i := range out {
			out[i] = dashboardValue(v.Index(i))
		}
		return out
	default:
		return v.Interface()
	}
}

type AssignmentStore interface {
	DashboardAssign(context.Context, Scope, string, bool) error
	DashboardAssigned(context.Context, Scope, string) (bool, error)
}

type PrivacyStore interface {
	DashboardTokens(context.Context, Scope, string, *time.Time, Filter) (Page, error)
	DashboardDeleteTokens(context.Context, Scope, time.Time, []string) (int64, error)
}

func ValidateRetention(scope Scope, cutoff time.Time, keys []string) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	if cutoff.IsZero() || cutoff.After(time.Now().UTC()) || len(keys) == 0 || len(keys) > 100 {
		return errors.New("shield: invalid bounded retention selection")
	}
	return nil
}

func ValidReferenceKind(kind string) bool {
	return kind == "instincts" || kind == "awareness" || kind == "boundaries" || kind == "values" || kind == "judgments" || kind == "reflexes"
}
func ReferenceField(kind string) string {
	return map[string]string{"instincts": "instinct_name", "awareness": "awareness_name", "judgments": "judgment_name"}[kind]
}

// PolicyScope is supplied by a host authorization adapter, never request params.
func (s Scope) PolicyScope() (string, string) {
	if s.PolicyKey != "" && (s.PolicyLevel == "app" || s.PolicyLevel == "org") {
		return s.PolicyKey, s.PolicyLevel
	}
	return s.AppID, "app"
}
