// Package contract registers Shield's authenticated dashboard contract.
package contract

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	dash "github.com/xraph/forge/extensions/dashboard/contract"
	"github.com/xraph/forge/extensions/dashboard/contract/dispatcher"
	"github.com/xraph/forge/extensions/dashboard/contract/loader"
	"github.com/xraph/shield/admin"
	"github.com/xraph/shield/store"
	"strings"
	"time"
)

//go:embed manifest.yaml
var manifestYAML []byte

const ContributorName = "shield"

type Deps struct {
	Admin   *admin.Service
	Resolve ActorResolver
}
type warden struct{ resolve ActorResolver }

func (w warden) Authorize(ctx context.Context, p dash.Principal, action dash.Action) (dash.Decision, error) {
	a, err := w.resolve(ctx, p)
	if err != nil {
		return dash.Decision{}, mapError(err)
	}
	err = a.Check(action.Kind == dash.KindCommand)
	return dash.Decision{Allow: err == nil}, mapError(err)
}
func Register(d *dispatcher.Dispatcher, reg dash.Registry, wreg dash.WardenRegistry, deps Deps) error {
	if deps.Admin == nil || !deps.Admin.Ready() {
		return errors.New("shield/contract: persistence and engine are required")
	}
	if deps.Resolve == nil {
		deps.Resolve = ResolveActor
	}
	if err := wreg.Register("shield.scope", warden{deps.Resolve}); err != nil {
		return err
	}
	m, err := loader.Load(bytes.NewReader(manifestYAML), "shield/manifest.yaml")
	if err != nil {
		return err
	}
	if err = loader.Validate(m, wreg); err != nil {
		return err
	}
	if err = reg.Register(m); err != nil {
		return err
	}
	for _, intent := range m.Intents {
		if err = d.Register(ContributorName, intent.Name, 1, handler(deps, intent.Name)); err != nil {
			return fmt.Errorf("register %s: %w", intent.Name, err)
		}
	}
	return nil
}
func mapError(err error) error {
	if err == nil {
		return nil
	}
	var ce *dash.Error
	if errors.As(err, &ce) {
		return ce
	}
	var ae *admin.Error
	if errors.As(err, &ae) {
		return &dash.Error{Code: dash.ErrorCode(ae.Code), Message: ae.Message, Details: map[string]any{"fields": ae.Fields}}
	}
	switch {
	case errors.Is(err, store.ErrNotFound):
		return &dash.Error{Code: dash.CodeNotFound, Message: "Resource not found in this scope"}
	case errors.Is(err, store.ErrConflict):
		return &dash.Error{Code: dash.CodeConflict, Message: "Resource conflicts with existing configuration"}
	case errors.Is(err, store.ErrScope):
		return &dash.Error{Code: dash.CodePermissionDenied, Message: "Authorized scope is required"}
	case errors.Is(err, store.ErrCollection):
		return &dash.Error{Code: dash.CodeBadRequest, Message: "Unsupported collection"}
	}
	message := err.Error()
	if strings.Contains(message, "UNIQUE constraint") || strings.Contains(message, "duplicate key") || strings.Contains(message, "E11000") {
		return &dash.Error{Code: dash.CodeConflict, Message: "That name is already used in this app"}
	}
	return &dash.Error{Code: dash.CodeInternal, Message: "Shield could not complete the request", Retryable: true}
}

type request struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Collection string          `json:"collection"`
	Row        json.RawMessage `json:"row"`
	Enabled    *bool           `json:"enabled"`
	PreviewID  string          `json:"preview_id"`
	store.Filter
}

func handler(deps Deps, intent string) dispatcher.Handler {
	return func(ctx context.Context, payload json.RawMessage, params map[string]any, p dash.Principal) (*dispatcher.Result, error) {
		a, err := deps.Resolve(ctx, p)
		if err != nil {
			return nil, mapError(err)
		}
		in := request{}
		raw := payload
		if len(raw) == 0 || string(raw) == "null" {
			raw, _ = json.Marshal(params)
		}
		if len(raw) > 0 {
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			if err = dec.Decode(&in); err != nil {
				return nil, &dash.Error{Code: dash.CodeBadRequest, Message: "Invalid Shield request"}
			}
		}
		var data any
		s := deps.Admin
		switch intent {
		case "capabilities":
			if err = a.Check(false); err == nil {
				data = map[string]any{"engine": s.Engine().Capabilities(), "scope": a.Scope, "can_manage": a.Manage, "can_manage_privacy": a.Manage && a.Sensitive && s.PrivacyAvailable(), "schemas": admin.Schemas, "limits": map[string]int{"page_default": 25, "page_max": 100, "entries_max": 64, "name_max": 128, "description_max": 4096, "body_bytes_max": 131072}}
			}
		case "config.detail":
			data = s.Engine().Config()
			err = a.Check(false)
		case "overview", "layers.summary":
			sections := []map[string]any{}
			for _, kind := range []string{"instincts", "awareness", "boundaries", "values", "judgments", "reflexes", "profiles", "policies", "scans", "compliance"} {
				page, e := s.List(ctx, a, kind, store.Filter{Limit: 1})
				section := map[string]any{"collection": kind, "available": e == nil, "evaluation_available": false, "refreshed_at": time.Now().UTC()}
				if e == nil {
					section["total"] = page.Total
				} else {
					section["error"] = "Could not load this section"
				}
				sections = append(sections, section)
			}
			data = map[string]any{"sections": sections, "evaluation_available": false, "refreshed_at": time.Now().UTC()}
			err = a.Check(false)
		case "scans.stats":
			counts := map[string]int64{}
			for _, decision := range []string{"allow", "block", "flag", "redact"} {
				page, e := s.List(ctx, a, "scans", store.Filter{Limit: 1, Field: "decision", Value: decision})
				if e != nil {
					err = e
					break
				}
				counts[decision] = page.Total
			}
			data = counts
		case "profiles.references":
			data, err = s.References(ctx, a, in.Collection, in.Name)
		case "policies.assignments":
			var assigned bool
			assigned, err = s.Assigned(ctx, a, in.ID)
			data = map[string]any{"tenant_id": a.Scope.TenantID, "assigned": assigned}
		case "policies.assign", "policies.unassign":
			err = s.Assign(ctx, a, in.ID, intent == "policies.assign")
			data = map[string]bool{"assigned": intent == "policies.assign"}
		case "pii.stats", "pii.byScan":
			data, err = s.Tokens(ctx, a, in.ID, in.Filter)
		case "pii.retentionPreview":
			data, err = s.RetentionPreview(ctx, a)
		case "pii.purge", "pii.deleteTokens", "pii.deleteTenant":
			var affected int64
			affected, err = s.RetentionExecute(ctx, a, in.PreviewID)
			data = map[string]int64{"affected": affected}
		default:
			parts := strings.Split(intent, ".")
			if len(parts) != 2 {
				return nil, &dash.Error{Code: dash.CodeBadRequest, Message: "Unsupported intent"}
			}
			kind, op := parts[0], parts[1]
			switch op {
			case "list":
				data, err = s.List(ctx, a, kind, in.Filter)
			case "detail":
				data, err = s.Get(ctx, a, kind, in.ID)
			case "create":
				data, err = s.Create(ctx, a, kind, in.Row)
			case "update":
				data, err = s.Update(ctx, a, kind, in.ID, in.Row)
			case "setEnabled":
				if in.Enabled == nil {
					err = &dash.Error{Code: dash.CodeBadRequest, Message: "enabled is required"}
				} else {
					b, _ := json.Marshal(map[string]bool{"enabled": *in.Enabled})
					data, err = s.Update(ctx, a, kind, in.ID, b)
				}
			case "delete":
				err = s.Delete(ctx, a, kind, in.ID)
				data = map[string]bool{"deleted": err == nil}
			default:
				err = &dash.Error{Code: dash.CodeBadRequest, Message: "Unsupported intent"}
			}
		}
		if err != nil {
			return nil, mapError(err)
		}
		wire, err := json.Marshal(data)
		if err != nil {
			return nil, mapError(err)
		}
		return &dispatcher.Result{Data: wire}, nil
	}
}
