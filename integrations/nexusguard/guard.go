package nexusguard

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/xraph/nexus/guard"
	"github.com/xraph/nexus/provider"

	"github.com/xraph/shield"
	"github.com/xraph/shield/engine"
	"github.com/xraph/shield/scan"
)

// guardName is the name of both guards.
const guardName = "shield"

// defaultBlockReason stands in when a blocking scan names no reason.
const defaultBlockReason = "Content was blocked by the safety profile."

var (
	errNoEngine          = errors.New("nexusguard: no shield engine")
	errUnreadableContent = errors.New("nexusguard: message content has a shape the guard cannot read")
	errNoQuotedText      = errors.New("nexusguard: shield returned no quoted text for untrusted content")
)

// Input returns a nexus guard for the input phase. It scans the messages of
// the configured roles with Engine.ScanInput (see the package doc).
func Input(eng *engine.Engine, opts ...Option) guard.Guard {
	return &shieldGuard{eng: eng, phase: guard.PhaseInput, opts: newOptions(opts)}
}

// Output returns a nexus guard for the output phase. It scans the
// assistant's reply with Engine.ScanOutput and replaces it when the scan
// redacts.
func Output(eng *engine.Engine, opts ...Option) guard.Guard {
	return &shieldGuard{eng: eng, phase: guard.PhaseOutput, opts: newOptions(opts)}
}

type shieldGuard struct {
	eng   *engine.Engine
	phase guard.Phase
	opts  options
}

var _ guard.Guard = (*shieldGuard)(nil)

func (g *shieldGuard) Name() string { return guardName }

func (g *shieldGuard) Phase() guard.Phase { return g.phase }

// Check scans each message the guard covers, one scan per message. The first
// block ends the check. Any change returns the whole message list, copied,
// so the caller's messages are never edited in place.
func (g *shieldGuard) Check(ctx context.Context, in *guard.CheckInput) (*guard.CheckResult, error) {
	if judging(ctx) {
		return &guard.CheckResult{Passed: true, Action: guard.ActionAllow}, nil
	}
	if in == nil {
		return nil, shield.ErrInvalidInput
	}
	if g.eng == nil {
		return nil, errNoEngine
	}
	ctx, err := g.scope(ctx, in.TenantID)
	if err != nil {
		return nil, err
	}
	md := scanMetadata(in.Metadata)

	var (
		out      []provider.Message
		ids      []string
		decision = scan.DecisionAllow
	)
	for i, msg := range in.Messages {
		role := strings.ToLower(msg.Role)
		if !g.covers(role) {
			continue
		}
		text, ok := textOf(msg.Content)
		if !ok {
			return nil, fmt.Errorf("%w: message %d holds %T", errUnreadableContent, i, msg.Content)
		}
		if text == "" {
			continue
		}
		untrusted := g.phase == guard.PhaseInput && g.opts.untrusted[role]
		res, scanErr := g.scan(ctx, &scan.Input{
			Text: text, Profile: g.opts.profile, Source: sourceOf(role), Untrusted: untrusted, Metadata: md,
		})
		if scanErr != nil {
			return nil, scanErr
		}
		switch res.Decision {
		case scan.DecisionAllow:
		case scan.DecisionFlag, scan.DecisionRedact:
			ids = append(ids, res.ID.String())
			decision = scan.Stricter(decision, res.Decision)
		default:
			// Block, and any decision a text scan should never give.
			return blocked(res, append(ids, res.ID.String())), nil
		}
		if !untrusted && res.Decision != scan.DecisionRedact {
			continue
		}
		if untrusted && res.Redacted == "" {
			return nil, errNoQuotedText
		}
		if out == nil {
			out = slices.Clone(in.Messages)
		}
		out[i].Content = withText(msg.Content, res.Redacted)
	}

	result := &guard.CheckResult{Passed: true, Action: guard.ActionAllow}
	switch decision {
	case scan.DecisionRedact:
		result.Action = guard.ActionRedact
	case scan.DecisionFlag:
		result.Action = guard.ActionWarn
	}
	if len(ids) > 0 {
		result.Details = map[string]any{"scan_ids": ids}
	}
	if out != nil {
		result.Modified, result.Messages = true, out
	}
	if result.Modified || result.Action != guard.ActionAllow {
		result.Guard = guardName
	}
	return result, nil
}

// covers reports whether the guard scans a message of role (lower case).
// The output phase holds the model's reply, whose role is "assistant" or,
// from some providers, empty.
func (g *shieldGuard) covers(role string) bool {
	if g.phase == guard.PhaseOutput {
		return role == "assistant" || role == ""
	}
	return role != "system" && (g.opts.roles[role] || g.opts.untrusted[role])
}

// sourceOf is the scan source of a message of role: "<role>_message", and
// "assistant_message" for a reply that names no role.
func sourceOf(role string) string {
	if role == "" {
		role = "assistant"
	}
	return role + "_message"
}

func (g *shieldGuard) scan(ctx context.Context, in *scan.Input) (*scan.Result, error) {
	if g.phase == guard.PhaseOutput {
		return g.eng.ScanOutput(ctx, in)
	}
	return g.eng.ScanInput(ctx, in)
}

// scope puts the shield tenant, and the app when one is configured, on ctx.
func (g *shieldGuard) scope(ctx context.Context, nexusTenant string) (context.Context, error) {
	var tenant string
	if g.opts.tenant != nil {
		tenant = g.opts.tenant(ctx, nexusTenant)
	} else {
		tenant = shield.TenantFromContext(ctx)
		if tenant == "" {
			tenant = nexusTenant
		}
	}
	if tenant == "" {
		return nil, shield.ErrTenantRequired
	}
	ctx = shield.WithTenant(ctx, tenant)
	if g.opts.app != "" {
		ctx = shield.WithApp(ctx, g.opts.app)
	}
	return ctx, nil
}

// blocked is the guard's verdict on a scan that blocked. The reason is
// shield's fixed message for the deciding finding and never quotes content.
func blocked(res *scan.Result, ids []string) *guard.CheckResult {
	reason := res.Reason()
	if reason == "" {
		reason = defaultBlockReason
	}
	return &guard.CheckResult{
		Blocked: true,
		Action:  guard.ActionBlock,
		Reason:  reason,
		Details: map[string]any{"scan_ids": ids},
		Guard:   guardName,
	}
}

// scanMetadata copies the request's metadata for the stored scan, nil when
// there is none.
func scanMetadata(md map[string]string) map[string]any {
	if len(md) == 0 {
		return nil
	}
	out := make(map[string]any, len(md))
	for k, v := range md {
		out[k] = v
	}
	return out
}

// textOf returns the text of a message's content: the string itself, or the
// text of its parts joined by newlines. ok is false when the guard cannot
// read content's shape.
func textOf(content any) (text string, ok bool) {
	switch c := content.(type) {
	case nil:
		return "", true
	case string:
		return c, true
	case []provider.ContentPart:
		return joinTexts(c, func(p provider.ContentPart) (string, bool) { return p.Text, true })
	case []map[string]any:
		return joinTexts(c, func(m map[string]any) (string, bool) { return mapText(m), true })
	case []any:
		return joinTexts(c, anyText)
	}
	return "", false
}

func joinTexts[T any](parts []T, text func(T) (string, bool)) (string, bool) {
	texts := make([]string, 0, len(parts))
	for _, p := range parts {
		t, ok := text(p)
		if !ok {
			return "", false
		}
		if t != "" {
			texts = append(texts, t)
		}
	}
	return strings.Join(texts, "\n"), true
}

// mapText is the text of a JSON content part, whatever its type.
func mapText(m map[string]any) string {
	if t, ok := m["text"].(string); ok {
		return t
	}
	return ""
}

func anyText(el any) (string, bool) {
	switch p := el.(type) {
	case map[string]any:
		return mapText(p), true
	case provider.ContentPart:
		return p.Text, true
	case *provider.ContentPart:
		if p == nil {
			return "", true
		}
		return p.Text, true
	}
	return "", false
}

// withText returns content with its text replaced by text. A part list gets
// text in its first part that has any; the others lose theirs, and a part of
// type "text" left with nothing is dropped. Other parts are kept as they are.
// content is never edited in place.
func withText(content any, text string) any {
	switch c := content.(type) {
	case []provider.ContentPart:
		return rewriteParts(c, text, func(p provider.ContentPart) string { return p.Text }, editPart)
	case []map[string]any:
		return rewriteParts(c, text, mapText, editMap)
	case []any:
		return rewriteParts(c, text, func(el any) string {
			if t, ok := anyText(el); ok {
				return t
			}
			return ""
		}, editAny)
	}
	return text
}

// rewriteParts puts text in the first part that has text and clears the
// rest with edit, which reports whether to keep the part.
func rewriteParts[T any](parts []T, text string, textOfPart func(T) string, edit func(T, string) (T, bool)) []T {
	out := make([]T, 0, len(parts))
	placed := false
	for _, p := range parts {
		if textOfPart(p) == "" {
			out = append(out, p)
			continue
		}
		next := ""
		if !placed {
			next, placed = text, true
		}
		if edited, keep := edit(p, next); keep {
			out = append(out, edited)
		}
	}
	return out
}

func editPart(p provider.ContentPart, text string) (provider.ContentPart, bool) {
	if text == "" && p.Type == "text" {
		return p, false
	}
	p.Text = text
	return p, true
}

func editMap(m map[string]any, text string) (map[string]any, bool) {
	if text == "" && m["type"] == "text" {
		return m, false
	}
	m = maps.Clone(m)
	if text == "" {
		delete(m, "text")
	} else {
		m["text"] = text
	}
	return m, true
}

func editAny(el any, text string) (any, bool) {
	switch p := el.(type) {
	case map[string]any:
		return editMap(p, text)
	case provider.ContentPart:
		return editPart(p, text)
	case *provider.ContentPart:
		edited, keep := editPart(*p, text)
		return &edited, keep
	}
	return el, true
}
