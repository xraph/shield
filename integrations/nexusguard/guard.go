package nexusguard

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

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

// maxUnwrap bounds how many layers of shield's own quoting a text loses
// before it is scanned again.
const maxUnwrap = 8

// reservedMetadata are the scan metadata keys the engine owns. Request
// metadata never sets them.
var reservedMetadata = []string{"source", "untrusted", "secret_count"}

var (
	errNoEngine     = errors.New("nexusguard: no shield engine")
	errNoQuotedText = errors.New("nexusguard: shield returned no quoted text for untrusted content")
)

// Input returns a nexus guard for the input phase. It scans the messages of
// the configured roles with Engine.ScanInput (see the package doc).
func Input(eng *engine.Engine, opts ...Option) guard.Guard {
	return newGuard(eng, guard.PhaseInput, opts)
}

// Output returns a nexus guard for the output phase. It scans every reply
// message with Engine.ScanOutput and replaces its text when the scan
// redacts.
func Output(eng *engine.Engine, opts ...Option) guard.Guard {
	return newGuard(eng, guard.PhaseOutput, opts)
}

func newGuard(eng *engine.Engine, phase guard.Phase, opts []Option) *shieldGuard {
	g := &shieldGuard{eng: eng, phase: phase, opts: newOptions(opts)}
	if eng != nil {
		g.ttl = eng.Config().ProfileCacheTTL
	}
	if g.ttl > 0 {
		g.cache = newVerdictCache(g.opts.cacheSize)
	}
	return g
}

type shieldGuard struct {
	eng   *engine.Engine
	phase guard.Phase
	opts  options
	cache *verdictCache // nil when off
	ttl   time.Duration
}

var _ guard.Guard = (*shieldGuard)(nil)

func (g *shieldGuard) Name() string { return guardName }

func (g *shieldGuard) Phase() guard.Phase { return g.phase }

// Check scans each text of each message the guard covers, one scan per
// text, answering from the verdict cache when it can. The first block ends
// the check. Any change returns the whole message list, copied, so the
// caller's messages are never edited in place.
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
	ctx, tenant, err := g.scope(ctx, in.TenantID)
	if err != nil {
		return nil, err
	}
	run := &checkRun{tenant: tenant, app: shield.AppFromContext(ctx), metadata: scanMetadata(in.Metadata)}

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
		cc, readErr := readContent(msg.Content)
		if readErr != nil {
			return nil, fmt.Errorf("%w (message %d)", readErr, i)
		}
		untrusted := g.phase == guard.PhaseInput && g.opts.untrusted[role]
		changed := false
		for _, sl := range cc.slots {
			v, verdictErr := g.verdict(ctx, run, sl.text, role, untrusted)
			if verdictErr != nil {
				return nil, verdictErr
			}
			if v.decision == scan.DecisionBlock {
				return blocked(v.reason, append(ids, v.scanID)), nil
			}
			if v.decision != scan.DecisionAllow {
				ids = append(ids, v.scanID)
				decision = scan.Stricter(decision, v.decision)
			}
			if v.replace {
				sl.set(v.text)
				changed = true
			}
		}
		if changed {
			if out == nil {
				out = slices.Clone(in.Messages)
			}
			out[i].Content = cc.value
		}
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

// checkRun is what every scan of one check shares.
type checkRun struct {
	tenant, app string
	metadata    map[string]any
}

// covers reports whether the guard scans a message of role (lower case).
// The output phase holds only the model's reply, whatever role a provider
// gives it, so every message there is scanned.
func (g *shieldGuard) covers(role string) bool {
	if g.phase == guard.PhaseOutput {
		return true
	}
	return role != "system" && (g.opts.roles[role] || g.opts.untrusted[role])
}

// verdict decides one text, from the cache when a fresh verdict is there.
// An untrusted text loses any layers of shield's own quoting first, so a
// history that was guarded before is quoted once, not once per turn.
func (g *shieldGuard) verdict(ctx context.Context, run *checkRun, text, role string, untrusted bool) (verdict, error) {
	source := sourceOf(role)
	if untrusted {
		text = unquote(source, text)
	}
	var key verdictKey
	if g.cache != nil {
		key = verdictKey{
			tenant: run.tenant, app: run.app, profile: g.opts.profile, role: role,
			generation: g.eng.ProfileGeneration(run.tenant), untrusted: untrusted,
			sum: sha256.Sum256([]byte(text)),
		}
		if v, ok := g.cache.get(key, time.Now()); ok {
			return v, nil
		}
	}
	if text == "" {
		return verdict{decision: scan.DecisionAllow}, nil
	}
	res, err := g.scan(ctx, &scan.Input{
		Text: text, Profile: g.opts.profile, Source: source, Untrusted: untrusted, Metadata: run.metadata,
	})
	if err != nil {
		return verdict{}, err
	}
	v := verdict{decision: res.Decision, scanID: res.ID.String()}
	switch res.Decision {
	case scan.DecisionAllow, scan.DecisionFlag, scan.DecisionRedact:
	default:
		// Block, and any decision a text scan should never give.
		v.decision = scan.DecisionBlock
		v.reason = res.Reason()
		return v, nil
	}
	if untrusted || res.Decision == scan.DecisionRedact {
		if untrusted && res.Redacted == "" {
			return verdict{}, errNoQuotedText
		}
		v.text, v.replace = res.Redacted, true
	}
	if g.cache != nil {
		g.cache.put(key, v, time.Now().Add(g.ttl))
	}
	return v, nil
}

// unquote strips the envelopes scan.Quote(source, ...) puts around a text.
// The inner text is scanned and quoted again, so a text that only looks
// quoted gains nothing.
func unquote(source, text string) string {
	open := `<` + scan.QuoteTag + ` source="` + source + "\">\n"
	closing := "\n</" + scan.QuoteTag + ">"
	for range maxUnwrap {
		inner, ok := strings.CutPrefix(text, open)
		if !ok {
			return text
		}
		if inner, ok = strings.CutSuffix(inner, closing); !ok {
			return text
		}
		text = inner
	}
	return text
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
func (g *shieldGuard) scope(ctx context.Context, nexusTenant string) (context.Context, string, error) {
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
		return nil, "", shield.ErrTenantRequired
	}
	ctx = shield.WithTenant(ctx, tenant)
	if g.opts.app != "" {
		ctx = shield.WithApp(ctx, g.opts.app)
	}
	return ctx, tenant, nil
}

// blocked is the guard's verdict on a scan that blocked. The reason is
// shield's fixed message for the deciding finding and never quotes content.
func blocked(reason string, ids []string) *guard.CheckResult {
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

// scanMetadata copies the request's metadata for the stored scan, leaving
// out the keys the engine owns. It is nil when nothing is left.
func scanMetadata(md map[string]string) map[string]any {
	out := make(map[string]any, len(md))
	for k, v := range md {
		if !slices.Contains(reservedMetadata, k) {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
