package nexusguard

import (
	"context"
	"strings"
)

// Option configures a guard built by Input or Output.
type Option func(*options)

type options struct {
	profile   string
	app       string
	roles     map[string]bool
	untrusted map[string]bool
	tenant    func(ctx context.Context, nexusTenant string) string
	cacheSize int
}

func newOptions(opts []Option) options {
	o := options{
		roles:     roleSet([]string{"user", "tool"}),
		untrusted: roleSet([]string{"tool"}),
		cacheSize: defaultVerdictCacheSize,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	return o
}

// WithProfile names the shield safety profile each scan uses. Empty, the
// default, leaves it to shield.Config.DefaultProfile.
func WithProfile(name string) Option {
	return func(o *options) { o.profile = name }
}

// WithApp scans under appID. Empty, the default, keeps the app already on
// the context (shield.WithApp).
func WithApp(appID string) Option {
	return func(o *options) { o.app = appID }
}

// WithRoles sets the roles whose messages the input guard scans, replacing
// the default "user" and "tool". Roles match without regard to case, and
// "system" is never scanned. Untrusted roles are scanned whatever this
// lists. The output guard ignores it.
func WithRoles(roles ...string) Option {
	return func(o *options) { o.roles = roleSet(roles) }
}

// WithUntrustedRoles sets the roles whose messages the input guard scans as
// untrusted content (scan.Input.Untrusted, Source "<role>_message"),
// replacing the default "tool". Their messages always come back quoted.
// None at all leaves every role trusted.
func WithUntrustedRoles(roles ...string) Option {
	return func(o *options) { o.untrusted = roleSet(roles) }
}

// WithTenant maps the nexus tenant of a request (CheckInput.TenantID) to the
// shield tenant its scans run under. By default the guards use the shield
// tenant on the context and fall back to the nexus tenant, so a shield
// tenant on the context wins over a different nexus tenant: never leave a
// stale one on a long-lived context. A mapper that returns "" fails the
// check with shield.ErrTenantRequired.
func WithTenant(resolve func(ctx context.Context, nexusTenant string) string) Option {
	return func(o *options) { o.tenant = resolve }
}

func roleSet(roles []string) map[string]bool {
	set := make(map[string]bool, len(roles))
	for _, r := range roles {
		set[strings.ToLower(r)] = true
	}
	return set
}

// WithVerdictCache keeps the verdicts of up to n texts (10,000 by default),
// so a conversation's history is not scanned again on every turn: a text
// whose verdict is cached makes no engine call and stores no new scan, and
// only new or changed messages are scanned. 0 turns the cache off.
//
// A verdict is keyed by tenant, app, profile, role, whether the role is
// untrusted, the engine's ProfileGeneration and the SHA-256 of the text, and
// expires after the engine's ProfileCacheTTL (a negative TTL turns the cache
// off too). A block is never cached, so a profile change that lifts it takes
// effect on the next request. The cache also holds at most 64 MiB of
// replacement text. A cached verdict does not record the request metadata of
// later requests, since no scan is stored for them.
func WithVerdictCache(n int) Option {
	return func(o *options) { o.cacheSize = n }
}
