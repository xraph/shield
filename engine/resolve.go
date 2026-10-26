package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"

	"github.com/xraph/shield"
	"github.com/xraph/shield/awareness"
	"github.com/xraph/shield/boundary"
	"github.com/xraph/shield/instinct"
	"github.com/xraph/shield/internal/telemetry"
	"github.com/xraph/shield/judgment"
	"github.com/xraph/shield/profile"
	"github.com/xraph/shield/reflex"
	"github.com/xraph/shield/values"
)

// profileKey identifies a cached profile. Names are unique per app and
// tenant, so one tenant never reads another's entry.
type profileKey struct{ tenant, app, name string }

type cachedProfile struct {
	profile *compiledProfile
	expires time.Time
}

// profileCache holds compiled profiles. Each tenant has a generation that
// InvalidateProfiles bumps, so a load that started before an invalidation
// cannot store the rows it read.
type profileCache struct {
	mu          sync.Mutex
	entries     map[profileKey]cachedProfile
	generations map[string]uint64
	// global is bumped by InvalidateAllProfiles; a tenant's generation is
	// its own plus this one.
	global uint64
}

func newProfileCache() *profileCache {
	return &profileCache{entries: map[profileKey]cachedProfile{}, generations: map[string]uint64{}}
}

func (c *profileCache) get(k profileKey, now time.Time) (*compiledProfile, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[k]
	if !ok || !now.Before(e.expires) {
		return nil, false
	}
	return e.profile, true
}

func (c *profileCache) generation(tenant string) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.global + c.generations[tenant]
}

// put stores p unless the tenant was invalidated since generation gen.
func (c *profileCache) put(k profileKey, p *compiledProfile, expires time.Time, gen uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.global+c.generations[k.tenant] != gen {
		return
	}
	c.entries[k] = cachedProfile{profile: p, expires: expires}
}

func (c *profileCache) invalidate(tenant string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.generations[tenant]++
	for k := range c.entries {
		if k.tenant == tenant {
			delete(c.entries, k)
		}
	}
}

func (c *profileCache) invalidateAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.global++
	clear(c.entries)
}

// InvalidateAllProfiles drops every tenant's cached profiles, so each
// tenant's next scan loads its profile and policies again. Call it after
// changing an app-level policy outside the admin service, which calls it for
// you: every tenant the policy is assigned to compiles it in.
func (e *Engine) InvalidateAllProfiles() {
	e.profiles.invalidateAll()
}

// InvalidateProfiles drops every cached profile of tenantID, so the next
// scan for that tenant loads its profile and primitives again. Call it after
// changing a tenant's safety rows outside the admin service, which calls it
// for you.
func (e *Engine) InvalidateProfiles(tenantID string) {
	e.profiles.invalidate(tenantID)
}

// ProfileGeneration returns a number that changes whenever
// InvalidateProfiles(tenantID) or InvalidateAllProfiles runs. A host that
// caches scan verdicts keys them on it, so a profile change made through
// the admin service (or followed by an invalidation) is never answered from
// a stale verdict.
func (e *Engine) ProfileGeneration(tenantID string) uint64 {
	return e.profiles.generation(tenantID)
}

// resolveProfile returns the compiled profile name of (tenant, app), from
// the cache when it is fresh. It runs under a "resolve profile" span.
func (e *Engine) resolveProfile(ctx context.Context, tenant, app, name string) (*compiledProfile, error) {
	ctx, span := telemetry.Tracer().Start(ctx, "resolve profile")
	defer span.End()

	key := profileKey{tenant: tenant, app: app, name: name}
	ttl := e.config.ProfileCacheTTL
	if ttl > 0 {
		if p, ok := e.profiles.get(key, time.Now()); ok {
			span.SetAttributes(attribute.Bool("shield.profile.cached", true))
			return p, nil
		}
	}
	span.SetAttributes(attribute.Bool("shield.profile.cached", false))
	gen := e.profiles.generation(tenant)
	p, err := e.loadProfile(ctx, tenant, app, name)
	if err != nil {
		telemetry.Fail(span, "resolve_failed", err)
		return nil, err
	}
	if ttl > 0 {
		e.profiles.put(key, p, time.Now().Add(ttl), gen)
	}
	return p, nil
}

// loadProfile reads the profile and every primitive it references from the
// store, filtered on (app, tenant), and the policies that apply to the
// tenant, and compiles them.
func (e *Engine) loadProfile(ctx context.Context, tenant, app, name string) (*compiledProfile, error) {
	profiles, err := e.store.ListProfiles(ctx, &profile.ListFilter{AppID: app, TenantID: tenant})
	if err != nil {
		return nil, fmt.Errorf("shield: load profile: %w", err)
	}
	var p *profile.SafetyProfile
	for _, row := range profiles {
		if row.Name == name && row.AppID == app {
			p = row
			break
		}
	}
	if p == nil || !p.Enabled {
		return nil, fmt.Errorf("%w: %s", shield.ErrNoProfile, name)
	}

	rows := &profileRows{}
	instinctNames := make([]string, 0, len(p.Instincts))
	for _, a := range p.Instincts {
		instinctNames = append(instinctNames, a.InstinctName)
	}
	if rows.instincts, err = loadNamed("instinct", instinctNames, app, func() ([]*instinct.Instinct, error) {
		return e.store.ListInstincts(ctx, &instinct.ListFilter{AppID: app, TenantID: tenant})
	}, func(r *instinct.Instinct) (string, string, bool) { return r.Name, r.AppID, r.Enabled }); err != nil {
		return nil, err
	}
	awarenessNames := make([]string, 0, len(p.Awareness))
	for _, a := range p.Awareness {
		awarenessNames = append(awarenessNames, a.AwarenessName)
	}
	if rows.awareness, err = loadNamed("awareness", awarenessNames, app, func() ([]*awareness.Awareness, error) {
		return e.store.ListAwareness(ctx, &awareness.ListFilter{AppID: app, TenantID: tenant})
	}, func(r *awareness.Awareness) (string, string, bool) { return r.Name, r.AppID, r.Enabled }); err != nil {
		return nil, err
	}
	if rows.boundaries, err = loadNamed("boundary", p.Boundaries, app, func() ([]*boundary.Boundary, error) {
		return e.store.ListBoundaries(ctx, &boundary.ListFilter{AppID: app, TenantID: tenant})
	}, func(r *boundary.Boundary) (string, string, bool) { return r.Name, r.AppID, r.Enabled }); err != nil {
		return nil, err
	}
	if rows.values, err = loadNamed("values", p.Values, app, func() ([]*values.Values, error) {
		return e.store.ListValues(ctx, &values.ListFilter{AppID: app, TenantID: tenant})
	}, func(r *values.Values) (string, string, bool) { return r.Name, r.AppID, r.Enabled }); err != nil {
		return nil, err
	}
	judgmentNames := make([]string, 0, len(p.Judgments))
	for _, a := range p.Judgments {
		judgmentNames = append(judgmentNames, a.JudgmentName)
	}
	if rows.judgments, err = loadNamed("judgment", judgmentNames, app, func() ([]*judgment.Judgment, error) {
		return e.store.ListJudgments(ctx, &judgment.ListFilter{AppID: app, TenantID: tenant})
	}, func(r *judgment.Judgment) (string, string, bool) { return r.Name, r.AppID, r.Enabled }); err != nil {
		return nil, err
	}
	if rows.reflexes, err = loadNamed("reflex", p.Reflexes, app, func() ([]*reflex.Reflex, error) {
		return e.store.ListReflexes(ctx, &reflex.ListFilter{AppID: app, TenantID: tenant})
	}, func(r *reflex.Reflex) (string, string, bool) { return r.Name, r.AppID, r.Enabled }); err != nil {
		return nil, err
	}
	policies, err := e.loadPolicies(ctx, tenant, app)
	if err != nil {
		return nil, err
	}
	compiled, err := compileProfile(p, rows, policies)
	if err != nil {
		return nil, err
	}
	return compiled, nil
}

// loadNamed lists one kind of primitive and indexes the rows of app by
// name. A referenced name with no row is ErrProfileInvalid; a disabled row
// maps to nil, which the compiler skips. Nothing is listed when no name is
// referenced.
func loadNamed[T any](kind string, names []string, app string,
	list func() ([]*T, error), describe func(*T) (name, appID string, enabled bool),
) (map[string]*T, error) {
	if len(names) == 0 {
		return nil, nil
	}
	rows, err := list()
	if err != nil {
		return nil, fmt.Errorf("shield: load %s: %w", kind, err)
	}
	byName := make(map[string]*T, len(rows))
	present := make(map[string]bool, len(rows))
	for _, row := range rows {
		name, appID, enabled := describe(row)
		if appID != app {
			continue
		}
		present[name] = true
		if enabled {
			byName[name] = row
		}
	}
	for _, name := range names {
		if !present[name] {
			return nil, invalid(kind, name, "")
		}
	}
	return byName, nil
}
