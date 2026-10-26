// Package presets holds ready-made safety configurations a host seeds for
// each of its tenants. A Bundle is a set of primitives, safety profiles and
// org-level policies; Seed writes the rows a tenant lacks and keeps every
// row it already has, so a tenant's own edits survive a re-seed.
package presets

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/xraph/shield"
	"github.com/xraph/shield/awareness"
	"github.com/xraph/shield/boundary"
	"github.com/xraph/shield/id"
	"github.com/xraph/shield/instinct"
	"github.com/xraph/shield/judgment"
	"github.com/xraph/shield/policy"
	"github.com/xraph/shield/profile"
	"github.com/xraph/shield/reflex"
	"github.com/xraph/shield/store"
	"github.com/xraph/shield/values"
)

// Bundle is a preset: the rows Seed writes for one tenant. Rows carry no ID,
// app or tenant; Seed sets them on its own copies.
type Bundle struct {
	Name       string
	Instincts  []*instinct.Instinct
	Awareness  []*awareness.Awareness
	Boundaries []*boundary.Boundary
	Values     []*values.Values
	Judgments  []*judgment.Judgment
	Reflexes   []*reflex.Reflex
	Profiles   []*profile.SafetyProfile
	Policies   []*policy.Policy // org level; Seed sets ScopeKey to the tenant
}

// SeedReport lists the rows one Seed call wrote and the rows it found
// already there, each as "<kind>/<name>": instinct, awareness, boundary,
// values, judgment, reflex, profile or policy.
type SeedReport struct {
	Created []string
	Kept    []string
}

// Seed creates every row the tenant lacks (by name within app and tenant) and
// leaves existing rows untouched, so a workspace's edits survive. It puts the
// tenant on ctx itself. Empty tenantID is shield.ErrTenantRequired.
//
// Primitives go first, then profiles, then policies, so a profile is never
// stored before what it references. Each policy is written at org level with
// ScopeKey set to tenantID, the only kind of policy a tenant may own.
//
// Seed is safe to run from several processes at once for one tenant: names
// are unique per app and tenant (policies per scope key), so when two calls
// race to create the same row one create fails, and Seed counts a row that
// exists once its create failed as kept rather than returning the error.
// Seed does not invalidate any engine's profile cache; a tenant that had no
// profile before has nothing cached.
func (b Bundle) Seed(ctx context.Context, s store.Store, tenantID, appID string) (SeedReport, error) {
	var rep SeedReport
	if strings.TrimSpace(tenantID) == "" {
		return rep, shield.ErrTenantRequired
	}
	if s == nil {
		return rep, shield.ErrNoStore
	}
	ctx = shield.WithApp(shield.WithTenant(ctx, tenantID), appID)
	sd := &seeder{report: &rep}

	for _, r := range b.Instincts {
		if r == nil {
			continue
		}
		row := *r
		row.ID, row.AppID, row.TenantID = id.NewInstinctID(), appID, tenantID
		sd.seed("instinct", row.Name, shield.ErrInstinctNotFound,
			func() error { return second(s.GetInstinctByName(ctx, appID, row.Name)) },
			func() error { return s.CreateInstinct(ctx, &row) })
	}
	for _, r := range b.Awareness {
		if r == nil {
			continue
		}
		row := *r
		row.ID, row.AppID, row.TenantID = id.NewAwarenessID(), appID, tenantID
		sd.seed("awareness", row.Name, shield.ErrAwarenessNotFound,
			func() error { return second(s.GetAwarenessByName(ctx, appID, row.Name)) },
			func() error { return s.CreateAwareness(ctx, &row) })
	}
	for _, r := range b.Boundaries {
		if r == nil {
			continue
		}
		row := *r
		row.ID, row.AppID, row.TenantID = id.NewBoundaryID(), appID, tenantID
		sd.seed("boundary", row.Name, shield.ErrBoundaryNotFound,
			func() error { return second(s.GetBoundaryByName(ctx, appID, row.Name)) },
			func() error { return s.CreateBoundary(ctx, &row) })
	}
	for _, r := range b.Values {
		if r == nil {
			continue
		}
		row := *r
		row.ID, row.AppID, row.TenantID = id.NewValueID(), appID, tenantID
		sd.seed("values", row.Name, shield.ErrValueNotFound,
			func() error { return second(s.GetValuesByName(ctx, appID, row.Name)) },
			func() error { return s.CreateValues(ctx, &row) })
	}
	for _, r := range b.Judgments {
		if r == nil {
			continue
		}
		row := *r
		row.ID, row.AppID, row.TenantID = id.NewJudgmentID(), appID, tenantID
		sd.seed("judgment", row.Name, shield.ErrJudgmentNotFound,
			func() error { return second(s.GetJudgmentByName(ctx, appID, row.Name)) },
			func() error { return s.CreateJudgment(ctx, &row) })
	}
	for _, r := range b.Reflexes {
		if r == nil {
			continue
		}
		row := *r
		row.ID, row.AppID, row.TenantID = id.NewReflexID(), appID, tenantID
		sd.seed("reflex", row.Name, shield.ErrReflexNotFound,
			func() error { return second(s.GetReflexByName(ctx, appID, row.Name)) },
			func() error { return s.CreateReflex(ctx, &row) })
	}
	for _, r := range b.Profiles {
		if r == nil {
			continue
		}
		row := *r
		row.ID, row.AppID, row.TenantID = id.NewSafetyProfileID(), appID, tenantID
		sd.seed("profile", row.Name, shield.ErrProfileNotFound,
			func() error { return second(s.GetProfileByName(ctx, appID, row.Name)) },
			func() error { return s.CreateProfile(ctx, &row) })
	}
	for _, r := range b.Policies {
		if r == nil {
			continue
		}
		row := *r
		row.ID, row.ScopeKey, row.ScopeLevel = id.NewPolicyID(), tenantID, policy.ScopeOrg
		sd.seed("policy", row.Name, shield.ErrPolicyNotFound,
			func() error { return second(s.GetPolicyByName(ctx, tenantID, row.Name)) },
			func() error { return s.CreatePolicy(ctx, &row) })
	}
	if sd.err != nil {
		return rep, sd.err
	}
	return rep, nil
}

// seeder writes rows one at a time and stops at the first error.
type seeder struct {
	report *SeedReport
	err    error
}

// seed creates one row unless it exists. exists returns nil when the row is
// there and notFound when it is not; any other error stops the seed. A
// create that fails while the row now exists means another caller created
// it first, and the row is kept.
func (sd *seeder) seed(kind, name string, notFound error, exists, create func() error) {
	if sd.err != nil {
		return
	}
	key := kind + "/" + name
	err := exists()
	switch {
	case err == nil:
		sd.report.Kept = append(sd.report.Kept, key)
		return
	case !errors.Is(err, notFound):
		sd.err = fmt.Errorf("presets: seed %s: %w", key, err)
		return
	}
	createErr := create()
	if createErr == nil {
		sd.report.Created = append(sd.report.Created, key)
		return
	}
	if exists() == nil {
		sd.report.Kept = append(sd.report.Kept, key)
		return
	}
	sd.err = fmt.Errorf("presets: seed %s: %w", key, createErr)
}

// second returns the error of a (value, error) pair.
func second[T any](_ T, err error) error { return err }
