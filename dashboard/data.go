package dashboard

import (
	"context"
	"strconv"

	"github.com/xraph/shield/awareness"
	"github.com/xraph/shield/boundary"
	"github.com/xraph/shield/compliance"
	"github.com/xraph/shield/dashboard/shared"
	"github.com/xraph/shield/instinct"
	"github.com/xraph/shield/judgment"
	"github.com/xraph/shield/pii"
	"github.com/xraph/shield/policy"
	"github.com/xraph/shield/profile"
	"github.com/xraph/shield/reflex"
	"github.com/xraph/shield/scan"
	"github.com/xraph/shield/store"
	"github.com/xraph/shield/values"
)

// PaginationMeta is an alias for shared.PaginationMeta.
type PaginationMeta = shared.PaginationMeta

// NewPaginationMeta is a convenience re-export.
var NewPaginationMeta = shared.NewPaginationMeta

// --- Helper Functions ---

func parseIntParam(params map[string]string, key string, defaultVal int) int {
	v, ok := params[key]
	if !ok || v == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return defaultVal
	}
	return n
}

// --- Entity Counts ---

// entityCounts is a type alias for shared.EntityCounts.
type entityCounts = shared.EntityCounts

func fetchEntityCounts(ctx context.Context, s store.Store, appID string) entityCounts {
	var c entityCounts
	if items, err := s.ListInstincts(ctx, &instinct.ListFilter{AppID: appID}); err == nil {
		c.Instincts = int64(len(items))
	}
	if items, err := s.ListAwareness(ctx, &awareness.ListFilter{AppID: appID}); err == nil {
		c.Awareness = int64(len(items))
	}
	if items, err := s.ListBoundaries(ctx, &boundary.ListFilter{AppID: appID}); err == nil {
		c.Boundaries = int64(len(items))
	}
	if items, err := s.ListValues(ctx, &values.ListFilter{AppID: appID}); err == nil {
		c.Values = int64(len(items))
	}
	if items, err := s.ListJudgments(ctx, &judgment.ListFilter{AppID: appID}); err == nil {
		c.Judgments = int64(len(items))
	}
	if items, err := s.ListReflexes(ctx, &reflex.ListFilter{AppID: appID}); err == nil {
		c.Reflexes = int64(len(items))
	}
	if items, err := s.ListProfiles(ctx, &profile.ListFilter{AppID: appID}); err == nil {
		c.Profiles = int64(len(items))
	}
	if items, err := s.ListScans(ctx, &scan.ListFilter{AppID: appID}); err == nil {
		c.Scans = int64(len(items))
	}
	if items, err := s.ListPolicies(ctx, &policy.ListFilter{}); err == nil {
		c.Policies = int64(len(items))
	}
	return c
}

// --- Paginated Fetch Functions ---

func fetchInstinctsPaginated(ctx context.Context, s store.Store, appID string, category instinct.Category, limit, offset int) ([]*instinct.Instinct, int64, error) {
	filter := &instinct.ListFilter{AppID: appID, Category: category, Limit: limit, Offset: offset}
	items, err := s.ListInstincts(ctx, filter)
	if err != nil {
		return nil, 0, err
	}
	all, err := s.ListInstincts(ctx, &instinct.ListFilter{AppID: appID, Category: category})
	if err != nil {
		return items, 0, nil
	}
	return items, int64(len(all)), nil
}

func fetchAwarenessPaginated(ctx context.Context, s store.Store, appID string, focus awareness.Focus, limit, offset int) ([]*awareness.Awareness, int64, error) {
	filter := &awareness.ListFilter{AppID: appID, Focus: focus, Limit: limit, Offset: offset}
	items, err := s.ListAwareness(ctx, filter)
	if err != nil {
		return nil, 0, err
	}
	all, err := s.ListAwareness(ctx, &awareness.ListFilter{AppID: appID, Focus: focus})
	if err != nil {
		return items, 0, nil
	}
	return items, int64(len(all)), nil
}

func fetchBoundariesPaginated(ctx context.Context, s store.Store, appID string, scope boundary.Scope, limit, offset int) ([]*boundary.Boundary, int64, error) {
	filter := &boundary.ListFilter{AppID: appID, Scope: scope, Limit: limit, Offset: offset}
	items, err := s.ListBoundaries(ctx, filter)
	if err != nil {
		return nil, 0, err
	}
	all, err := s.ListBoundaries(ctx, &boundary.ListFilter{AppID: appID, Scope: scope})
	if err != nil {
		return items, 0, nil
	}
	return items, int64(len(all)), nil
}

func fetchValuesPaginated(ctx context.Context, s store.Store, appID string, limit, offset int) ([]*values.Values, int64, error) {
	filter := &values.ListFilter{AppID: appID, Limit: limit, Offset: offset}
	items, err := s.ListValues(ctx, filter)
	if err != nil {
		return nil, 0, err
	}
	all, err := s.ListValues(ctx, &values.ListFilter{AppID: appID})
	if err != nil {
		return items, 0, nil
	}
	return items, int64(len(all)), nil
}

func fetchJudgmentsPaginated(ctx context.Context, s store.Store, appID string, domain judgment.Domain, limit, offset int) ([]*judgment.Judgment, int64, error) {
	filter := &judgment.ListFilter{AppID: appID, Domain: domain, Limit: limit, Offset: offset}
	items, err := s.ListJudgments(ctx, filter)
	if err != nil {
		return nil, 0, err
	}
	all, err := s.ListJudgments(ctx, &judgment.ListFilter{AppID: appID, Domain: domain})
	if err != nil {
		return items, 0, nil
	}
	return items, int64(len(all)), nil
}

func fetchReflexesPaginated(ctx context.Context, s store.Store, appID string, limit, offset int) ([]*reflex.Reflex, int64, error) {
	filter := &reflex.ListFilter{AppID: appID, Limit: limit, Offset: offset}
	items, err := s.ListReflexes(ctx, filter)
	if err != nil {
		return nil, 0, err
	}
	all, err := s.ListReflexes(ctx, &reflex.ListFilter{AppID: appID})
	if err != nil {
		return items, 0, nil
	}
	return items, int64(len(all)), nil
}

func fetchProfilesPaginated(ctx context.Context, s store.Store, appID string, limit, offset int) ([]*profile.SafetyProfile, int64, error) {
	filter := &profile.ListFilter{AppID: appID, Limit: limit, Offset: offset}
	items, err := s.ListProfiles(ctx, filter)
	if err != nil {
		return nil, 0, err
	}
	all, err := s.ListProfiles(ctx, &profile.ListFilter{AppID: appID})
	if err != nil {
		return items, 0, nil
	}
	return items, int64(len(all)), nil
}

func fetchScansPaginated(ctx context.Context, s store.Store, appID string, direction scan.Direction, decision scan.Decision, limit, offset int) ([]*scan.Result, int64, error) {
	filter := &scan.ListFilter{AppID: appID, Direction: direction, Decision: decision, Limit: limit, Offset: offset}
	items, err := s.ListScans(ctx, filter)
	if err != nil {
		return nil, 0, err
	}
	all, err := s.ListScans(ctx, &scan.ListFilter{AppID: appID, Direction: direction, Decision: decision})
	if err != nil {
		return items, 0, nil
	}
	return items, int64(len(all)), nil
}

func fetchPoliciesPaginated(ctx context.Context, s store.Store, scopeKey string, scopeLevel policy.ScopeLevel, limit, offset int) ([]*policy.Policy, int64, error) {
	filter := &policy.ListFilter{ScopeKey: scopeKey, ScopeLevel: scopeLevel, Limit: limit, Offset: offset}
	items, err := s.ListPolicies(ctx, filter)
	if err != nil {
		return nil, 0, err
	}
	all, err := s.ListPolicies(ctx, &policy.ListFilter{ScopeKey: scopeKey, ScopeLevel: scopeLevel})
	if err != nil {
		return items, 0, nil
	}
	return items, int64(len(all)), nil
}

func fetchComplianceReportsPaginated(ctx context.Context, s store.Store, scopeKey string, framework compliance.Framework, limit, offset int) ([]*compliance.Report, int64, error) {
	filter := &compliance.ListFilter{ScopeKey: scopeKey, Framework: framework, Limit: limit, Offset: offset}
	items, err := s.ListReports(ctx, filter)
	if err != nil {
		return nil, 0, err
	}
	all, err := s.ListReports(ctx, &compliance.ListFilter{ScopeKey: scopeKey, Framework: framework})
	if err != nil {
		return items, 0, nil
	}
	return items, int64(len(all)), nil
}

// --- Stats Helpers ---

func fetchScanStats(ctx context.Context, s store.Store, appID string) *scan.Stats {
	stats, err := s.ScanStats(ctx, &scan.StatsFilter{AppID: appID})
	if err != nil {
		return &scan.Stats{}
	}
	return stats
}

func fetchPIIStats(ctx context.Context, s store.Store, tenantID string) *pii.Stats {
	stats, err := s.PIIStats(ctx, tenantID)
	if err != nil {
		return &pii.Stats{}
	}
	return stats
}

// --- Non-Paginated Helpers ---

func fetchRecentScans(ctx context.Context, s store.Store, limit int) []*scan.Result {
	items, err := s.ListScans(ctx, &scan.ListFilter{Limit: limit})
	if err != nil {
		return nil
	}
	return items
}

func fetchAllProfiles(ctx context.Context, s store.Store) []*profile.SafetyProfile {
	items, err := s.ListProfiles(ctx, &profile.ListFilter{})
	if err != nil {
		return nil
	}
	return items
}

// --- Usage Counting ---

func countInstinctUsageInProfiles(profiles []*profile.SafetyProfile, name string) int {
	count := 0
	for _, p := range profiles {
		for _, ia := range p.Instincts {
			if ia.InstinctName == name {
				count++
				break
			}
		}
	}
	return count
}

func countAwarenessUsageInProfiles(profiles []*profile.SafetyProfile, name string) int {
	count := 0
	for _, p := range profiles {
		for _, aa := range p.Awareness {
			if aa.AwarenessName == name {
				count++
				break
			}
		}
	}
	return count
}

func countBoundaryUsageInProfiles(profiles []*profile.SafetyProfile, name string) int {
	count := 0
	for _, p := range profiles {
		for _, b := range p.Boundaries {
			if b == name {
				count++
				break
			}
		}
	}
	return count
}

func countValueUsageInProfiles(profiles []*profile.SafetyProfile, name string) int {
	count := 0
	for _, p := range profiles {
		for _, v := range p.Values {
			if v == name {
				count++
				break
			}
		}
	}
	return count
}

func countJudgmentUsageInProfiles(profiles []*profile.SafetyProfile, name string) int {
	count := 0
	for _, p := range profiles {
		for _, ja := range p.Judgments {
			if ja.JudgmentName == name {
				count++
				break
			}
		}
	}
	return count
}

func countReflexUsageInProfiles(profiles []*profile.SafetyProfile, name string) int {
	count := 0
	for _, p := range profiles {
		for _, r := range p.Reflexes {
			if r == name {
				count++
				break
			}
		}
	}
	return count
}
