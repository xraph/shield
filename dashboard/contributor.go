package dashboard

import (
	"context"
	"io"
	"strings"

	"github.com/a-h/templ"

	"github.com/xraph/forge/extensions/dashboard/contributor"

	"github.com/xraph/shield/awareness"
	"github.com/xraph/shield/boundary"
	"github.com/xraph/shield/compliance"
	"github.com/xraph/shield/dashboard/components"
	"github.com/xraph/shield/dashboard/pages"
	"github.com/xraph/shield/dashboard/settings"
	"github.com/xraph/shield/dashboard/widgets"
	"github.com/xraph/shield/engine"
	"github.com/xraph/shield/id"
	"github.com/xraph/shield/instinct"
	"github.com/xraph/shield/judgment"
	"github.com/xraph/shield/policy"
	"github.com/xraph/shield/scan"
	"github.com/xraph/shield/store"
)

var _ contributor.LocalContributor = (*Contributor)(nil)

// Contributor implements the dashboard LocalContributor interface for the
// shield extension.
type Contributor struct {
	manifest *contributor.Manifest
	eng      *engine.Engine
}

// New creates a new shield dashboard contributor.
func New(manifest *contributor.Manifest, eng *engine.Engine) *Contributor {
	return &Contributor{
		manifest: manifest,
		eng:      eng,
	}
}

// Manifest returns the contributor manifest.
func (c *Contributor) Manifest() *contributor.Manifest { return c.manifest }

// RenderPage renders a page for the given route.
func (c *Contributor) RenderPage(ctx context.Context, route string, params contributor.Params) (templ.Component, error) {
	if c.eng == nil {
		return components.EmptyState("alert-circle", "Engine not initialized", "The Shield engine is not available. Please check extension configuration."), nil
	}
	s := c.eng.Store()
	if s == nil {
		return components.EmptyState("database", "No store configured", "The Shield dashboard requires a database store. Please configure a Grove driver or provide a store via engine options."), nil
	}
	comp, err := c.renderPageRoute(ctx, route, s, params)
	if err != nil {
		return nil, err
	}
	pagesBase := params.BasePath + "/ext/" + c.manifest.Name + "/pages"
	return templ.ComponentFunc(func(tCtx context.Context, w io.Writer) error {
		return components.PathRewriter(pagesBase).Render(templ.WithChildren(tCtx, comp), w)
	}), nil
}

func (c *Contributor) renderPageRoute(ctx context.Context, pageRoute string, s store.Store, params contributor.Params) (templ.Component, error) {
	pageRoute = strings.TrimRight(pageRoute, "/")
	if pageRoute == "" {
		pageRoute = "/"
	}

	switch pageRoute {
	case "/":
		return c.renderOverview(ctx, s)
	// Instincts
	case "/instincts":
		return c.renderInstincts(ctx, s, params)
	case "/instincts/detail":
		return c.renderInstinctDetail(ctx, s, params)
	case "/instincts/create":
		return c.renderInstinctForm(ctx, s, params)
	case "/instincts/edit":
		return c.renderInstinctForm(ctx, s, params)
	// Awareness
	case "/awareness":
		return c.renderAwareness(ctx, s, params)
	case "/awareness/detail":
		return c.renderAwarenessDetail(ctx, s, params)
	case "/awareness/create":
		return c.renderAwarenessForm(ctx, s, params)
	case "/awareness/edit":
		return c.renderAwarenessForm(ctx, s, params)
	// Boundaries
	case "/boundaries":
		return c.renderBoundaries(ctx, s, params)
	case "/boundaries/detail":
		return c.renderBoundaryDetail(ctx, s, params)
	case "/boundaries/create":
		return c.renderBoundaryForm(ctx, s, params)
	case "/boundaries/edit":
		return c.renderBoundaryForm(ctx, s, params)
	// Values
	case "/values":
		return c.renderValues(ctx, s, params)
	case "/values/detail":
		return c.renderValueDetail(ctx, s, params)
	case "/values/create":
		return c.renderValueForm(ctx, s, params)
	case "/values/edit":
		return c.renderValueForm(ctx, s, params)
	// Judgments
	case "/judgments":
		return c.renderJudgments(ctx, s, params)
	case "/judgments/detail":
		return c.renderJudgmentDetail(ctx, s, params)
	case "/judgments/create":
		return c.renderJudgmentForm(ctx, s, params)
	case "/judgments/edit":
		return c.renderJudgmentForm(ctx, s, params)
	// Reflexes
	case "/reflexes":
		return c.renderReflexes(ctx, s, params)
	case "/reflexes/detail":
		return c.renderReflexDetail(ctx, s, params)
	case "/reflexes/create":
		return c.renderReflexForm(ctx, s, params)
	case "/reflexes/edit":
		return c.renderReflexForm(ctx, s, params)
	// Profiles
	case "/profiles":
		return c.renderProfiles(ctx, s, params)
	case "/profiles/detail":
		return c.renderProfileDetail(ctx, s, params)
	case "/profiles/create":
		return c.renderProfileForm(ctx, s, params)
	case "/profiles/edit":
		return c.renderProfileForm(ctx, s, params)
	// Scans
	case "/scans":
		return c.renderScans(ctx, s, params)
	case "/scans/detail":
		return c.renderScanDetail(ctx, s, params)
	// Policies
	case "/policies":
		return c.renderPolicies(ctx, s, params)
	case "/policies/detail":
		return c.renderPolicyDetail(ctx, s, params)
	case "/policies/create":
		return c.renderPolicyForm(ctx, s, params)
	case "/policies/edit":
		return c.renderPolicyForm(ctx, s, params)
	// PII Vault
	case "/pii":
		return c.renderPIIVault(ctx, s)
	// Compliance
	case "/compliance":
		return c.renderCompliance(ctx, s, params)
	default:
		return components.EmptyState("alert-circle", "Page not found", "The requested page does not exist."), nil
	}
}

// RenderWidget renders a widget by ID.
func (c *Contributor) RenderWidget(ctx context.Context, widgetID string) (templ.Component, error) {
	if c.eng == nil || c.eng.Store() == nil {
		return components.EmptyState("alert-circle", "Not available", "Engine or store not configured"), nil
	}
	s := c.eng.Store()

	switch widgetID {
	case "shield-scan-stats":
		stats := fetchScanStats(ctx, s, "")
		return widgets.ScanStatsWidget(stats.TotalScans, stats.BlockedCount, stats.FlaggedCount, stats.AllowedCount), nil
	case "shield-recent-scans":
		scans := fetchRecentScans(ctx, s, 5)
		return widgets.RecentScansWidget(scans), nil
	case "shield-pii-stats":
		stats := fetchPIIStats(ctx, s, "")
		return widgets.PIIStatsWidget(stats), nil
	case "shield-layer-summary":
		counts := fetchEntityCounts(ctx, s, "")
		return widgets.LayerSummaryWidget(counts.Instincts, counts.Awareness, counts.Boundaries, counts.Values, counts.Judgments, counts.Reflexes, counts.Profiles), nil
	default:
		return components.EmptyState("alert-circle", "Unknown widget", widgetID), nil
	}
}

// RenderSettings renders a settings panel by ID.
func (c *Contributor) RenderSettings(_ context.Context, settingID string) (templ.Component, error) {
	switch settingID {
	case "shield-config":
		return settings.EngineConfigPanel(c.eng), nil
	default:
		return components.EmptyState("alert-circle", "Unknown setting", settingID), nil
	}
}

// --- Page Render Methods ---

func (c *Contributor) renderOverview(ctx context.Context, s store.Store) (templ.Component, error) {
	counts := fetchEntityCounts(ctx, s, "")
	recent := fetchRecentScans(ctx, s, 10)
	stats := fetchScanStats(ctx, s, "")
	return pages.OverviewPage(counts, recent, stats), nil
}

func (c *Contributor) renderInstincts(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	category := instinct.Category(params.QueryParams["category"])
	limit := parseIntParam(params.QueryParams, "limit", 20)
	offset := parseIntParam(params.QueryParams, "offset", 0)
	items, total, err := fetchInstinctsPaginated(ctx, s, "", category, limit, offset)
	if err != nil {
		return nil, err
	}
	pg := NewPaginationMeta(total, limit, offset)
	return pages.InstinctsListPage(items, string(category), pg), nil
}

func (c *Contributor) renderInstinctDetail(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	name := params.QueryParams["name"]
	inst, err := s.GetInstinctByName(ctx, "", name)
	if err != nil {
		return components.EmptyState("alert-circle", "Instinct not found", name), nil
	}
	profiles := fetchAllProfiles(ctx, s)
	usage := countInstinctUsageInProfiles(profiles, inst.Name)
	return pages.InstinctDetailPage(inst, usage), nil
}

func (c *Contributor) renderInstinctForm(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	name := params.QueryParams["name"]
	if name != "" {
		inst, err := s.GetInstinctByName(ctx, "", name)
		if err != nil {
			return components.EmptyState("alert-circle", "Instinct not found", name), nil
		}
		return pages.InstinctFormPage(inst), nil
	}
	return pages.InstinctFormPage(nil), nil
}

func (c *Contributor) renderAwareness(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	focus := awareness.Focus(params.QueryParams["focus"])
	limit := parseIntParam(params.QueryParams, "limit", 20)
	offset := parseIntParam(params.QueryParams, "offset", 0)
	items, total, err := fetchAwarenessPaginated(ctx, s, "", focus, limit, offset)
	if err != nil {
		return nil, err
	}
	pg := NewPaginationMeta(total, limit, offset)
	return pages.AwarenessListPage(items, string(focus), pg), nil
}

func (c *Contributor) renderAwarenessDetail(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	name := params.QueryParams["name"]
	aw, err := s.GetAwarenessByName(ctx, "", name)
	if err != nil {
		return components.EmptyState("alert-circle", "Awareness not found", name), nil
	}
	profiles := fetchAllProfiles(ctx, s)
	usage := countAwarenessUsageInProfiles(profiles, aw.Name)
	return pages.AwarenessDetailPage(aw, usage), nil
}

func (c *Contributor) renderAwarenessForm(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	name := params.QueryParams["name"]
	if name != "" {
		aw, err := s.GetAwarenessByName(ctx, "", name)
		if err != nil {
			return components.EmptyState("alert-circle", "Awareness not found", name), nil
		}
		return pages.AwarenessFormPage(aw), nil
	}
	return pages.AwarenessFormPage(nil), nil
}

func (c *Contributor) renderBoundaries(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	scope := boundary.Scope(params.QueryParams["scope"])
	limit := parseIntParam(params.QueryParams, "limit", 20)
	offset := parseIntParam(params.QueryParams, "offset", 0)
	items, total, err := fetchBoundariesPaginated(ctx, s, "", scope, limit, offset)
	if err != nil {
		return nil, err
	}
	pg := NewPaginationMeta(total, limit, offset)
	return pages.BoundariesListPage(items, string(scope), pg), nil
}

func (c *Contributor) renderBoundaryDetail(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	name := params.QueryParams["name"]
	bnd, err := s.GetBoundaryByName(ctx, "", name)
	if err != nil {
		return components.EmptyState("alert-circle", "Boundary not found", name), nil
	}
	profiles := fetchAllProfiles(ctx, s)
	usage := countBoundaryUsageInProfiles(profiles, bnd.Name)
	return pages.BoundaryDetailPage(bnd, usage), nil
}

func (c *Contributor) renderBoundaryForm(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	name := params.QueryParams["name"]
	if name != "" {
		bnd, err := s.GetBoundaryByName(ctx, "", name)
		if err != nil {
			return components.EmptyState("alert-circle", "Boundary not found", name), nil
		}
		return pages.BoundaryFormPage(bnd), nil
	}
	return pages.BoundaryFormPage(nil), nil
}

func (c *Contributor) renderValues(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	limit := parseIntParam(params.QueryParams, "limit", 20)
	offset := parseIntParam(params.QueryParams, "offset", 0)
	items, total, err := fetchValuesPaginated(ctx, s, "", limit, offset)
	if err != nil {
		return nil, err
	}
	pg := NewPaginationMeta(total, limit, offset)
	return pages.ValuesListPage(items, pg), nil
}

func (c *Contributor) renderValueDetail(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	name := params.QueryParams["name"]
	val, err := s.GetValuesByName(ctx, "", name)
	if err != nil {
		return components.EmptyState("alert-circle", "Values not found", name), nil
	}
	profiles := fetchAllProfiles(ctx, s)
	usage := countValueUsageInProfiles(profiles, val.Name)
	return pages.ValueDetailPage(val, usage), nil
}

func (c *Contributor) renderValueForm(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	name := params.QueryParams["name"]
	if name != "" {
		val, err := s.GetValuesByName(ctx, "", name)
		if err != nil {
			return components.EmptyState("alert-circle", "Values not found", name), nil
		}
		return pages.ValueFormPage(val), nil
	}
	return pages.ValueFormPage(nil), nil
}

func (c *Contributor) renderJudgments(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	domain := judgment.Domain(params.QueryParams["domain"])
	limit := parseIntParam(params.QueryParams, "limit", 20)
	offset := parseIntParam(params.QueryParams, "offset", 0)
	items, total, err := fetchJudgmentsPaginated(ctx, s, "", domain, limit, offset)
	if err != nil {
		return nil, err
	}
	pg := NewPaginationMeta(total, limit, offset)
	return pages.JudgmentsListPage(items, string(domain), pg), nil
}

func (c *Contributor) renderJudgmentDetail(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	name := params.QueryParams["name"]
	jdg, err := s.GetJudgmentByName(ctx, "", name)
	if err != nil {
		return components.EmptyState("alert-circle", "Judgment not found", name), nil
	}
	profiles := fetchAllProfiles(ctx, s)
	usage := countJudgmentUsageInProfiles(profiles, jdg.Name)
	return pages.JudgmentDetailPage(jdg, usage), nil
}

func (c *Contributor) renderJudgmentForm(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	name := params.QueryParams["name"]
	if name != "" {
		jdg, err := s.GetJudgmentByName(ctx, "", name)
		if err != nil {
			return components.EmptyState("alert-circle", "Judgment not found", name), nil
		}
		return pages.JudgmentFormPage(jdg), nil
	}
	return pages.JudgmentFormPage(nil), nil
}

func (c *Contributor) renderReflexes(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	limit := parseIntParam(params.QueryParams, "limit", 20)
	offset := parseIntParam(params.QueryParams, "offset", 0)
	items, total, err := fetchReflexesPaginated(ctx, s, "", limit, offset)
	if err != nil {
		return nil, err
	}
	pg := NewPaginationMeta(total, limit, offset)
	return pages.ReflexesListPage(items, pg), nil
}

func (c *Contributor) renderReflexDetail(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	name := params.QueryParams["name"]
	rflx, err := s.GetReflexByName(ctx, "", name)
	if err != nil {
		return components.EmptyState("alert-circle", "Reflex not found", name), nil
	}
	profiles := fetchAllProfiles(ctx, s)
	usage := countReflexUsageInProfiles(profiles, rflx.Name)
	return pages.ReflexDetailPage(rflx, usage), nil
}

func (c *Contributor) renderReflexForm(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	name := params.QueryParams["name"]
	if name != "" {
		rflx, err := s.GetReflexByName(ctx, "", name)
		if err != nil {
			return components.EmptyState("alert-circle", "Reflex not found", name), nil
		}
		return pages.ReflexFormPage(rflx), nil
	}
	return pages.ReflexFormPage(nil), nil
}

func (c *Contributor) renderProfiles(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	limit := parseIntParam(params.QueryParams, "limit", 20)
	offset := parseIntParam(params.QueryParams, "offset", 0)
	items, total, err := fetchProfilesPaginated(ctx, s, "", limit, offset)
	if err != nil {
		return nil, err
	}
	pg := NewPaginationMeta(total, limit, offset)
	return pages.ProfilesListPage(items, pg), nil
}

func (c *Contributor) renderProfileDetail(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	name := params.QueryParams["name"]
	prof, err := s.GetProfileByName(ctx, "", name)
	if err != nil {
		return components.EmptyState("alert-circle", "Profile not found", name), nil
	}
	return pages.ProfileDetailPage(prof), nil
}

func (c *Contributor) renderProfileForm(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	name := params.QueryParams["name"]
	if name != "" {
		prof, err := s.GetProfileByName(ctx, "", name)
		if err != nil {
			return components.EmptyState("alert-circle", "Profile not found", name), nil
		}
		return pages.ProfileFormPage(prof), nil
	}
	return pages.ProfileFormPage(nil), nil
}

func (c *Contributor) renderScans(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	direction := scan.Direction(params.QueryParams["direction"])
	decision := scan.Decision(params.QueryParams["decision"])
	limit := parseIntParam(params.QueryParams, "limit", 20)
	offset := parseIntParam(params.QueryParams, "offset", 0)
	items, total, err := fetchScansPaginated(ctx, s, "", direction, decision, limit, offset)
	if err != nil {
		return nil, err
	}
	pg := NewPaginationMeta(total, limit, offset)
	return pages.ScansListPage(items, string(direction), string(decision), pg), nil
}

func (c *Contributor) renderScanDetail(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	idStr := params.QueryParams["id"]
	scanID, err := id.ParseScanID(idStr)
	if err != nil {
		return components.EmptyState("alert-circle", "Invalid scan ID", idStr), nil
	}
	result, err := s.GetScan(ctx, scanID)
	if err != nil {
		return components.EmptyState("alert-circle", "Scan not found", idStr), nil
	}
	piiTokens, err := s.LoadPIITokensByScan(ctx, scanID)
	if err != nil {
		piiTokens = nil
	}
	return pages.ScanDetailPage(result, piiTokens), nil
}

func (c *Contributor) renderPolicies(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	scopeLevel := policy.ScopeLevel(params.QueryParams["scope_level"])
	limit := parseIntParam(params.QueryParams, "limit", 20)
	offset := parseIntParam(params.QueryParams, "offset", 0)
	items, total, err := fetchPoliciesPaginated(ctx, s, "", scopeLevel, limit, offset)
	if err != nil {
		return nil, err
	}
	pg := NewPaginationMeta(total, limit, offset)
	return pages.PoliciesListPage(items, string(scopeLevel), pg), nil
}

func (c *Contributor) renderPolicyDetail(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	name := params.QueryParams["name"]
	pol, err := s.GetPolicyByName(ctx, "", name)
	if err != nil {
		return components.EmptyState("alert-circle", "Policy not found", name), nil
	}
	return pages.PolicyDetailPage(pol), nil
}

func (c *Contributor) renderPolicyForm(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	name := params.QueryParams["name"]
	if name != "" {
		pol, err := s.GetPolicyByName(ctx, "", name)
		if err != nil {
			return components.EmptyState("alert-circle", "Policy not found", name), nil
		}
		return pages.PolicyFormPage(pol), nil
	}
	return pages.PolicyFormPage(nil), nil
}

func (c *Contributor) renderPIIVault(ctx context.Context, s store.Store) (templ.Component, error) {
	stats := fetchPIIStats(ctx, s, "")
	return pages.PIIVaultPage(stats), nil
}

func (c *Contributor) renderCompliance(ctx context.Context, s store.Store, params contributor.Params) (templ.Component, error) {
	framework := compliance.Framework(params.QueryParams["framework"])
	limit := parseIntParam(params.QueryParams, "limit", 20)
	offset := parseIntParam(params.QueryParams, "offset", 0)
	items, total, err := fetchComplianceReportsPaginated(ctx, s, "", framework, limit, offset)
	if err != nil {
		return nil, err
	}
	pg := NewPaginationMeta(total, limit, offset)
	return pages.ComplianceListPage(items, string(framework), pg), nil
}
