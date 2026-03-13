package dashboard

import (
	"context"

	"github.com/a-h/templ"

	"github.com/xraph/forge/extensions/dashboard/contributor"

	"github.com/xraph/shield/id"
)

// Plugin is the base interface for Shield dashboard plugins.
// Implement any subset of methods to contribute widgets, settings, or pages.
type Plugin interface {
	DashboardWidgets(ctx context.Context) []PluginWidget
	DashboardSettingsPanel(ctx context.Context) templ.Component
	DashboardPages() []PluginPage
}

// PageContributor contributes navigation items and renders pages.
type PageContributor interface {
	DashboardNavItems() []contributor.NavItem
	DashboardRenderPage(ctx context.Context, route string, params contributor.Params) (templ.Component, error)
}

// ScanDetailContributor extends scan detail pages with additional sections.
type ScanDetailContributor interface {
	DashboardScanDetailSection(ctx context.Context, scanID id.ScanID) templ.Component
}

// ProfileDetailContributor extends profile detail pages with additional sections.
type ProfileDetailContributor interface {
	DashboardProfileDetailSection(ctx context.Context, profileID id.SafetyProfileID) templ.Component
}

// PluginWidget describes a widget contributed by a plugin.
type PluginWidget struct {
	ID         string
	Title      string
	Size       string
	RefreshSec int
	Render     func(ctx context.Context) templ.Component
}

// PluginPage describes a page contributed by a plugin.
type PluginPage struct {
	Label  string
	Route  string
	Icon   string
	Render func(ctx context.Context) templ.Component
}
