package dashboard

import (
	"github.com/xraph/forge/extensions/dashboard/contributor"

	"github.com/xraph/shield/dashboard/components"
)

// NewManifest builds a contributor.Manifest for the shield dashboard.
func NewManifest() *contributor.Manifest {
	return &contributor.Manifest{
		Name:        "shield",
		DisplayName: "Shield",
		Icon:        "shield-check",
		Version:     "0.1.0",
		Layout:      "extension",
		ShowSidebar: boolPtr(true),
		TopbarConfig: &contributor.TopbarConfig{
			Title:       "Shield",
			LogoIcon:    "shield-check",
			AccentColor: "#ef4444",
			ShowSearch:  true,
			Actions: []contributor.TopbarAction{
				{Label: "API Docs", Icon: "file-text", Href: "/docs", Variant: "ghost"},
			},
		},
		SidebarFooterContent: components.FooterAPIDocsLink("/docs"),
		Nav:                  baseNav(),
		Widgets:              baseWidgets(),
		Settings:             baseSettings(),
		Capabilities: []string{
			"searchable",
		},
	}
}

func baseNav() []contributor.NavItem {
	return []contributor.NavItem{
		{Label: "Overview", Path: "/", Icon: "layout-dashboard", Group: "Shield", Priority: 0},
		{Label: "Instincts", Path: "/instincts", Icon: "zap", Group: "Cognition", Priority: 1},
		{Label: "Awareness", Path: "/awareness", Icon: "eye", Group: "Cognition", Priority: 2},
		{Label: "Boundaries", Path: "/boundaries", Icon: "shield-off", Group: "Cognition", Priority: 3},
		{Label: "Values", Path: "/values", Icon: "heart", Group: "Cognition", Priority: 4},
		{Label: "Judgments", Path: "/judgments", Icon: "scale", Group: "Cognition", Priority: 5},
		{Label: "Reflexes", Path: "/reflexes", Icon: "activity", Group: "Cognition", Priority: 6},
		{Label: "Profiles", Path: "/profiles", Icon: "user-check", Group: "Composition", Priority: 7},
		{Label: "Scans", Path: "/scans", Icon: "scan-line", Group: "Operations", Priority: 8},
		{Label: "Policies", Path: "/policies", Icon: "gavel", Group: "Governance", Priority: 9},
		{Label: "PII Vault", Path: "/pii", Icon: "lock", Group: "Privacy", Priority: 10},
		{Label: "Compliance", Path: "/compliance", Icon: "file-check", Group: "Governance", Priority: 11},
	}
}

func baseWidgets() []contributor.WidgetDescriptor {
	return []contributor.WidgetDescriptor{
		{
			ID:          "shield-scan-stats",
			Title:       "Scan Stats",
			Description: "Safety scan statistics",
			Size:        "md",
			RefreshSec:  30,
			Group:       "Shield",
		},
		{
			ID:          "shield-recent-scans",
			Title:       "Recent Scans",
			Description: "Recent safety scan results",
			Size:        "lg",
			RefreshSec:  15,
			Group:       "Shield",
		},
		{
			ID:          "shield-pii-stats",
			Title:       "PII Detections",
			Description: "PII detection breakdown by type",
			Size:        "md",
			RefreshSec:  60,
			Group:       "Shield",
		},
		{
			ID:          "shield-layer-summary",
			Title:       "Layer Summary",
			Description: "Counts per safety layer",
			Size:        "md",
			RefreshSec:  60,
			Group:       "Shield",
		},
	}
}

func baseSettings() []contributor.SettingsDescriptor {
	return []contributor.SettingsDescriptor{
		{
			ID:          "shield-config",
			Title:       "Engine Settings",
			Description: "Configure Shield engine behavior",
			Group:       "Shield",
			Icon:        "shield-check",
		},
	}
}

func boolPtr(b bool) *bool { return &b }
