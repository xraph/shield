package scan

import (
	"context"

	"github.com/xraph/shield/id"
)

// StatsFilter defines filtering for scan statistics queries.
type StatsFilter struct {
	AppID    string
	TenantID string
	From     string // ISO 8601 date
	To       string // ISO 8601 date
}

// Stats holds aggregated scan statistics.
type Stats struct {
	TotalScans   int64            `json:"total_scans"`
	BlockedCount int64            `json:"blocked_count"`
	FlaggedCount int64            `json:"flagged_count"`
	AllowedCount int64            `json:"allowed_count"`
	ByDirection  map[string]int64 `json:"by_direction,omitempty"`
	ByDecision   map[string]int64 `json:"by_decision,omitempty"`
}

// ListFilter defines filtering for scan list queries.
type ListFilter struct {
	AppID     string
	TenantID  string
	Direction Direction
	Decision  Decision
	Limit     int
	Offset    int
}

// Store defines persistence operations for scan results.
type Store interface {
	CreateScan(ctx context.Context, result *Result) error
	GetScan(ctx context.Context, scanID id.ScanID) (*Result, error)
	ListScans(ctx context.Context, filter *ListFilter) ([]*Result, error)
	ScanStats(ctx context.Context, filter *StatsFilter) (*Stats, error)
}
