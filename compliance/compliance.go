// Package compliance provides compliance reporting for regulatory frameworks.
package compliance

import (
	"context"
	"time"

	"github.com/xraph/shield"
	"github.com/xraph/shield/id"
)

// Framework identifies a compliance framework.
type Framework string

const (
	FrameworkEUAIAct Framework = "eu_ai_act"
	FrameworkNIST    Framework = "nist_ai_rmf"
	FrameworkSOC2    Framework = "soc2"
)

// Report represents a generated compliance report.
type Report struct {
	shield.Entity
	ID          id.ComplianceReportID `json:"id" bun:",pk"`
	Framework   Framework             `json:"framework" bun:",notnull"`
	ScopeKey    string                `json:"scope_key" bun:",notnull"`
	ScopeLevel  string                `json:"scope_level" bun:",notnull"`
	PeriodStart time.Time             `json:"period_start" bun:",notnull"`
	PeriodEnd   time.Time             `json:"period_end" bun:",notnull"`
	Summary     map[string]any        `json:"summary" bun:"type:jsonb"`
	Details     map[string]any        `json:"details" bun:"type:jsonb"`
	GeneratedAt time.Time             `json:"generated_at" bun:",notnull"`
}

// ListFilter defines filtering for compliance report list queries.
type ListFilter struct {
	ScopeKey  string
	Framework Framework
	Limit     int
	Offset    int
}

// Store defines persistence operations for compliance reports.
type Store interface {
	CreateReport(ctx context.Context, report *Report) error
	GetReport(ctx context.Context, reportID id.ComplianceReportID) (*Report, error)
	ListReports(ctx context.Context, filter *ListFilter) ([]*Report, error)
}
