package postgres

import (
	"time"

	"github.com/xraph/grove"

	"github.com/xraph/shield"
	"github.com/xraph/shield/awareness"
	"github.com/xraph/shield/boundary"
	"github.com/xraph/shield/compliance"
	"github.com/xraph/shield/id"
	"github.com/xraph/shield/instinct"
	"github.com/xraph/shield/judgment"
	"github.com/xraph/shield/pii"
	"github.com/xraph/shield/policy"
	"github.com/xraph/shield/profile"
	"github.com/xraph/shield/reflex"
	"github.com/xraph/shield/scan"
	"github.com/xraph/shield/values"
)

// ──────────────────────────────────────────────────
// Instinct model
// ──────────────────────────────────────────────────

type instinctModel struct {
	grove.BaseModel `grove:"table:shield_instincts"`
	ID              string              `grove:"id,pk"`
	Name            string              `grove:"name,notnull"`
	Description     string              `grove:"description"`
	AppID           string              `grove:"app_id,notnull"`
	TenantID        string              `grove:"tenant_id"`
	Category        string              `grove:"category,notnull"`
	Strategies      []instinct.Strategy `grove:"strategies,type:jsonb"`
	Sensitivity     string              `grove:"sensitivity,notnull"`
	Action          string              `grove:"action,notnull"`
	Enabled         bool                `grove:"enabled,notnull"`
	Metadata        map[string]any      `grove:"metadata,type:jsonb"`
	CreatedAt       time.Time           `grove:"created_at,notnull"`
	UpdatedAt       time.Time           `grove:"updated_at,notnull"`
}

func instinctToModel(inst *instinct.Instinct) *instinctModel {
	return &instinctModel{
		ID:          inst.ID.String(),
		Name:        inst.Name,
		Description: inst.Description,
		AppID:       inst.AppID,
		TenantID:    inst.TenantID,
		Category:    string(inst.Category),
		Strategies:  inst.Strategies,
		Sensitivity: string(inst.Sensitivity),
		Action:      inst.Action,
		Enabled:     inst.Enabled,
		Metadata:    inst.Metadata,
		CreatedAt:   inst.CreatedAt,
		UpdatedAt:   inst.UpdatedAt,
	}
}

func instinctFromModel(m *instinctModel) *instinct.Instinct {
	iid, _ := id.ParseInstinctID(m.ID) //nolint:errcheck // stored IDs are always valid
	return &instinct.Instinct{
		Entity:      entityFromTimestamps(m.CreatedAt, m.UpdatedAt),
		ID:          iid,
		Name:        m.Name,
		Description: m.Description,
		AppID:       m.AppID,
		TenantID:    m.TenantID,
		Category:    instinct.Category(m.Category),
		Strategies:  m.Strategies,
		Sensitivity: instinct.Sensitivity(m.Sensitivity),
		Action:      m.Action,
		Enabled:     m.Enabled,
		Metadata:    m.Metadata,
	}
}

// ──────────────────────────────────────────────────
// Awareness model
// ──────────────────────────────────────────────────

type awarenessModel struct {
	grove.BaseModel `grove:"table:shield_awareness"`
	ID              string               `grove:"id,pk"`
	Name            string               `grove:"name,notnull"`
	Description     string               `grove:"description"`
	AppID           string               `grove:"app_id,notnull"`
	TenantID        string               `grove:"tenant_id"`
	Focus           string               `grove:"focus,notnull"`
	Detectors       []awareness.Detector `grove:"detectors,type:jsonb"`
	Action          string               `grove:"action,notnull"`
	Enabled         bool                 `grove:"enabled,notnull"`
	Metadata        map[string]any       `grove:"metadata,type:jsonb"`
	CreatedAt       time.Time            `grove:"created_at,notnull"`
	UpdatedAt       time.Time            `grove:"updated_at,notnull"`
}

func awarenessToModel(a *awareness.Awareness) *awarenessModel {
	return &awarenessModel{
		ID:          a.ID.String(),
		Name:        a.Name,
		Description: a.Description,
		AppID:       a.AppID,
		TenantID:    a.TenantID,
		Focus:       string(a.Focus),
		Detectors:   a.Detectors,
		Action:      a.Action,
		Enabled:     a.Enabled,
		Metadata:    a.Metadata,
		CreatedAt:   a.CreatedAt,
		UpdatedAt:   a.UpdatedAt,
	}
}

func awarenessFromModel(m *awarenessModel) *awareness.Awareness {
	aid, _ := id.ParseAwarenessID(m.ID) //nolint:errcheck // stored IDs are always valid
	return &awareness.Awareness{
		Entity:      entityFromTimestamps(m.CreatedAt, m.UpdatedAt),
		ID:          aid,
		Name:        m.Name,
		Description: m.Description,
		AppID:       m.AppID,
		TenantID:    m.TenantID,
		Focus:       awareness.Focus(m.Focus),
		Detectors:   m.Detectors,
		Action:      m.Action,
		Enabled:     m.Enabled,
		Metadata:    m.Metadata,
	}
}

// ──────────────────────────────────────────────────
// Boundary model
// ──────────────────────────────────────────────────

type boundaryModel struct {
	grove.BaseModel `grove:"table:shield_boundaries"`
	ID              string           `grove:"id,pk"`
	Name            string           `grove:"name,notnull"`
	Description     string           `grove:"description"`
	AppID           string           `grove:"app_id,notnull"`
	TenantID        string           `grove:"tenant_id"`
	Limits          []boundary.Limit `grove:"limits,type:jsonb"`
	Response        string           `grove:"response"`
	Enabled         bool             `grove:"enabled,notnull"`
	Metadata        map[string]any   `grove:"metadata,type:jsonb"`
	CreatedAt       time.Time        `grove:"created_at,notnull"`
	UpdatedAt       time.Time        `grove:"updated_at,notnull"`
}

func boundaryToModel(b *boundary.Boundary) *boundaryModel {
	return &boundaryModel{
		ID:          b.ID.String(),
		Name:        b.Name,
		Description: b.Description,
		AppID:       b.AppID,
		TenantID:    b.TenantID,
		Limits:      b.Limits,
		Response:    b.Response,
		Enabled:     b.Enabled,
		Metadata:    b.Metadata,
		CreatedAt:   b.CreatedAt,
		UpdatedAt:   b.UpdatedAt,
	}
}

func boundaryFromModel(m *boundaryModel) *boundary.Boundary {
	bid, _ := id.ParseBoundaryID(m.ID) //nolint:errcheck // stored IDs are always valid
	return &boundary.Boundary{
		Entity:      entityFromTimestamps(m.CreatedAt, m.UpdatedAt),
		ID:          bid,
		Name:        m.Name,
		Description: m.Description,
		AppID:       m.AppID,
		TenantID:    m.TenantID,
		Limits:      m.Limits,
		Response:    m.Response,
		Enabled:     m.Enabled,
		Metadata:    m.Metadata,
	}
}

// ──────────────────────────────────────────────────
// Values model
// ──────────────────────────────────────────────────

type valuesModel struct {
	grove.BaseModel `grove:"table:shield_values"`
	ID              string         `grove:"id,pk"`
	Name            string         `grove:"name,notnull"`
	Description     string         `grove:"description"`
	AppID           string         `grove:"app_id,notnull"`
	TenantID        string         `grove:"tenant_id"`
	Rules           []values.Rule  `grove:"rules,type:jsonb"`
	Severity        string         `grove:"severity"`
	Action          string         `grove:"action,notnull"`
	Enabled         bool           `grove:"enabled,notnull"`
	Metadata        map[string]any `grove:"metadata,type:jsonb"`
	CreatedAt       time.Time      `grove:"created_at,notnull"`
	UpdatedAt       time.Time      `grove:"updated_at,notnull"`
}

func valuesToModel(v *values.Values) *valuesModel {
	return &valuesModel{
		ID:          v.ID.String(),
		Name:        v.Name,
		Description: v.Description,
		AppID:       v.AppID,
		TenantID:    v.TenantID,
		Rules:       v.Rules,
		Severity:    v.Severity,
		Action:      v.Action,
		Enabled:     v.Enabled,
		Metadata:    v.Metadata,
		CreatedAt:   v.CreatedAt,
		UpdatedAt:   v.UpdatedAt,
	}
}

func valuesFromModel(m *valuesModel) *values.Values {
	vid, _ := id.ParseValueID(m.ID) //nolint:errcheck // stored IDs are always valid
	return &values.Values{
		Entity:      entityFromTimestamps(m.CreatedAt, m.UpdatedAt),
		ID:          vid,
		Name:        m.Name,
		Description: m.Description,
		AppID:       m.AppID,
		TenantID:    m.TenantID,
		Rules:       m.Rules,
		Severity:    m.Severity,
		Action:      m.Action,
		Enabled:     m.Enabled,
		Metadata:    m.Metadata,
	}
}

// ──────────────────────────────────────────────────
// Judgment model
// ──────────────────────────────────────────────────

type judgmentModel struct {
	grove.BaseModel `grove:"table:shield_judgments"`
	ID              string              `grove:"id,pk"`
	Name            string              `grove:"name,notnull"`
	Description     string              `grove:"description"`
	AppID           string              `grove:"app_id,notnull"`
	TenantID        string              `grove:"tenant_id"`
	Domain          string              `grove:"domain,notnull"`
	Assessors       []judgment.Assessor `grove:"assessors,type:jsonb"`
	Threshold       float64             `grove:"threshold"`
	Action          string              `grove:"action,notnull"`
	Enabled         bool                `grove:"enabled,notnull"`
	Metadata        map[string]any      `grove:"metadata,type:jsonb"`
	CreatedAt       time.Time           `grove:"created_at,notnull"`
	UpdatedAt       time.Time           `grove:"updated_at,notnull"`
}

func judgmentToModel(j *judgment.Judgment) *judgmentModel {
	return &judgmentModel{
		ID:          j.ID.String(),
		Name:        j.Name,
		Description: j.Description,
		AppID:       j.AppID,
		TenantID:    j.TenantID,
		Domain:      string(j.Domain),
		Assessors:   j.Assessors,
		Threshold:   j.Threshold,
		Action:      j.Action,
		Enabled:     j.Enabled,
		Metadata:    j.Metadata,
		CreatedAt:   j.CreatedAt,
		UpdatedAt:   j.UpdatedAt,
	}
}

func judgmentFromModel(m *judgmentModel) *judgment.Judgment {
	jid, _ := id.ParseJudgmentID(m.ID) //nolint:errcheck // stored IDs are always valid
	return &judgment.Judgment{
		Entity:      entityFromTimestamps(m.CreatedAt, m.UpdatedAt),
		ID:          jid,
		Name:        m.Name,
		Description: m.Description,
		AppID:       m.AppID,
		TenantID:    m.TenantID,
		Domain:      judgment.Domain(m.Domain),
		Assessors:   m.Assessors,
		Threshold:   m.Threshold,
		Action:      m.Action,
		Enabled:     m.Enabled,
		Metadata:    m.Metadata,
	}
}

// ──────────────────────────────────────────────────
// Reflex model
// ──────────────────────────────────────────────────

type reflexModel struct {
	grove.BaseModel `grove:"table:shield_reflexes"`
	ID              string           `grove:"id,pk"`
	Name            string           `grove:"name,notnull"`
	Description     string           `grove:"description"`
	AppID           string           `grove:"app_id,notnull"`
	TenantID        string           `grove:"tenant_id"`
	Triggers        []reflex.Trigger `grove:"triggers,type:jsonb"`
	Actions         []reflex.Action  `grove:"actions,type:jsonb"`
	Priority        int              `grove:"priority"`
	Enabled         bool             `grove:"enabled,notnull"`
	Metadata        map[string]any   `grove:"metadata,type:jsonb"`
	CreatedAt       time.Time        `grove:"created_at,notnull"`
	UpdatedAt       time.Time        `grove:"updated_at,notnull"`
}

func reflexToModel(r *reflex.Reflex) *reflexModel {
	return &reflexModel{
		ID:          r.ID.String(),
		Name:        r.Name,
		Description: r.Description,
		AppID:       r.AppID,
		TenantID:    r.TenantID,
		Triggers:    r.Triggers,
		Actions:     r.Actions,
		Priority:    r.Priority,
		Enabled:     r.Enabled,
		Metadata:    r.Metadata,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}

func reflexFromModel(m *reflexModel) *reflex.Reflex {
	rid, _ := id.ParseReflexID(m.ID) //nolint:errcheck // stored IDs are always valid
	return &reflex.Reflex{
		Entity:      entityFromTimestamps(m.CreatedAt, m.UpdatedAt),
		ID:          rid,
		Name:        m.Name,
		Description: m.Description,
		AppID:       m.AppID,
		TenantID:    m.TenantID,
		Triggers:    m.Triggers,
		Actions:     m.Actions,
		Priority:    m.Priority,
		Enabled:     m.Enabled,
		Metadata:    m.Metadata,
	}
}

// ──────────────────────────────────────────────────
// Profile model
// ──────────────────────────────────────────────────

type profileModel struct {
	grove.BaseModel `grove:"table:shield_profiles"`
	ID              string                        `grove:"id,pk"`
	Name            string                        `grove:"name,notnull"`
	Description     string                        `grove:"description"`
	AppID           string                        `grove:"app_id,notnull"`
	TenantID        string                        `grove:"tenant_id"`
	Instincts       []profile.InstinctAssignment  `grove:"instincts,type:jsonb"`
	Judgments       []profile.JudgmentAssignment  `grove:"judgments,type:jsonb"`
	Awareness       []profile.AwarenessAssignment `grove:"awareness,type:jsonb"`
	Values          []string                      `grove:"values,type:jsonb"`
	Reflexes        []string                      `grove:"reflexes,type:jsonb"`
	Boundaries      []string                      `grove:"boundaries,type:jsonb"`
	Enabled         bool                          `grove:"enabled,notnull"`
	Metadata        map[string]any                `grove:"metadata,type:jsonb"`
	CreatedAt       time.Time                     `grove:"created_at,notnull"`
	UpdatedAt       time.Time                     `grove:"updated_at,notnull"`
}

func profileToModel(p *profile.SafetyProfile) *profileModel {
	return &profileModel{
		ID:          p.ID.String(),
		Name:        p.Name,
		Description: p.Description,
		AppID:       p.AppID,
		TenantID:    p.TenantID,
		Instincts:   p.Instincts,
		Judgments:   p.Judgments,
		Awareness:   p.Awareness,
		Values:      p.Values,
		Reflexes:    p.Reflexes,
		Boundaries:  p.Boundaries,
		Enabled:     p.Enabled,
		Metadata:    p.Metadata,
		CreatedAt:   p.CreatedAt,
		UpdatedAt:   p.UpdatedAt,
	}
}

func profileFromModel(m *profileModel) *profile.SafetyProfile {
	pid, _ := id.ParseSafetyProfileID(m.ID) //nolint:errcheck // stored IDs are always valid
	return &profile.SafetyProfile{
		Entity:      entityFromTimestamps(m.CreatedAt, m.UpdatedAt),
		ID:          pid,
		Name:        m.Name,
		Description: m.Description,
		AppID:       m.AppID,
		TenantID:    m.TenantID,
		Instincts:   m.Instincts,
		Judgments:   m.Judgments,
		Awareness:   m.Awareness,
		Values:      m.Values,
		Reflexes:    m.Reflexes,
		Boundaries:  m.Boundaries,
		Enabled:     m.Enabled,
		Metadata:    m.Metadata,
	}
}

// ──────────────────────────────────────────────────
// Scan model
// ──────────────────────────────────────────────────

type scanModel struct {
	grove.BaseModel `grove:"table:shield_scans"`
	ID              string          `grove:"id,pk"`
	Direction       string          `grove:"direction,notnull"`
	Decision        string          `grove:"decision,notnull"`
	Blocked         bool            `grove:"blocked,notnull"`
	Findings        []*scan.Finding `grove:"findings,type:jsonb"`
	Redacted        string          `grove:"redacted"`
	PIICount        int             `grove:"pii_count"`
	ProfileUsed     string          `grove:"profile_used"`
	PoliciesUsed    []string        `grove:"policies_used,type:jsonb"`
	TenantID        string          `grove:"tenant_id,notnull"`
	AppID           string          `grove:"app_id,notnull"`
	Duration        int64           `grove:"duration"`
	Metadata        map[string]any  `grove:"metadata,type:jsonb"`
	CreatedAt       time.Time       `grove:"created_at,notnull"`
	UpdatedAt       time.Time       `grove:"updated_at,notnull"`
}

func scanToModel(r *scan.Result) *scanModel {
	return &scanModel{
		ID:           r.ID.String(),
		Direction:    string(r.Direction),
		Decision:     string(r.Decision),
		Blocked:      r.Blocked,
		Findings:     r.Findings,
		Redacted:     r.Redacted,
		PIICount:     r.PIICount,
		ProfileUsed:  r.ProfileUsed,
		PoliciesUsed: r.PoliciesUsed,
		TenantID:     r.TenantID,
		AppID:        r.AppID,
		Duration:     int64(r.Duration),
		Metadata:     r.Metadata,
		CreatedAt:    r.CreatedAt,
		UpdatedAt:    r.UpdatedAt,
	}
}

func scanFromModel(m *scanModel) *scan.Result {
	sid, _ := id.ParseScanID(m.ID) //nolint:errcheck // stored IDs are always valid
	return &scan.Result{
		Entity:       entityFromTimestamps(m.CreatedAt, m.UpdatedAt),
		ID:           sid,
		Direction:    scan.Direction(m.Direction),
		Decision:     scan.Decision(m.Decision),
		Blocked:      m.Blocked,
		Findings:     m.Findings,
		Redacted:     m.Redacted,
		PIICount:     m.PIICount,
		ProfileUsed:  m.ProfileUsed,
		PoliciesUsed: m.PoliciesUsed,
		TenantID:     m.TenantID,
		AppID:        m.AppID,
		Duration:     time.Duration(m.Duration),
		Metadata:     m.Metadata,
	}
}

// ──────────────────────────────────────────────────
// Policy model
// ──────────────────────────────────────────────────

type policyModel struct {
	grove.BaseModel `grove:"table:shield_policies"`
	ID              string         `grove:"id,pk"`
	Name            string         `grove:"name,notnull"`
	Description     string         `grove:"description"`
	ScopeKey        string         `grove:"scope_key,notnull"`
	ScopeLevel      string         `grove:"scope_level,notnull"`
	Rules           []policy.Rule  `grove:"rules,type:jsonb"`
	Enabled         bool           `grove:"enabled,notnull"`
	Metadata        map[string]any `grove:"metadata,type:jsonb"`
	CreatedAt       time.Time      `grove:"created_at,notnull"`
	UpdatedAt       time.Time      `grove:"updated_at,notnull"`
}

func policyToModel(pol *policy.Policy) *policyModel {
	return &policyModel{
		ID:          pol.ID.String(),
		Name:        pol.Name,
		Description: pol.Description,
		ScopeKey:    pol.ScopeKey,
		ScopeLevel:  string(pol.ScopeLevel),
		Rules:       pol.Rules,
		Enabled:     pol.Enabled,
		Metadata:    pol.Metadata,
		CreatedAt:   pol.CreatedAt,
		UpdatedAt:   pol.UpdatedAt,
	}
}

func policyFromModel(m *policyModel) *policy.Policy {
	pid, _ := id.ParsePolicyID(m.ID) //nolint:errcheck // stored IDs are always valid
	return &policy.Policy{
		Entity:      entityFromTimestamps(m.CreatedAt, m.UpdatedAt),
		ID:          pid,
		Name:        m.Name,
		Description: m.Description,
		ScopeKey:    m.ScopeKey,
		ScopeLevel:  policy.ScopeLevel(m.ScopeLevel),
		Rules:       m.Rules,
		Enabled:     m.Enabled,
		Metadata:    m.Metadata,
	}
}

// ──────────────────────────────────────────────────
// Policy tenant join model
// ──────────────────────────────────────────────────

type policyTenantModel struct {
	grove.BaseModel `grove:"table:shield_policy_tenants"`
	TenantID        string    `grove:"tenant_id,pk"`
	PolicyID        string    `grove:"policy_id,pk"`
	CreatedAt       time.Time `grove:"created_at,notnull"`
}

// ──────────────────────────────────────────────────
// PII Token model
// ──────────────────────────────────────────────────

type piiTokenModel struct {
	grove.BaseModel `grove:"table:shield_pii_tokens"`
	ID              string     `grove:"id,pk"`
	ScanID          string     `grove:"scan_id,notnull"`
	TenantID        string     `grove:"tenant_id,notnull"`
	PIIType         string     `grove:"pii_type,notnull"`
	Placeholder     string     `grove:"placeholder,notnull"`
	EncryptedValue  []byte     `grove:"encrypted_value,notnull"`
	ExpiresAt       *time.Time `grove:"expires_at"`
	CreatedAt       time.Time  `grove:"created_at,notnull"`
	UpdatedAt       time.Time  `grove:"updated_at,notnull"`
}

func piiTokenToModel(t *pii.Token) *piiTokenModel {
	return &piiTokenModel{
		ID:             t.ID.String(),
		ScanID:         t.ScanID.String(),
		TenantID:       t.TenantID,
		PIIType:        t.PIIType,
		Placeholder:    t.Placeholder,
		EncryptedValue: t.EncryptedValue,
		ExpiresAt:      t.ExpiresAt,
		CreatedAt:      t.CreatedAt,
		UpdatedAt:      t.UpdatedAt,
	}
}

func piiTokenFromModel(m *piiTokenModel) *pii.Token {
	tid, _ := id.ParsePIITokenID(m.ID) //nolint:errcheck // stored IDs are always valid
	sid, _ := id.ParseScanID(m.ScanID) //nolint:errcheck // stored IDs are always valid
	return &pii.Token{
		Entity:         entityFromTimestamps(m.CreatedAt, m.UpdatedAt),
		ID:             tid,
		ScanID:         sid,
		TenantID:       m.TenantID,
		PIIType:        m.PIIType,
		Placeholder:    m.Placeholder,
		EncryptedValue: m.EncryptedValue,
		ExpiresAt:      m.ExpiresAt,
	}
}

// ──────────────────────────────────────────────────
// Compliance report model
// ──────────────────────────────────────────────────

type complianceReportModel struct {
	grove.BaseModel `grove:"table:shield_compliance_reports"`
	ID              string         `grove:"id,pk"`
	Framework       string         `grove:"framework,notnull"`
	ScopeKey        string         `grove:"scope_key,notnull"`
	ScopeLevel      string         `grove:"scope_level,notnull"`
	PeriodStart     time.Time      `grove:"period_start,notnull"`
	PeriodEnd       time.Time      `grove:"period_end,notnull"`
	Summary         map[string]any `grove:"summary,type:jsonb"`
	Details         map[string]any `grove:"details,type:jsonb"`
	GeneratedAt     time.Time      `grove:"generated_at,notnull"`
	CreatedAt       time.Time      `grove:"created_at,notnull"`
	UpdatedAt       time.Time      `grove:"updated_at,notnull"`
}

func complianceToModel(r *compliance.Report) *complianceReportModel {
	return &complianceReportModel{
		ID:          r.ID.String(),
		Framework:   string(r.Framework),
		ScopeKey:    r.ScopeKey,
		ScopeLevel:  r.ScopeLevel,
		PeriodStart: r.PeriodStart,
		PeriodEnd:   r.PeriodEnd,
		Summary:     r.Summary,
		Details:     r.Details,
		GeneratedAt: r.GeneratedAt,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}

func complianceFromModel(m *complianceReportModel) *compliance.Report {
	cid, _ := id.ParseComplianceReportID(m.ID) //nolint:errcheck // stored IDs are always valid
	return &compliance.Report{
		Entity:      entityFromTimestamps(m.CreatedAt, m.UpdatedAt),
		ID:          cid,
		Framework:   compliance.Framework(m.Framework),
		ScopeKey:    m.ScopeKey,
		ScopeLevel:  m.ScopeLevel,
		PeriodStart: m.PeriodStart,
		PeriodEnd:   m.PeriodEnd,
		Summary:     m.Summary,
		Details:     m.Details,
		GeneratedAt: m.GeneratedAt,
	}
}

// ──────────────────────────────────────────────────
// Helper
// ──────────────────────────────────────────────────

func entityFromTimestamps(createdAt, updatedAt time.Time) shield.Entity {
	return shield.Entity{CreatedAt: createdAt, UpdatedAt: updatedAt}
}
