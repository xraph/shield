package mongo

import (
	"fmt"
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
	ID              string              `grove:"id,pk"        bson:"_id"`
	Name            string              `grove:"name"         bson:"name"`
	Description     string              `grove:"description"  bson:"description"`
	AppID           string              `grove:"app_id"       bson:"app_id"`
	TenantID        string              `grove:"tenant_id"    bson:"tenant_id"`
	Category        string              `grove:"category"     bson:"category"`
	Strategies      []instinct.Strategy `grove:"strategies"   bson:"strategies,omitempty"`
	Sensitivity     string              `grove:"sensitivity"  bson:"sensitivity"`
	Action          string              `grove:"action"       bson:"action"`
	Enabled         bool                `grove:"enabled"      bson:"enabled"`
	Metadata        map[string]any      `grove:"metadata"     bson:"metadata,omitempty"`
	CreatedAt       time.Time           `grove:"created_at"   bson:"created_at"`
	UpdatedAt       time.Time           `grove:"updated_at"   bson:"updated_at"`
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

func instinctFromModel(m *instinctModel) (*instinct.Instinct, error) {
	iid, err := id.ParseInstinctID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("parse instinct ID %q: %w", m.ID, err)
	}
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
	}, nil
}

// ──────────────────────────────────────────────────
// Awareness model
// ──────────────────────────────────────────────────

type awarenessModel struct {
	grove.BaseModel `grove:"table:shield_awareness"`
	ID              string               `grove:"id,pk"        bson:"_id"`
	Name            string               `grove:"name"         bson:"name"`
	Description     string               `grove:"description"  bson:"description"`
	AppID           string               `grove:"app_id"       bson:"app_id"`
	TenantID        string               `grove:"tenant_id"    bson:"tenant_id"`
	Focus           string               `grove:"focus"        bson:"focus"`
	Detectors       []awareness.Detector `grove:"detectors"    bson:"detectors,omitempty"`
	Action          string               `grove:"action"       bson:"action"`
	Enabled         bool                 `grove:"enabled"      bson:"enabled"`
	Metadata        map[string]any       `grove:"metadata"     bson:"metadata,omitempty"`
	CreatedAt       time.Time            `grove:"created_at"   bson:"created_at"`
	UpdatedAt       time.Time            `grove:"updated_at"   bson:"updated_at"`
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

func awarenessFromModel(m *awarenessModel) (*awareness.Awareness, error) {
	aid, err := id.ParseAwarenessID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("parse awareness ID %q: %w", m.ID, err)
	}
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
	}, nil
}

// ──────────────────────────────────────────────────
// Boundary model
// ──────────────────────────────────────────────────

type boundaryModel struct {
	grove.BaseModel `grove:"table:shield_boundaries"`
	ID              string           `grove:"id,pk"        bson:"_id"`
	Name            string           `grove:"name"         bson:"name"`
	Description     string           `grove:"description"  bson:"description"`
	AppID           string           `grove:"app_id"       bson:"app_id"`
	TenantID        string           `grove:"tenant_id"    bson:"tenant_id"`
	Limits          []boundary.Limit `grove:"limits"       bson:"limits,omitempty"`
	Response        string           `grove:"response"     bson:"response"`
	Enabled         bool             `grove:"enabled"      bson:"enabled"`
	Metadata        map[string]any   `grove:"metadata"     bson:"metadata,omitempty"`
	CreatedAt       time.Time        `grove:"created_at"   bson:"created_at"`
	UpdatedAt       time.Time        `grove:"updated_at"   bson:"updated_at"`
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

func boundaryFromModel(m *boundaryModel) (*boundary.Boundary, error) {
	bid, err := id.ParseBoundaryID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("parse boundary ID %q: %w", m.ID, err)
	}
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
	}, nil
}

// ──────────────────────────────────────────────────
// Values model
// ──────────────────────────────────────────────────

type valuesModel struct {
	grove.BaseModel `grove:"table:shield_values"`
	ID              string         `grove:"id,pk"        bson:"_id"`
	Name            string         `grove:"name"         bson:"name"`
	Description     string         `grove:"description"  bson:"description"`
	AppID           string         `grove:"app_id"       bson:"app_id"`
	TenantID        string         `grove:"tenant_id"    bson:"tenant_id"`
	Rules           []values.Rule  `grove:"rules"        bson:"rules,omitempty"`
	Severity        string         `grove:"severity"     bson:"severity"`
	Action          string         `grove:"action"       bson:"action"`
	Enabled         bool           `grove:"enabled"      bson:"enabled"`
	Metadata        map[string]any `grove:"metadata"     bson:"metadata,omitempty"`
	CreatedAt       time.Time      `grove:"created_at"   bson:"created_at"`
	UpdatedAt       time.Time      `grove:"updated_at"   bson:"updated_at"`
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

func valuesFromModel(m *valuesModel) (*values.Values, error) {
	vid, err := id.ParseValueID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("parse value ID %q: %w", m.ID, err)
	}
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
	}, nil
}

// ──────────────────────────────────────────────────
// Judgment model
// ──────────────────────────────────────────────────

type judgmentModel struct {
	grove.BaseModel `grove:"table:shield_judgments"`
	ID              string              `grove:"id,pk"        bson:"_id"`
	Name            string              `grove:"name"         bson:"name"`
	Description     string              `grove:"description"  bson:"description"`
	AppID           string              `grove:"app_id"       bson:"app_id"`
	TenantID        string              `grove:"tenant_id"    bson:"tenant_id"`
	Domain          string              `grove:"domain"       bson:"domain"`
	Assessors       []judgment.Assessor `grove:"assessors"    bson:"assessors,omitempty"`
	Threshold       float64             `grove:"threshold"    bson:"threshold"`
	Action          string              `grove:"action"       bson:"action"`
	Enabled         bool                `grove:"enabled"      bson:"enabled"`
	Metadata        map[string]any      `grove:"metadata"     bson:"metadata,omitempty"`
	CreatedAt       time.Time           `grove:"created_at"   bson:"created_at"`
	UpdatedAt       time.Time           `grove:"updated_at"   bson:"updated_at"`
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

func judgmentFromModel(m *judgmentModel) (*judgment.Judgment, error) {
	jid, err := id.ParseJudgmentID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("parse judgment ID %q: %w", m.ID, err)
	}
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
	}, nil
}

// ──────────────────────────────────────────────────
// Reflex model
// ──────────────────────────────────────────────────

type reflexModel struct {
	grove.BaseModel `grove:"table:shield_reflexes"`
	ID              string           `grove:"id,pk"        bson:"_id"`
	Name            string           `grove:"name"         bson:"name"`
	Description     string           `grove:"description"  bson:"description"`
	AppID           string           `grove:"app_id"       bson:"app_id"`
	TenantID        string           `grove:"tenant_id"    bson:"tenant_id"`
	Triggers        []reflex.Trigger `grove:"triggers"     bson:"triggers,omitempty"`
	Actions         []reflex.Action  `grove:"actions"      bson:"actions,omitempty"`
	Priority        int              `grove:"priority"     bson:"priority"`
	Enabled         bool             `grove:"enabled"      bson:"enabled"`
	Metadata        map[string]any   `grove:"metadata"     bson:"metadata,omitempty"`
	CreatedAt       time.Time        `grove:"created_at"   bson:"created_at"`
	UpdatedAt       time.Time        `grove:"updated_at"   bson:"updated_at"`
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

func reflexFromModel(m *reflexModel) (*reflex.Reflex, error) {
	rid, err := id.ParseReflexID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("parse reflex ID %q: %w", m.ID, err)
	}
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
	}, nil
}

// ──────────────────────────────────────────────────
// Profile model
// ──────────────────────────────────────────────────

type profileModel struct {
	grove.BaseModel `grove:"table:shield_profiles"`
	ID              string                        `grove:"id,pk"        bson:"_id"`
	Name            string                        `grove:"name"         bson:"name"`
	Description     string                        `grove:"description"  bson:"description"`
	AppID           string                        `grove:"app_id"       bson:"app_id"`
	TenantID        string                        `grove:"tenant_id"    bson:"tenant_id"`
	Instincts       []profile.InstinctAssignment  `grove:"instincts"    bson:"instincts,omitempty"`
	Judgments       []profile.JudgmentAssignment  `grove:"judgments"    bson:"judgments,omitempty"`
	Awareness       []profile.AwarenessAssignment `grove:"awareness"    bson:"awareness,omitempty"`
	Values          []string                      `grove:"values"       bson:"values,omitempty"`
	Reflexes        []string                      `grove:"reflexes"     bson:"reflexes,omitempty"`
	Boundaries      []string                      `grove:"boundaries"   bson:"boundaries,omitempty"`
	Enabled         bool                          `grove:"enabled"      bson:"enabled"`
	Metadata        map[string]any                `grove:"metadata"     bson:"metadata,omitempty"`
	CreatedAt       time.Time                     `grove:"created_at"   bson:"created_at"`
	UpdatedAt       time.Time                     `grove:"updated_at"   bson:"updated_at"`
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

func profileFromModel(m *profileModel) (*profile.SafetyProfile, error) {
	pid, err := id.ParseSafetyProfileID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("parse profile ID %q: %w", m.ID, err)
	}
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
	}, nil
}

// ──────────────────────────────────────────────────
// Scan model
// ──────────────────────────────────────────────────

type scanResultModel struct {
	grove.BaseModel `grove:"table:shield_scans"`
	ID              string          `grove:"id,pk"          bson:"_id"`
	Direction       string          `grove:"direction"      bson:"direction"`
	Decision        string          `grove:"decision"       bson:"decision"`
	Blocked         bool            `grove:"blocked"        bson:"blocked"`
	Findings        []*scan.Finding `grove:"findings"       bson:"findings,omitempty"`
	Redacted        string          `grove:"redacted"       bson:"redacted"`
	PIICount        int             `grove:"pii_count"      bson:"pii_count"`
	ProfileUsed     string          `grove:"profile_used"   bson:"profile_used"`
	PoliciesUsed    []string        `grove:"policies_used"  bson:"policies_used,omitempty"`
	TenantID        string          `grove:"tenant_id"      bson:"tenant_id"`
	AppID           string          `grove:"app_id"         bson:"app_id"`
	Duration        int64           `grove:"duration"       bson:"duration"`
	Metadata        map[string]any  `grove:"metadata"       bson:"metadata,omitempty"`
	CreatedAt       time.Time       `grove:"created_at"     bson:"created_at"`
	UpdatedAt       time.Time       `grove:"updated_at"     bson:"updated_at"`
}

func scanToModel(r *scan.Result) *scanResultModel {
	return &scanResultModel{
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

func scanFromModel(m *scanResultModel) (*scan.Result, error) {
	sid, err := id.ParseScanID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("parse scan ID %q: %w", m.ID, err)
	}
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
	}, nil
}

// ──────────────────────────────────────────────────
// Policy model
// ──────────────────────────────────────────────────

type policyModel struct {
	grove.BaseModel `grove:"table:shield_policies"`
	ID              string         `grove:"id,pk"         bson:"_id"`
	Name            string         `grove:"name"          bson:"name"`
	Description     string         `grove:"description"   bson:"description"`
	ScopeKey        string         `grove:"scope_key"     bson:"scope_key"`
	ScopeLevel      string         `grove:"scope_level"   bson:"scope_level"`
	Rules           []policy.Rule  `grove:"rules"         bson:"rules,omitempty"`
	Enabled         bool           `grove:"enabled"       bson:"enabled"`
	TenantIDs       []string       `grove:"-"             bson:"tenant_ids,omitempty"`
	Metadata        map[string]any `grove:"metadata"      bson:"metadata,omitempty"`
	CreatedAt       time.Time      `grove:"created_at"    bson:"created_at"`
	UpdatedAt       time.Time      `grove:"updated_at"    bson:"updated_at"`
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

func policyFromModel(m *policyModel) (*policy.Policy, error) {
	pid, err := id.ParsePolicyID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("parse policy ID %q: %w", m.ID, err)
	}
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
	}, nil
}

// ──────────────────────────────────────────────────
// PII Token model
// ──────────────────────────────────────────────────

type piiTokenModel struct {
	grove.BaseModel `grove:"table:shield_pii_tokens"`
	ID              string     `grove:"id,pk"            bson:"_id"`
	ScanID          string     `grove:"scan_id"          bson:"scan_id"`
	TenantID        string     `grove:"tenant_id"        bson:"tenant_id"`
	PIIType         string     `grove:"pii_type"         bson:"pii_type"`
	Placeholder     string     `grove:"placeholder"      bson:"placeholder"`
	EncryptedValue  []byte     `grove:"encrypted_value"  bson:"encrypted_value"`
	ExpiresAt       *time.Time `grove:"expires_at"       bson:"expires_at,omitempty"`
	CreatedAt       time.Time  `grove:"created_at"       bson:"created_at"`
	UpdatedAt       time.Time  `grove:"updated_at"       bson:"updated_at"`
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

func piiTokenFromModel(m *piiTokenModel) (*pii.Token, error) {
	tid, err := id.ParsePIITokenID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("parse pii token ID %q: %w", m.ID, err)
	}
	sid, err := id.ParseScanID(m.ScanID)
	if err != nil {
		return nil, fmt.Errorf("parse scan ID %q: %w", m.ScanID, err)
	}
	return &pii.Token{
		Entity:         entityFromTimestamps(m.CreatedAt, m.UpdatedAt),
		ID:             tid,
		ScanID:         sid,
		TenantID:       m.TenantID,
		PIIType:        m.PIIType,
		Placeholder:    m.Placeholder,
		EncryptedValue: m.EncryptedValue,
		ExpiresAt:      m.ExpiresAt,
	}, nil
}

// ──────────────────────────────────────────────────
// Compliance report model
// ──────────────────────────────────────────────────

type complianceReportModel struct {
	grove.BaseModel `grove:"table:shield_compliance_reports"`
	ID              string         `grove:"id,pk"          bson:"_id"`
	Framework       string         `grove:"framework"      bson:"framework"`
	ScopeKey        string         `grove:"scope_key"      bson:"scope_key"`
	ScopeLevel      string         `grove:"scope_level"    bson:"scope_level"`
	PeriodStart     time.Time      `grove:"period_start"   bson:"period_start"`
	PeriodEnd       time.Time      `grove:"period_end"     bson:"period_end"`
	Summary         map[string]any `grove:"summary"        bson:"summary,omitempty"`
	Details         map[string]any `grove:"details"        bson:"details,omitempty"`
	GeneratedAt     time.Time      `grove:"generated_at"   bson:"generated_at"`
	CreatedAt       time.Time      `grove:"created_at"     bson:"created_at"`
	UpdatedAt       time.Time      `grove:"updated_at"     bson:"updated_at"`
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

func complianceFromModel(m *complianceReportModel) (*compliance.Report, error) {
	cid, err := id.ParseComplianceReportID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("parse compliance report ID %q: %w", m.ID, err)
	}
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
	}, nil
}

// ──────────────────────────────────────────────────
// Helper
// ──────────────────────────────────────────────────

func entityFromTimestamps(createdAt, updatedAt time.Time) shield.Entity {
	return shield.Entity{CreatedAt: createdAt, UpdatedAt: updatedAt}
}
