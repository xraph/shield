package sqlite

import (
	"encoding/json"
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
	ID              string    `grove:"id,pk"`
	Name            string    `grove:"name,notnull"`
	Description     string    `grove:"description"`
	AppID           string    `grove:"app_id,notnull"`
	TenantID        string    `grove:"tenant_id"`
	Category        string    `grove:"category,notnull"`
	Strategies      string    `grove:"strategies"`
	Sensitivity     string    `grove:"sensitivity,notnull"`
	Action          string    `grove:"action,notnull"`
	Enabled         bool      `grove:"enabled,notnull"`
	Metadata        string    `grove:"metadata"`
	CreatedAt       time.Time `grove:"created_at,notnull"`
	UpdatedAt       time.Time `grove:"updated_at,notnull"`
}

func instinctToModel(inst *instinct.Instinct) (*instinctModel, error) {
	strategies, err := json.Marshal(inst.Strategies)
	if err != nil {
		return nil, fmt.Errorf("marshal strategies: %w", err)
	}
	metadata, err := json.Marshal(inst.Metadata)
	if err != nil {
		return nil, fmt.Errorf("marshal metadata: %w", err)
	}
	return &instinctModel{
		ID:          inst.ID.String(),
		Name:        inst.Name,
		Description: inst.Description,
		AppID:       inst.AppID,
		TenantID:    inst.TenantID,
		Category:    string(inst.Category),
		Strategies:  string(strategies),
		Sensitivity: string(inst.Sensitivity),
		Action:      inst.Action,
		Enabled:     inst.Enabled,
		Metadata:    string(metadata),
		CreatedAt:   inst.CreatedAt,
		UpdatedAt:   inst.UpdatedAt,
	}, nil
}

func instinctFromModel(m *instinctModel) (*instinct.Instinct, error) {
	iid, err := id.ParseInstinctID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("parse instinct ID %q: %w", m.ID, err)
	}
	var strategies []instinct.Strategy
	if m.Strategies != "" {
		if err := json.Unmarshal([]byte(m.Strategies), &strategies); err != nil {
			return nil, fmt.Errorf("unmarshal strategies: %w", err)
		}
	}
	var metadata map[string]any
	if m.Metadata != "" {
		if err := json.Unmarshal([]byte(m.Metadata), &metadata); err != nil {
			return nil, fmt.Errorf("unmarshal metadata: %w", err)
		}
	}
	return &instinct.Instinct{
		Entity:      entityFromTimestamps(m.CreatedAt, m.UpdatedAt),
		ID:          iid,
		Name:        m.Name,
		Description: m.Description,
		AppID:       m.AppID,
		TenantID:    m.TenantID,
		Category:    instinct.Category(m.Category),
		Strategies:  strategies,
		Sensitivity: instinct.Sensitivity(m.Sensitivity),
		Action:      m.Action,
		Enabled:     m.Enabled,
		Metadata:    metadata,
	}, nil
}

// ──────────────────────────────────────────────────
// Awareness model
// ──────────────────────────────────────────────────

type awarenessModel struct {
	grove.BaseModel `grove:"table:shield_awareness"`
	ID              string    `grove:"id,pk"`
	Name            string    `grove:"name,notnull"`
	Description     string    `grove:"description"`
	AppID           string    `grove:"app_id,notnull"`
	TenantID        string    `grove:"tenant_id"`
	Focus           string    `grove:"focus,notnull"`
	Detectors       string    `grove:"detectors"`
	Action          string    `grove:"action,notnull"`
	Enabled         bool      `grove:"enabled,notnull"`
	Metadata        string    `grove:"metadata"`
	CreatedAt       time.Time `grove:"created_at,notnull"`
	UpdatedAt       time.Time `grove:"updated_at,notnull"`
}

func awarenessToModel(a *awareness.Awareness) (*awarenessModel, error) {
	detectors, err := json.Marshal(a.Detectors)
	if err != nil {
		return nil, fmt.Errorf("marshal detectors: %w", err)
	}
	metadata, err := json.Marshal(a.Metadata)
	if err != nil {
		return nil, fmt.Errorf("marshal metadata: %w", err)
	}
	return &awarenessModel{
		ID:          a.ID.String(),
		Name:        a.Name,
		Description: a.Description,
		AppID:       a.AppID,
		TenantID:    a.TenantID,
		Focus:       string(a.Focus),
		Detectors:   string(detectors),
		Action:      a.Action,
		Enabled:     a.Enabled,
		Metadata:    string(metadata),
		CreatedAt:   a.CreatedAt,
		UpdatedAt:   a.UpdatedAt,
	}, nil
}

func awarenessFromModel(m *awarenessModel) (*awareness.Awareness, error) {
	aid, err := id.ParseAwarenessID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("parse awareness ID %q: %w", m.ID, err)
	}
	var detectors []awareness.Detector
	if m.Detectors != "" {
		if err := json.Unmarshal([]byte(m.Detectors), &detectors); err != nil {
			return nil, fmt.Errorf("unmarshal detectors: %w", err)
		}
	}
	var metadata map[string]any
	if m.Metadata != "" {
		if err := json.Unmarshal([]byte(m.Metadata), &metadata); err != nil {
			return nil, fmt.Errorf("unmarshal metadata: %w", err)
		}
	}
	return &awareness.Awareness{
		Entity:      entityFromTimestamps(m.CreatedAt, m.UpdatedAt),
		ID:          aid,
		Name:        m.Name,
		Description: m.Description,
		AppID:       m.AppID,
		TenantID:    m.TenantID,
		Focus:       awareness.Focus(m.Focus),
		Detectors:   detectors,
		Action:      m.Action,
		Enabled:     m.Enabled,
		Metadata:    metadata,
	}, nil
}

// ──────────────────────────────────────────────────
// Boundary model
// ──────────────────────────────────────────────────

type boundaryModel struct {
	grove.BaseModel `grove:"table:shield_boundaries"`
	ID              string    `grove:"id,pk"`
	Name            string    `grove:"name,notnull"`
	Description     string    `grove:"description"`
	AppID           string    `grove:"app_id,notnull"`
	TenantID        string    `grove:"tenant_id"`
	Limits          string    `grove:"limits"`
	Response        string    `grove:"response"`
	Enabled         bool      `grove:"enabled,notnull"`
	Metadata        string    `grove:"metadata"`
	CreatedAt       time.Time `grove:"created_at,notnull"`
	UpdatedAt       time.Time `grove:"updated_at,notnull"`
}

func boundaryToModel(b *boundary.Boundary) (*boundaryModel, error) {
	limits, err := json.Marshal(b.Limits)
	if err != nil {
		return nil, fmt.Errorf("marshal limits: %w", err)
	}
	metadata, err := json.Marshal(b.Metadata)
	if err != nil {
		return nil, fmt.Errorf("marshal metadata: %w", err)
	}
	return &boundaryModel{
		ID:          b.ID.String(),
		Name:        b.Name,
		Description: b.Description,
		AppID:       b.AppID,
		TenantID:    b.TenantID,
		Limits:      string(limits),
		Response:    b.Response,
		Enabled:     b.Enabled,
		Metadata:    string(metadata),
		CreatedAt:   b.CreatedAt,
		UpdatedAt:   b.UpdatedAt,
	}, nil
}

func boundaryFromModel(m *boundaryModel) (*boundary.Boundary, error) {
	bid, err := id.ParseBoundaryID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("parse boundary ID %q: %w", m.ID, err)
	}
	var limits []boundary.Limit
	if m.Limits != "" {
		if err := json.Unmarshal([]byte(m.Limits), &limits); err != nil {
			return nil, fmt.Errorf("unmarshal limits: %w", err)
		}
	}
	var metadata map[string]any
	if m.Metadata != "" {
		if err := json.Unmarshal([]byte(m.Metadata), &metadata); err != nil {
			return nil, fmt.Errorf("unmarshal metadata: %w", err)
		}
	}
	return &boundary.Boundary{
		Entity:      entityFromTimestamps(m.CreatedAt, m.UpdatedAt),
		ID:          bid,
		Name:        m.Name,
		Description: m.Description,
		AppID:       m.AppID,
		TenantID:    m.TenantID,
		Limits:      limits,
		Response:    m.Response,
		Enabled:     m.Enabled,
		Metadata:    metadata,
	}, nil
}

// ──────────────────────────────────────────────────
// Values model
// ──────────────────────────────────────────────────

type valuesModel struct {
	grove.BaseModel `grove:"table:shield_values"`
	ID              string    `grove:"id,pk"`
	Name            string    `grove:"name,notnull"`
	Description     string    `grove:"description"`
	AppID           string    `grove:"app_id,notnull"`
	TenantID        string    `grove:"tenant_id"`
	Rules           string    `grove:"rules"`
	Severity        string    `grove:"severity"`
	Action          string    `grove:"action,notnull"`
	Enabled         bool      `grove:"enabled,notnull"`
	Metadata        string    `grove:"metadata"`
	CreatedAt       time.Time `grove:"created_at,notnull"`
	UpdatedAt       time.Time `grove:"updated_at,notnull"`
}

func valuesToModel(v *values.Values) (*valuesModel, error) {
	rules, err := json.Marshal(v.Rules)
	if err != nil {
		return nil, fmt.Errorf("marshal rules: %w", err)
	}
	metadata, err := json.Marshal(v.Metadata)
	if err != nil {
		return nil, fmt.Errorf("marshal metadata: %w", err)
	}
	return &valuesModel{
		ID:          v.ID.String(),
		Name:        v.Name,
		Description: v.Description,
		AppID:       v.AppID,
		TenantID:    v.TenantID,
		Rules:       string(rules),
		Severity:    v.Severity,
		Action:      v.Action,
		Enabled:     v.Enabled,
		Metadata:    string(metadata),
		CreatedAt:   v.CreatedAt,
		UpdatedAt:   v.UpdatedAt,
	}, nil
}

func valuesFromModel(m *valuesModel) (*values.Values, error) {
	vid, err := id.ParseValueID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("parse value ID %q: %w", m.ID, err)
	}
	var rules []values.Rule
	if m.Rules != "" {
		if err := json.Unmarshal([]byte(m.Rules), &rules); err != nil {
			return nil, fmt.Errorf("unmarshal rules: %w", err)
		}
	}
	var metadata map[string]any
	if m.Metadata != "" {
		if err := json.Unmarshal([]byte(m.Metadata), &metadata); err != nil {
			return nil, fmt.Errorf("unmarshal metadata: %w", err)
		}
	}
	return &values.Values{
		Entity:      entityFromTimestamps(m.CreatedAt, m.UpdatedAt),
		ID:          vid,
		Name:        m.Name,
		Description: m.Description,
		AppID:       m.AppID,
		TenantID:    m.TenantID,
		Rules:       rules,
		Severity:    m.Severity,
		Action:      m.Action,
		Enabled:     m.Enabled,
		Metadata:    metadata,
	}, nil
}

// ──────────────────────────────────────────────────
// Judgment model
// ──────────────────────────────────────────────────

type judgmentModel struct {
	grove.BaseModel `grove:"table:shield_judgments"`
	ID              string    `grove:"id,pk"`
	Name            string    `grove:"name,notnull"`
	Description     string    `grove:"description"`
	AppID           string    `grove:"app_id,notnull"`
	TenantID        string    `grove:"tenant_id"`
	Domain          string    `grove:"domain,notnull"`
	Assessors       string    `grove:"assessors"`
	Threshold       float64   `grove:"threshold"`
	Action          string    `grove:"action,notnull"`
	Enabled         bool      `grove:"enabled,notnull"`
	Metadata        string    `grove:"metadata"`
	CreatedAt       time.Time `grove:"created_at,notnull"`
	UpdatedAt       time.Time `grove:"updated_at,notnull"`
}

func judgmentToModel(j *judgment.Judgment) (*judgmentModel, error) {
	assessors, err := json.Marshal(j.Assessors)
	if err != nil {
		return nil, fmt.Errorf("marshal assessors: %w", err)
	}
	metadata, err := json.Marshal(j.Metadata)
	if err != nil {
		return nil, fmt.Errorf("marshal metadata: %w", err)
	}
	return &judgmentModel{
		ID:          j.ID.String(),
		Name:        j.Name,
		Description: j.Description,
		AppID:       j.AppID,
		TenantID:    j.TenantID,
		Domain:      string(j.Domain),
		Assessors:   string(assessors),
		Threshold:   j.Threshold,
		Action:      j.Action,
		Enabled:     j.Enabled,
		Metadata:    string(metadata),
		CreatedAt:   j.CreatedAt,
		UpdatedAt:   j.UpdatedAt,
	}, nil
}

func judgmentFromModel(m *judgmentModel) (*judgment.Judgment, error) {
	jid, err := id.ParseJudgmentID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("parse judgment ID %q: %w", m.ID, err)
	}
	var assessors []judgment.Assessor
	if m.Assessors != "" {
		if err := json.Unmarshal([]byte(m.Assessors), &assessors); err != nil {
			return nil, fmt.Errorf("unmarshal assessors: %w", err)
		}
	}
	var metadata map[string]any
	if m.Metadata != "" {
		if err := json.Unmarshal([]byte(m.Metadata), &metadata); err != nil {
			return nil, fmt.Errorf("unmarshal metadata: %w", err)
		}
	}
	return &judgment.Judgment{
		Entity:      entityFromTimestamps(m.CreatedAt, m.UpdatedAt),
		ID:          jid,
		Name:        m.Name,
		Description: m.Description,
		AppID:       m.AppID,
		TenantID:    m.TenantID,
		Domain:      judgment.Domain(m.Domain),
		Assessors:   assessors,
		Threshold:   m.Threshold,
		Action:      m.Action,
		Enabled:     m.Enabled,
		Metadata:    metadata,
	}, nil
}

// ──────────────────────────────────────────────────
// Reflex model
// ──────────────────────────────────────────────────

type reflexModel struct {
	grove.BaseModel `grove:"table:shield_reflexes"`
	ID              string    `grove:"id,pk"`
	Name            string    `grove:"name,notnull"`
	Description     string    `grove:"description"`
	AppID           string    `grove:"app_id,notnull"`
	TenantID        string    `grove:"tenant_id"`
	Triggers        string    `grove:"triggers"`
	Actions         string    `grove:"actions"`
	Priority        int       `grove:"priority"`
	Enabled         bool      `grove:"enabled,notnull"`
	Metadata        string    `grove:"metadata"`
	CreatedAt       time.Time `grove:"created_at,notnull"`
	UpdatedAt       time.Time `grove:"updated_at,notnull"`
}

func reflexToModel(r *reflex.Reflex) (*reflexModel, error) {
	triggers, err := json.Marshal(r.Triggers)
	if err != nil {
		return nil, fmt.Errorf("marshal triggers: %w", err)
	}
	actions, err := json.Marshal(r.Actions)
	if err != nil {
		return nil, fmt.Errorf("marshal actions: %w", err)
	}
	metadata, err := json.Marshal(r.Metadata)
	if err != nil {
		return nil, fmt.Errorf("marshal metadata: %w", err)
	}
	return &reflexModel{
		ID:          r.ID.String(),
		Name:        r.Name,
		Description: r.Description,
		AppID:       r.AppID,
		TenantID:    r.TenantID,
		Triggers:    string(triggers),
		Actions:     string(actions),
		Priority:    r.Priority,
		Enabled:     r.Enabled,
		Metadata:    string(metadata),
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}, nil
}

func reflexFromModel(m *reflexModel) (*reflex.Reflex, error) {
	rid, err := id.ParseReflexID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("parse reflex ID %q: %w", m.ID, err)
	}
	var triggers []reflex.Trigger
	if m.Triggers != "" {
		if err := json.Unmarshal([]byte(m.Triggers), &triggers); err != nil {
			return nil, fmt.Errorf("unmarshal triggers: %w", err)
		}
	}
	var actions []reflex.Action
	if m.Actions != "" {
		if err := json.Unmarshal([]byte(m.Actions), &actions); err != nil {
			return nil, fmt.Errorf("unmarshal actions: %w", err)
		}
	}
	var metadata map[string]any
	if m.Metadata != "" {
		if err := json.Unmarshal([]byte(m.Metadata), &metadata); err != nil {
			return nil, fmt.Errorf("unmarshal metadata: %w", err)
		}
	}
	return &reflex.Reflex{
		Entity:      entityFromTimestamps(m.CreatedAt, m.UpdatedAt),
		ID:          rid,
		Name:        m.Name,
		Description: m.Description,
		AppID:       m.AppID,
		TenantID:    m.TenantID,
		Triggers:    triggers,
		Actions:     actions,
		Priority:    m.Priority,
		Enabled:     m.Enabled,
		Metadata:    metadata,
	}, nil
}

// ──────────────────────────────────────────────────
// Profile model
// ──────────────────────────────────────────────────

type profileModel struct {
	grove.BaseModel `grove:"table:shield_profiles"`
	ID              string    `grove:"id,pk"`
	Name            string    `grove:"name,notnull"`
	Description     string    `grove:"description"`
	AppID           string    `grove:"app_id,notnull"`
	TenantID        string    `grove:"tenant_id"`
	Instincts       string    `grove:"instincts"`
	Judgments       string    `grove:"judgments"`
	Awareness       string    `grove:"awareness"`
	Values          string    `grove:"values"`
	Reflexes        string    `grove:"reflexes"`
	Boundaries      string    `grove:"boundaries"`
	Enabled         bool      `grove:"enabled,notnull"`
	Metadata        string    `grove:"metadata"`
	CreatedAt       time.Time `grove:"created_at,notnull"`
	UpdatedAt       time.Time `grove:"updated_at,notnull"`
}

func profileToModel(p *profile.SafetyProfile) (*profileModel, error) {
	instincts, err := json.Marshal(p.Instincts)
	if err != nil {
		return nil, fmt.Errorf("marshal instincts: %w", err)
	}
	judgments, err := json.Marshal(p.Judgments)
	if err != nil {
		return nil, fmt.Errorf("marshal judgments: %w", err)
	}
	awarenessData, err := json.Marshal(p.Awareness)
	if err != nil {
		return nil, fmt.Errorf("marshal awareness: %w", err)
	}
	valuesData, err := json.Marshal(p.Values)
	if err != nil {
		return nil, fmt.Errorf("marshal values: %w", err)
	}
	reflexes, err := json.Marshal(p.Reflexes)
	if err != nil {
		return nil, fmt.Errorf("marshal reflexes: %w", err)
	}
	boundaries, err := json.Marshal(p.Boundaries)
	if err != nil {
		return nil, fmt.Errorf("marshal boundaries: %w", err)
	}
	metadata, err := json.Marshal(p.Metadata)
	if err != nil {
		return nil, fmt.Errorf("marshal metadata: %w", err)
	}
	return &profileModel{
		ID:          p.ID.String(),
		Name:        p.Name,
		Description: p.Description,
		AppID:       p.AppID,
		TenantID:    p.TenantID,
		Instincts:   string(instincts),
		Judgments:   string(judgments),
		Awareness:   string(awarenessData),
		Values:      string(valuesData),
		Reflexes:    string(reflexes),
		Boundaries:  string(boundaries),
		Enabled:     p.Enabled,
		Metadata:    string(metadata),
		CreatedAt:   p.CreatedAt,
		UpdatedAt:   p.UpdatedAt,
	}, nil
}

func profileFromModel(m *profileModel) (*profile.SafetyProfile, error) {
	pid, err := id.ParseSafetyProfileID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("parse profile ID %q: %w", m.ID, err)
	}
	var instincts []profile.InstinctAssignment
	if m.Instincts != "" {
		if err := json.Unmarshal([]byte(m.Instincts), &instincts); err != nil {
			return nil, fmt.Errorf("unmarshal instincts: %w", err)
		}
	}
	var judgments []profile.JudgmentAssignment
	if m.Judgments != "" {
		if err := json.Unmarshal([]byte(m.Judgments), &judgments); err != nil {
			return nil, fmt.Errorf("unmarshal judgments: %w", err)
		}
	}
	var awarenessData []profile.AwarenessAssignment
	if m.Awareness != "" {
		if err := json.Unmarshal([]byte(m.Awareness), &awarenessData); err != nil {
			return nil, fmt.Errorf("unmarshal awareness: %w", err)
		}
	}
	var valuesData []string
	if m.Values != "" {
		if err := json.Unmarshal([]byte(m.Values), &valuesData); err != nil {
			return nil, fmt.Errorf("unmarshal values: %w", err)
		}
	}
	var reflexes []string
	if m.Reflexes != "" {
		if err := json.Unmarshal([]byte(m.Reflexes), &reflexes); err != nil {
			return nil, fmt.Errorf("unmarshal reflexes: %w", err)
		}
	}
	var boundaries []string
	if m.Boundaries != "" {
		if err := json.Unmarshal([]byte(m.Boundaries), &boundaries); err != nil {
			return nil, fmt.Errorf("unmarshal boundaries: %w", err)
		}
	}
	var metadata map[string]any
	if m.Metadata != "" {
		if err := json.Unmarshal([]byte(m.Metadata), &metadata); err != nil {
			return nil, fmt.Errorf("unmarshal metadata: %w", err)
		}
	}
	return &profile.SafetyProfile{
		Entity:      entityFromTimestamps(m.CreatedAt, m.UpdatedAt),
		ID:          pid,
		Name:        m.Name,
		Description: m.Description,
		AppID:       m.AppID,
		TenantID:    m.TenantID,
		Instincts:   instincts,
		Judgments:   judgments,
		Awareness:   awarenessData,
		Values:      valuesData,
		Reflexes:    reflexes,
		Boundaries:  boundaries,
		Enabled:     m.Enabled,
		Metadata:    metadata,
	}, nil
}

// ──────────────────────────────────────────────────
// Scan model
// ──────────────────────────────────────────────────

type scanResultModel struct {
	grove.BaseModel `grove:"table:shield_scans"`
	ID              string    `grove:"id,pk"`
	Direction       string    `grove:"direction,notnull"`
	Decision        string    `grove:"decision,notnull"`
	Blocked         bool      `grove:"blocked,notnull"`
	Findings        string    `grove:"findings"`
	Redacted        string    `grove:"redacted"`
	PIICount        int       `grove:"pii_count"`
	ProfileUsed     string    `grove:"profile_used"`
	PoliciesUsed    string    `grove:"policies_used"`
	TenantID        string    `grove:"tenant_id,notnull"`
	AppID           string    `grove:"app_id,notnull"`
	Duration        int64     `grove:"duration"`
	Metadata        string    `grove:"metadata"`
	CreatedAt       time.Time `grove:"created_at,notnull"`
	UpdatedAt       time.Time `grove:"updated_at,notnull"`
}

func scanToModel(r *scan.Result) (*scanResultModel, error) {
	findings, err := json.Marshal(r.Findings)
	if err != nil {
		return nil, fmt.Errorf("marshal findings: %w", err)
	}
	policiesUsed, err := json.Marshal(r.PoliciesUsed)
	if err != nil {
		return nil, fmt.Errorf("marshal policies_used: %w", err)
	}
	metadata, err := json.Marshal(r.Metadata)
	if err != nil {
		return nil, fmt.Errorf("marshal metadata: %w", err)
	}
	return &scanResultModel{
		ID:           r.ID.String(),
		Direction:    string(r.Direction),
		Decision:     string(r.Decision),
		Blocked:      r.Blocked,
		Findings:     string(findings),
		Redacted:     r.Redacted,
		PIICount:     r.PIICount,
		ProfileUsed:  r.ProfileUsed,
		PoliciesUsed: string(policiesUsed),
		TenantID:     r.TenantID,
		AppID:        r.AppID,
		Duration:     int64(r.Duration),
		Metadata:     string(metadata),
		CreatedAt:    r.CreatedAt,
		UpdatedAt:    r.UpdatedAt,
	}, nil
}

func scanFromModel(m *scanResultModel) (*scan.Result, error) {
	sid, err := id.ParseScanID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("parse scan ID %q: %w", m.ID, err)
	}
	var findings []*scan.Finding
	if m.Findings != "" {
		if err := json.Unmarshal([]byte(m.Findings), &findings); err != nil {
			return nil, fmt.Errorf("unmarshal findings: %w", err)
		}
	}
	var policiesUsed []string
	if m.PoliciesUsed != "" {
		if err := json.Unmarshal([]byte(m.PoliciesUsed), &policiesUsed); err != nil {
			return nil, fmt.Errorf("unmarshal policies_used: %w", err)
		}
	}
	var metadata map[string]any
	if m.Metadata != "" {
		if err := json.Unmarshal([]byte(m.Metadata), &metadata); err != nil {
			return nil, fmt.Errorf("unmarshal metadata: %w", err)
		}
	}
	return &scan.Result{
		Entity:       entityFromTimestamps(m.CreatedAt, m.UpdatedAt),
		ID:           sid,
		Direction:    scan.Direction(m.Direction),
		Decision:     scan.Decision(m.Decision),
		Blocked:      m.Blocked,
		Findings:     findings,
		Redacted:     m.Redacted,
		PIICount:     m.PIICount,
		ProfileUsed:  m.ProfileUsed,
		PoliciesUsed: policiesUsed,
		TenantID:     m.TenantID,
		AppID:        m.AppID,
		Duration:     time.Duration(m.Duration),
		Metadata:     metadata,
	}, nil
}

// ──────────────────────────────────────────────────
// Policy model
// ──────────────────────────────────────────────────

type policyModel struct {
	grove.BaseModel `grove:"table:shield_policies"`
	ID              string    `grove:"id,pk"`
	Name            string    `grove:"name,notnull"`
	Description     string    `grove:"description"`
	ScopeKey        string    `grove:"scope_key,notnull"`
	ScopeLevel      string    `grove:"scope_level,notnull"`
	Rules           string    `grove:"rules"`
	Enabled         bool      `grove:"enabled,notnull"`
	Metadata        string    `grove:"metadata"`
	CreatedAt       time.Time `grove:"created_at,notnull"`
	UpdatedAt       time.Time `grove:"updated_at,notnull"`
}

func policyToModel(pol *policy.Policy) (*policyModel, error) {
	rules, err := json.Marshal(pol.Rules)
	if err != nil {
		return nil, fmt.Errorf("marshal rules: %w", err)
	}
	metadata, err := json.Marshal(pol.Metadata)
	if err != nil {
		return nil, fmt.Errorf("marshal metadata: %w", err)
	}
	return &policyModel{
		ID:          pol.ID.String(),
		Name:        pol.Name,
		Description: pol.Description,
		ScopeKey:    pol.ScopeKey,
		ScopeLevel:  string(pol.ScopeLevel),
		Rules:       string(rules),
		Enabled:     pol.Enabled,
		Metadata:    string(metadata),
		CreatedAt:   pol.CreatedAt,
		UpdatedAt:   pol.UpdatedAt,
	}, nil
}

func policyFromModel(m *policyModel) (*policy.Policy, error) {
	pid, err := id.ParsePolicyID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("parse policy ID %q: %w", m.ID, err)
	}
	var rules []policy.Rule
	if m.Rules != "" {
		if err := json.Unmarshal([]byte(m.Rules), &rules); err != nil {
			return nil, fmt.Errorf("unmarshal rules: %w", err)
		}
	}
	var metadata map[string]any
	if m.Metadata != "" {
		if err := json.Unmarshal([]byte(m.Metadata), &metadata); err != nil {
			return nil, fmt.Errorf("unmarshal metadata: %w", err)
		}
	}
	return &policy.Policy{
		Entity:      entityFromTimestamps(m.CreatedAt, m.UpdatedAt),
		ID:          pid,
		Name:        m.Name,
		Description: m.Description,
		ScopeKey:    m.ScopeKey,
		ScopeLevel:  policy.ScopeLevel(m.ScopeLevel),
		Rules:       rules,
		Enabled:     m.Enabled,
		Metadata:    metadata,
	}, nil
}

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
	ID              string    `grove:"id,pk"`
	Framework       string    `grove:"framework,notnull"`
	ScopeKey        string    `grove:"scope_key,notnull"`
	ScopeLevel      string    `grove:"scope_level,notnull"`
	PeriodStart     time.Time `grove:"period_start,notnull"`
	PeriodEnd       time.Time `grove:"period_end,notnull"`
	Summary         string    `grove:"summary"`
	Details         string    `grove:"details"`
	GeneratedAt     time.Time `grove:"generated_at,notnull"`
	CreatedAt       time.Time `grove:"created_at,notnull"`
	UpdatedAt       time.Time `grove:"updated_at,notnull"`
}

func complianceToModel(r *compliance.Report) (*complianceReportModel, error) {
	summary, err := json.Marshal(r.Summary)
	if err != nil {
		return nil, fmt.Errorf("marshal summary: %w", err)
	}
	details, err := json.Marshal(r.Details)
	if err != nil {
		return nil, fmt.Errorf("marshal details: %w", err)
	}
	return &complianceReportModel{
		ID:          r.ID.String(),
		Framework:   string(r.Framework),
		ScopeKey:    r.ScopeKey,
		ScopeLevel:  r.ScopeLevel,
		PeriodStart: r.PeriodStart,
		PeriodEnd:   r.PeriodEnd,
		Summary:     string(summary),
		Details:     string(details),
		GeneratedAt: r.GeneratedAt,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}, nil
}

func complianceFromModel(m *complianceReportModel) (*compliance.Report, error) {
	cid, err := id.ParseComplianceReportID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("parse compliance report ID %q: %w", m.ID, err)
	}
	var summary map[string]any
	if m.Summary != "" {
		if err := json.Unmarshal([]byte(m.Summary), &summary); err != nil {
			return nil, fmt.Errorf("unmarshal summary: %w", err)
		}
	}
	var details map[string]any
	if m.Details != "" {
		if err := json.Unmarshal([]byte(m.Details), &details); err != nil {
			return nil, fmt.Errorf("unmarshal details: %w", err)
		}
	}
	return &compliance.Report{
		Entity:      entityFromTimestamps(m.CreatedAt, m.UpdatedAt),
		ID:          cid,
		Framework:   compliance.Framework(m.Framework),
		ScopeKey:    m.ScopeKey,
		ScopeLevel:  m.ScopeLevel,
		PeriodStart: m.PeriodStart,
		PeriodEnd:   m.PeriodEnd,
		Summary:     summary,
		Details:     details,
		GeneratedAt: m.GeneratedAt,
	}, nil
}

// ──────────────────────────────────────────────────
// Helper
// ──────────────────────────────────────────────────

func entityFromTimestamps(createdAt, updatedAt time.Time) shield.Entity {
	return shield.Entity{CreatedAt: createdAt, UpdatedAt: updatedAt}
}
