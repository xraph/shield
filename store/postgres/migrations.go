package postgres

import (
	"context"

	"github.com/xraph/grove/migrate"
)

// Migrations is the grove migration group for the Shield store.
var Migrations = migrate.NewGroup("shield")

func init() {
	Migrations.MustRegister(
		&migrate.Migration{
			Name:    "create_instincts",
			Version: "20240101000001",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS shield_instincts (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    app_id          TEXT NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT '',
    category        TEXT NOT NULL,
    strategies      JSONB NOT NULL DEFAULT '[]',
    sensitivity     TEXT NOT NULL DEFAULT 'balanced',
    action          TEXT NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(app_id, name)
);

CREATE INDEX IF NOT EXISTS idx_shield_instincts_app ON shield_instincts (app_id);
CREATE INDEX IF NOT EXISTS idx_shield_instincts_tenant ON shield_instincts (app_id, tenant_id);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS shield_instincts`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_awareness",
			Version: "20240101000002",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS shield_awareness (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    app_id          TEXT NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT '',
    focus           TEXT NOT NULL,
    detectors       JSONB NOT NULL DEFAULT '[]',
    action          TEXT NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(app_id, name)
);

CREATE INDEX IF NOT EXISTS idx_shield_awareness_app ON shield_awareness (app_id);
CREATE INDEX IF NOT EXISTS idx_shield_awareness_tenant ON shield_awareness (app_id, tenant_id);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS shield_awareness`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_boundaries",
			Version: "20240101000003",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS shield_boundaries (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    app_id          TEXT NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT '',
    limits          JSONB NOT NULL DEFAULT '[]',
    response        TEXT NOT NULL DEFAULT '',
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(app_id, name)
);

CREATE INDEX IF NOT EXISTS idx_shield_boundaries_app ON shield_boundaries (app_id);
CREATE INDEX IF NOT EXISTS idx_shield_boundaries_tenant ON shield_boundaries (app_id, tenant_id);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS shield_boundaries`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_values",
			Version: "20240101000004",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS shield_values (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    app_id          TEXT NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT '',
    rules           JSONB NOT NULL DEFAULT '[]',
    severity        TEXT NOT NULL DEFAULT 'warning',
    action          TEXT NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(app_id, name)
);

CREATE INDEX IF NOT EXISTS idx_shield_values_app ON shield_values (app_id);
CREATE INDEX IF NOT EXISTS idx_shield_values_tenant ON shield_values (app_id, tenant_id);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS shield_values`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_judgments",
			Version: "20240101000005",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS shield_judgments (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    app_id          TEXT NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT '',
    domain          TEXT NOT NULL,
    assessors       JSONB NOT NULL DEFAULT '[]',
    threshold       REAL NOT NULL DEFAULT 0,
    action          TEXT NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(app_id, name)
);

CREATE INDEX IF NOT EXISTS idx_shield_judgments_app ON shield_judgments (app_id);
CREATE INDEX IF NOT EXISTS idx_shield_judgments_tenant ON shield_judgments (app_id, tenant_id);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS shield_judgments`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_reflexes",
			Version: "20240101000006",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS shield_reflexes (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    app_id          TEXT NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT '',
    triggers        JSONB NOT NULL DEFAULT '[]',
    actions         JSONB NOT NULL DEFAULT '[]',
    priority        INT NOT NULL DEFAULT 0,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(app_id, name)
);

CREATE INDEX IF NOT EXISTS idx_shield_reflexes_app ON shield_reflexes (app_id);
CREATE INDEX IF NOT EXISTS idx_shield_reflexes_tenant ON shield_reflexes (app_id, tenant_id);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS shield_reflexes`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_profiles",
			Version: "20240101000007",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS shield_profiles (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    app_id          TEXT NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT '',
    instincts       JSONB NOT NULL DEFAULT '[]',
    judgments       JSONB NOT NULL DEFAULT '[]',
    awareness       JSONB NOT NULL DEFAULT '[]',
    values          JSONB NOT NULL DEFAULT '[]',
    reflexes        JSONB NOT NULL DEFAULT '[]',
    boundaries      JSONB NOT NULL DEFAULT '[]',
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(app_id, name)
);

CREATE INDEX IF NOT EXISTS idx_shield_profiles_app ON shield_profiles (app_id);
CREATE INDEX IF NOT EXISTS idx_shield_profiles_tenant ON shield_profiles (app_id, tenant_id);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS shield_profiles`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_scans",
			Version: "20240101000008",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS shield_scans (
    id              TEXT PRIMARY KEY,
    direction       TEXT NOT NULL,
    decision        TEXT NOT NULL,
    blocked         BOOLEAN NOT NULL DEFAULT FALSE,
    findings        JSONB NOT NULL DEFAULT '[]',
    redacted        TEXT NOT NULL DEFAULT '',
    pii_count       INT NOT NULL DEFAULT 0,
    profile_used    TEXT NOT NULL DEFAULT '',
    policies_used   JSONB NOT NULL DEFAULT '[]',
    tenant_id       TEXT NOT NULL,
    app_id          TEXT NOT NULL,
    duration        BIGINT NOT NULL DEFAULT 0,
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_shield_scans_app ON shield_scans (app_id);
CREATE INDEX IF NOT EXISTS idx_shield_scans_tenant ON shield_scans (tenant_id);
CREATE INDEX IF NOT EXISTS idx_shield_scans_decision ON shield_scans (decision, created_at DESC);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS shield_scans`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_policies",
			Version: "20240101000009",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS shield_policies (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    scope_key       TEXT NOT NULL,
    scope_level     TEXT NOT NULL,
    rules           JSONB NOT NULL DEFAULT '[]',
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(scope_key, name)
);

CREATE INDEX IF NOT EXISTS idx_shield_policies_scope ON shield_policies (scope_key, scope_level);

CREATE TABLE IF NOT EXISTS shield_policy_tenants (
    tenant_id       TEXT NOT NULL,
    policy_id       TEXT NOT NULL REFERENCES shield_policies(id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (tenant_id, policy_id)
);

CREATE INDEX IF NOT EXISTS idx_shield_policy_tenants_policy ON shield_policy_tenants (policy_id);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
DROP TABLE IF EXISTS shield_policy_tenants;
DROP TABLE IF EXISTS shield_policies;
`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_pii_tokens",
			Version: "20240101000010",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS shield_pii_tokens (
    id              TEXT PRIMARY KEY,
    scan_id         TEXT NOT NULL,
    tenant_id       TEXT NOT NULL,
    pii_type        TEXT NOT NULL,
    placeholder     TEXT NOT NULL,
    encrypted_value BYTEA NOT NULL,
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_shield_pii_tokens_scan ON shield_pii_tokens (scan_id);
CREATE INDEX IF NOT EXISTS idx_shield_pii_tokens_tenant ON shield_pii_tokens (tenant_id);
CREATE INDEX IF NOT EXISTS idx_shield_pii_tokens_expires ON shield_pii_tokens (expires_at) WHERE expires_at IS NOT NULL;
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS shield_pii_tokens`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_compliance_reports",
			Version: "20240101000011",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS shield_compliance_reports (
    id              TEXT PRIMARY KEY,
    framework       TEXT NOT NULL,
    scope_key       TEXT NOT NULL,
    scope_level     TEXT NOT NULL,
    period_start    TIMESTAMPTZ NOT NULL,
    period_end      TIMESTAMPTZ NOT NULL,
    summary         JSONB NOT NULL DEFAULT '{}',
    details         JSONB NOT NULL DEFAULT '{}',
    generated_at    TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_shield_compliance_scope ON shield_compliance_reports (scope_key, framework);
CREATE INDEX IF NOT EXISTS idx_shield_compliance_period ON shield_compliance_reports (period_start, period_end);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS shield_compliance_reports`)
				return err
			},
		},
	)
}
