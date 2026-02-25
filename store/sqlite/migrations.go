package sqlite

import (
	"context"

	"github.com/xraph/grove/migrate"
)

// Migrations is the grove migration group for the Shield store (SQLite).
var Migrations = migrate.NewGroup("shield")

func init() {
	Migrations.MustRegister(
		&migrate.Migration{
			Name:    "create_shield_instincts",
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
    strategies      TEXT NOT NULL DEFAULT '[]',
    sensitivity     TEXT NOT NULL DEFAULT 'balanced',
    action          TEXT NOT NULL,
    enabled         INTEGER NOT NULL DEFAULT 1,
    metadata        TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),

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
			Name:    "create_shield_awareness",
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
    detectors       TEXT NOT NULL DEFAULT '[]',
    action          TEXT NOT NULL,
    enabled         INTEGER NOT NULL DEFAULT 1,
    metadata        TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),

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
			Name:    "create_shield_boundaries",
			Version: "20240101000003",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS shield_boundaries (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    app_id          TEXT NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT '',
    limits          TEXT NOT NULL DEFAULT '[]',
    response        TEXT NOT NULL DEFAULT '',
    enabled         INTEGER NOT NULL DEFAULT 1,
    metadata        TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),

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
			Name:    "create_shield_values",
			Version: "20240101000004",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS shield_values (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    app_id          TEXT NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT '',
    rules           TEXT NOT NULL DEFAULT '[]',
    severity        TEXT NOT NULL DEFAULT 'warning',
    action          TEXT NOT NULL,
    enabled         INTEGER NOT NULL DEFAULT 1,
    metadata        TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),

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
			Name:    "create_shield_judgments",
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
    assessors       TEXT NOT NULL DEFAULT '[]',
    threshold       REAL NOT NULL DEFAULT 0,
    action          TEXT NOT NULL,
    enabled         INTEGER NOT NULL DEFAULT 1,
    metadata        TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),

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
			Name:    "create_shield_reflexes",
			Version: "20240101000006",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS shield_reflexes (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    app_id          TEXT NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT '',
    triggers        TEXT NOT NULL DEFAULT '[]',
    actions         TEXT NOT NULL DEFAULT '[]',
    priority        INTEGER NOT NULL DEFAULT 0,
    enabled         INTEGER NOT NULL DEFAULT 1,
    metadata        TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),

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
			Name:    "create_shield_profiles",
			Version: "20240101000007",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS shield_profiles (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    app_id          TEXT NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT '',
    instincts       TEXT NOT NULL DEFAULT '[]',
    judgments       TEXT NOT NULL DEFAULT '[]',
    awareness       TEXT NOT NULL DEFAULT '[]',
    "values"        TEXT NOT NULL DEFAULT '[]',
    reflexes        TEXT NOT NULL DEFAULT '[]',
    boundaries      TEXT NOT NULL DEFAULT '[]',
    enabled         INTEGER NOT NULL DEFAULT 1,
    metadata        TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),

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
			Name:    "create_shield_scans",
			Version: "20240101000008",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS shield_scans (
    id              TEXT PRIMARY KEY,
    direction       TEXT NOT NULL,
    decision        TEXT NOT NULL,
    blocked         INTEGER NOT NULL DEFAULT 0,
    findings        TEXT NOT NULL DEFAULT '[]',
    redacted        TEXT NOT NULL DEFAULT '',
    pii_count       INTEGER NOT NULL DEFAULT 0,
    profile_used    TEXT NOT NULL DEFAULT '',
    policies_used   TEXT NOT NULL DEFAULT '[]',
    tenant_id       TEXT NOT NULL,
    app_id          TEXT NOT NULL,
    duration        INTEGER NOT NULL DEFAULT 0,
    metadata        TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_shield_scans_app ON shield_scans (app_id);
CREATE INDEX IF NOT EXISTS idx_shield_scans_tenant ON shield_scans (tenant_id);
CREATE INDEX IF NOT EXISTS idx_shield_scans_decision ON shield_scans (decision);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS shield_scans`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_shield_policies",
			Version: "20240101000009",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS shield_policies (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    scope_key       TEXT NOT NULL,
    scope_level     TEXT NOT NULL,
    rules           TEXT NOT NULL DEFAULT '[]',
    enabled         INTEGER NOT NULL DEFAULT 1,
    metadata        TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),

    UNIQUE(scope_key, name)
);

CREATE INDEX IF NOT EXISTS idx_shield_policies_scope ON shield_policies (scope_key, scope_level);

CREATE TABLE IF NOT EXISTS shield_policy_tenants (
    tenant_id       TEXT NOT NULL,
    policy_id       TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),

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
			Name:    "create_shield_pii_tokens",
			Version: "20240101000010",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS shield_pii_tokens (
    id              TEXT PRIMARY KEY,
    scan_id         TEXT NOT NULL,
    tenant_id       TEXT NOT NULL,
    pii_type        TEXT NOT NULL,
    placeholder     TEXT NOT NULL,
    encrypted_value BLOB NOT NULL,
    expires_at      TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_shield_pii_tokens_scan ON shield_pii_tokens (scan_id);
CREATE INDEX IF NOT EXISTS idx_shield_pii_tokens_tenant ON shield_pii_tokens (tenant_id);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS shield_pii_tokens`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_shield_compliance_reports",
			Version: "20240101000011",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS shield_compliance_reports (
    id              TEXT PRIMARY KEY,
    framework       TEXT NOT NULL,
    scope_key       TEXT NOT NULL,
    scope_level     TEXT NOT NULL,
    period_start    TEXT NOT NULL,
    period_end      TEXT NOT NULL,
    summary         TEXT NOT NULL DEFAULT '{}',
    details         TEXT NOT NULL DEFAULT '{}',
    generated_at    TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_shield_compliance_scope ON shield_compliance_reports (scope_key, framework);
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
