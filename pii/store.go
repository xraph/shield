// Package pii provides PII vault functionality for secure storage
// and restoration of personally identifiable information.
package pii

import (
	"context"
	"time"

	"github.com/xraph/shield"
	"github.com/xraph/shield/id"
)

// Token represents an encrypted PII token stored in the vault.
type Token struct {
	shield.Entity
	ID             id.PIITokenID `json:"id" bun:",pk"`
	ScanID         id.ScanID     `json:"scan_id" bun:",notnull"`
	TenantID       string        `json:"tenant_id" bun:",notnull"`
	PIIType        string        `json:"pii_type" bun:",notnull"` // "email", "ssn", "phone", "cc", etc.
	Placeholder    string        `json:"placeholder" bun:",notnull"` // "[EMAIL_1]", "[SSN_1]"
	EncryptedValue []byte        `json:"encrypted_value" bun:",notnull"` // AES-256-GCM encrypted
	ExpiresAt      *time.Time    `json:"expires_at,omitempty"` // GDPR retention
}

// Stats holds PII vault statistics.
type Stats struct {
	TotalTokens int64            `json:"total_tokens"`
	ByType      map[string]int64 `json:"by_type,omitempty"`
	ByTenant    map[string]int64 `json:"by_tenant,omitempty"`
}

// Store defines persistence operations for PII vault tokens.
type Store interface {
	StorePIITokens(ctx context.Context, tokens []*Token) error
	LoadPIITokens(ctx context.Context, tokenIDs []id.PIITokenID) ([]*Token, error)
	LoadPIITokensByScan(ctx context.Context, scanID id.ScanID) ([]*Token, error)
	DeletePIITokens(ctx context.Context, tokenIDs []id.PIITokenID) error
	DeletePIITokensByTenant(ctx context.Context, tenantID string) error // GDPR
	PurgePIITokens(ctx context.Context, olderThan time.Time) (int64, error) // retention
	PIIStats(ctx context.Context, tenantID string) (*Stats, error)
}
