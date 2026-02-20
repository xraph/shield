package shield

import "errors"

// Sentinel errors for the Shield library.
var (
	// Store errors.
	ErrNoStore       = errors.New("shield: no store configured")
	ErrStoreClosed   = errors.New("shield: store is closed")
	ErrMigrateFailed = errors.New("shield: migration failed")

	// Entity not-found errors.
	ErrScanNotFound       = errors.New("shield: scan not found")
	ErrPolicyNotFound     = errors.New("shield: policy not found")
	ErrInstinctNotFound   = errors.New("shield: instinct not found")
	ErrJudgmentNotFound   = errors.New("shield: judgment not found")
	ErrAwarenessNotFound  = errors.New("shield: awareness not found")
	ErrValueNotFound      = errors.New("shield: value not found")
	ErrReflexNotFound     = errors.New("shield: reflex not found")
	ErrBoundaryNotFound   = errors.New("shield: boundary not found")
	ErrProfileNotFound    = errors.New("shield: safety profile not found")
	ErrPIITokenNotFound   = errors.New("shield: pii token not found")
	ErrComplianceNotFound = errors.New("shield: compliance report not found")

	// Duplicate errors.
	ErrAlreadyExists = errors.New("shield: entity already exists")

	// Scan errors.
	ErrInputBlocked  = errors.New("shield: input blocked by safety scan")
	ErrOutputBlocked = errors.New("shield: output blocked by safety scan")

	// Engine errors.
	ErrNoProfile     = errors.New("shield: no safety profile configured")
	ErrInvalidConfig = errors.New("shield: invalid configuration")

	// PII errors.
	ErrEncryptionKeyMissing = errors.New("shield: pii encryption key not configured")

	// State errors.
	ErrInvalidState = errors.New("shield: invalid state transition")
)
