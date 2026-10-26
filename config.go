package shield

import "time"

// Config holds global configuration for the Shield engine.
type Config struct {
	// DefaultProfile is the safety profile to use when none is specified.
	DefaultProfile string `json:"default_profile,omitempty"`

	// ShutdownTimeout is the maximum time to wait for graceful shutdown.
	ShutdownTimeout time.Duration `json:"shutdown_timeout,omitempty"`

	// ScanConcurrency controls how many scan operations can run in parallel.
	ScanConcurrency int `json:"scan_concurrency,omitempty"`

	// EnableShortCircuit allows layers to stop execution when a block decision
	// is reached, skipping deeper layers. Enabled by default.
	EnableShortCircuit bool `json:"enable_short_circuit,omitempty"`

	// MaxScanBytes is the largest text a scan accepts. A longer text fails
	// with ErrInputTooLarge before any layer runs. Zero means 1 MiB.
	MaxScanBytes int `json:"max_scan_bytes,omitempty"`

	// ProfileCacheTTL is how long a compiled safety profile is reused before
	// it is loaded again. Zero means 30 seconds; a negative value disables
	// the cache, so every scan loads its profile.
	ProfileCacheTTL time.Duration `json:"profile_cache_ttl,omitempty"`

	// StoreRedacted keeps Result.Redacted on persisted scans. By default the
	// stored row drops it.
	StoreRedacted bool `json:"store_redacted,omitempty"`

	// ModelJudge lets a judgment's model assessor call the judge registered
	// with engine.WithJudge. It is off by default, and a decision never
	// needs it: the judge can only raise a judgment's risk.
	ModelJudge bool `json:"model_judge,omitempty"`

	// JudgeTimeout bounds one judge call. Zero means 5 seconds.
	JudgeTimeout time.Duration `json:"judge_timeout,omitempty"`
}

// Defaults for the scan limits.
const (
	DefaultMaxScanBytes    = 1 << 20
	DefaultProfileCacheTTL = 30 * time.Second
	DefaultJudgeTimeout    = 5 * time.Second
)

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		ShutdownTimeout:    30 * time.Second,
		ScanConcurrency:    10,
		EnableShortCircuit: true,
		MaxScanBytes:       DefaultMaxScanBytes,
		ProfileCacheTTL:    DefaultProfileCacheTTL,
		JudgeTimeout:       DefaultJudgeTimeout,
	}
}
