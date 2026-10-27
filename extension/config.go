package extension

import (
	"time"

	"github.com/xraph/shield"
)

// Config holds the Shield extension configuration.
// Fields can be set programmatically via Option functions or loaded from
// YAML configuration files (under "extensions.shield" or "shield" keys).
type Config struct {
	// DisableRoutes prevents HTTP route registration.
	DisableRoutes bool `json:"disable_routes" mapstructure:"disable_routes" yaml:"disable_routes"`

	// DisableMigrate prevents auto-migration on start.
	DisableMigrate bool `json:"disable_migrate" mapstructure:"disable_migrate" yaml:"disable_migrate"`

	// BasePath is the URL prefix for shield routes (default: "/shield").
	BasePath string `json:"base_path" mapstructure:"base_path" yaml:"base_path"`

	// DefaultProfile is the safety profile to use when none is specified.
	DefaultProfile string `json:"default_profile" mapstructure:"default_profile" yaml:"default_profile"`

	// ShutdownTimeout is the maximum time to wait for graceful shutdown.
	ShutdownTimeout time.Duration `json:"shutdown_timeout" mapstructure:"shutdown_timeout" yaml:"shutdown_timeout"`

	// ScanConcurrency controls how many scan operations can run in parallel.
	ScanConcurrency int `json:"scan_concurrency" mapstructure:"scan_concurrency" yaml:"scan_concurrency"`

	// EnableShortCircuit allows layers to stop execution when a block decision
	// is reached, skipping deeper layers.
	EnableShortCircuit bool `json:"enable_short_circuit" mapstructure:"enable_short_circuit" yaml:"enable_short_circuit"`

	// MaxScanBytes is the largest text a scan accepts (default 1 MiB).
	MaxScanBytes int `json:"max_scan_bytes" mapstructure:"max_scan_bytes" yaml:"max_scan_bytes"`

	// ProfileCacheTTL is how long a compiled safety profile is reused
	// (default 30s). A negative value disables the cache.
	ProfileCacheTTL time.Duration `json:"profile_cache_ttl" mapstructure:"profile_cache_ttl" yaml:"profile_cache_ttl"`

	// StoreRedacted keeps the redacted text on persisted scans.
	StoreRedacted bool `json:"store_redacted" mapstructure:"store_redacted" yaml:"store_redacted"`

	// ModelJudge lets the model assessor call a judge registered through
	// WithEngineOption(engine.WithJudge(...)). Off by default.
	ModelJudge bool `json:"model_judge" mapstructure:"model_judge" yaml:"model_judge"`

	// JudgeTimeout bounds one judge call (default 5s).
	JudgeTimeout time.Duration `json:"judge_timeout" mapstructure:"judge_timeout" yaml:"judge_timeout"`

	// JudgeConcurrency caps the judge calls in flight (default 8).
	JudgeConcurrency int `json:"judge_concurrency" mapstructure:"judge_concurrency" yaml:"judge_concurrency"`

	// GroveDatabase is the name of a grove.DB registered in the DI container.
	// When set, the extension resolves this named database and auto-constructs
	// the appropriate store based on the driver type (pg/sqlite/mongo).
	// When empty and WithGroveDatabase was called, the default (unnamed) DB is used.
	GroveDatabase string `json:"grove_database" mapstructure:"grove_database" yaml:"grove_database"`

	// RequireConfig requires config to be present in YAML files.
	// If true and no config is found, Register returns an error.
	RequireConfig bool `json:"-" yaml:"-"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		ShutdownTimeout:    30 * time.Second,
		ScanConcurrency:    10,
		EnableShortCircuit: true,
		MaxScanBytes:       shield.DefaultMaxScanBytes,
		ProfileCacheTTL:    shield.DefaultProfileCacheTTL,
		JudgeTimeout:       shield.DefaultJudgeTimeout,
		JudgeConcurrency:   shield.DefaultJudgeConcurrency,
	}
}
