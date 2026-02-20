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
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		ShutdownTimeout:    30 * time.Second,
		ScanConcurrency:    10,
		EnableShortCircuit: true,
	}
}
