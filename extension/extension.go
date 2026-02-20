// Package extension provides the Forge extension adapter for Shield.
//
// It implements the forge.Extension interface to integrate Shield
// into a Forge application with automatic dependency discovery,
// route registration, and lifecycle management.
package extension

import (
	"context"
	"log/slog"

	"github.com/xraph/forge"
	"github.com/xraph/vessel"

	"github.com/xraph/shield"
	"github.com/xraph/shield/engine"
	"github.com/xraph/shield/ext"
	"github.com/xraph/shield/store"
)

// Extension is the Forge extension adapter for Shield.
type Extension struct {
	config     Config
	eng        *engine.Engine
	logger     *slog.Logger
	engineOpts []engine.Option
}

// Config holds Forge extension configuration.
type Config struct {
	DisableRoutes  bool   `json:"disable_routes,omitempty"`
	DisableMigrate bool   `json:"disable_migrate,omitempty"`
	BasePath       string `json:"base_path,omitempty"`
}

// Option configures the Forge extension.
type Option func(*Extension)

// New creates a new Forge extension for Shield.
func New(opts ...Option) *Extension {
	e := &Extension{
		logger: slog.Default(),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// WithStore sets the composite store for the engine.
func WithStore(s store.Store) Option {
	return func(e *Extension) {
		e.engineOpts = append(e.engineOpts, engine.WithStore(s))
	}
}

// WithExtension registers a lifecycle extension.
func WithExtension(x ext.Extension) Option {
	return func(e *Extension) {
		e.engineOpts = append(e.engineOpts, engine.WithExtension(x))
	}
}

// WithEngineOption passes an engine option through.
func WithEngineOption(opt engine.Option) Option {
	return func(e *Extension) {
		e.engineOpts = append(e.engineOpts, opt)
	}
}

// WithConfig sets the Forge extension configuration.
func WithConfig(cfg Config) Option {
	return func(e *Extension) { e.config = cfg }
}

// WithLogger sets a custom logger.
func WithLogger(l *slog.Logger) Option {
	return func(e *Extension) {
		e.logger = l
		e.engineOpts = append(e.engineOpts, engine.WithLogger(l))
	}
}

// WithDisableRoutes prevents HTTP route registration.
func WithDisableRoutes() Option {
	return func(e *Extension) { e.config.DisableRoutes = true }
}

// WithDisableMigrate prevents auto-migration on start.
func WithDisableMigrate() Option {
	return func(e *Extension) { e.config.DisableMigrate = true }
}

// WithBasePath sets the URL prefix for shield routes.
func WithBasePath(path string) Option {
	return func(e *Extension) { e.config.BasePath = path }
}

// ── Forge Extension interface ────────────────────────

// Name implements forge.Extension.
func (e *Extension) Name() string { return "shield" }

// Description implements forge.Extension.
func (e *Extension) Description() string {
	return "Human-centric AI safety and governance"
}

// Version implements forge.Extension.
func (e *Extension) Version() string { return shield.Version }

// Dependencies implements forge.Extension.
func (e *Extension) Dependencies() []string { return []string{} }

// Register implements forge.Extension. It initializes the engine and
// registers it in the Forge DI container.
func (e *Extension) Register(fapp forge.App) error {
	eng, err := engine.New(e.engineOpts...)
	if err != nil {
		return err
	}
	e.eng = eng

	// Provide engine for other extensions to use
	return vessel.Provide(fapp.Container(), func() (*engine.Engine, error) {
		return e.eng, nil
	})
}

// Start implements forge.Extension.
func (e *Extension) Start(ctx context.Context) error {
	return nil
}

// Stop implements forge.Extension.
func (e *Extension) Stop(ctx context.Context) error {
	if e.eng != nil {
		return e.eng.Stop(ctx)
	}
	return nil
}

// Health implements forge.Extension.
func (e *Extension) Health(ctx context.Context) error {
	return nil
}
