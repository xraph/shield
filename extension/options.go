package extension

import (
	"github.com/xraph/shield/engine"
	"github.com/xraph/shield/plugin"
	"github.com/xraph/shield/store"
)

// Option configures the Shield Forge extension.
type Option func(*Extension)

// WithStore sets the composite store for the engine.
func WithStore(s store.Store) Option {
	return func(e *Extension) {
		e.engineOpts = append(e.engineOpts, engine.WithStore(s))
	}
}

// WithPlugin registers a lifecycle plugin.
func WithPlugin(p plugin.Plugin) Option {
	return func(e *Extension) {
		e.engineOpts = append(e.engineOpts, engine.WithPlugin(p))
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

// WithRequireConfig requires config to be present in YAML files.
// If true and no config is found, Register returns an error.
func WithRequireConfig(require bool) Option {
	return func(e *Extension) { e.config.RequireConfig = require }
}

// WithGroveDatabase sets the name of the grove.DB to resolve from the DI container.
// The extension will auto-construct the appropriate store backend (postgres/sqlite/mongo)
// based on the grove driver type. Pass an empty string to use the default (unnamed) grove.DB.
func WithGroveDatabase(name string) Option {
	return func(e *Extension) {
		e.config.GroveDatabase = name
		e.useGrove = true
	}
}
