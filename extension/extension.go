// Package extension provides the Forge extension adapter for Shield.
//
// It implements the forge.Extension interface to integrate Shield
// into a Forge application with automatic dependency discovery,
// route registration, and lifecycle management.
//
// Configuration can be provided programmatically via Option functions
// or via YAML configuration files under "extensions.shield" or "shield" keys.
package extension

import (
	"context"
	"errors"
	"fmt"

	"github.com/xraph/forge"
	"github.com/xraph/grove"
	"github.com/xraph/vessel"

	"github.com/xraph/shield/engine"
	"github.com/xraph/shield/store"
	mongostore "github.com/xraph/shield/store/mongo"
	pgstore "github.com/xraph/shield/store/postgres"
	sqlitestore "github.com/xraph/shield/store/sqlite"
)

// ExtensionName is the name registered with Forge.
const ExtensionName = "shield"

// ExtensionDescription is the human-readable description.
const ExtensionDescription = "Human-centric AI safety and governance"

// ExtensionVersion is the semantic version.
const ExtensionVersion = "0.1.0"

// Ensure Extension implements forge.Extension at compile time.
var _ forge.Extension = (*Extension)(nil)

// Extension adapts Shield as a Forge extension.
type Extension struct {
	*forge.BaseExtension

	config     Config
	eng        *engine.Engine
	engineOpts []engine.Option
	useGrove   bool
}

// New creates a new Shield Forge extension with the given options.
func New(opts ...Option) *Extension {
	e := &Extension{
		BaseExtension: forge.NewBaseExtension(ExtensionName, ExtensionVersion, ExtensionDescription),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Engine returns the underlying Shield engine.
// This is nil until Register is called.
func (e *Extension) Engine() *engine.Engine { return e.eng }

// Register implements [forge.Extension]. It loads configuration,
// initializes the engine, and registers it in the DI container.
func (e *Extension) Register(fapp forge.App) error {
	if err := e.BaseExtension.Register(fapp); err != nil {
		return err
	}

	if err := e.loadConfiguration(); err != nil {
		return err
	}

	// Resolve store from grove DI if configured.
	if e.useGrove {
		groveDB, err := e.resolveGroveDB(fapp)
		if err != nil {
			return fmt.Errorf("shield: %w", err)
		}
		s, err := e.buildStoreFromGroveDB(groveDB)
		if err != nil {
			return err
		}
		e.engineOpts = append(e.engineOpts, engine.WithStore(s))
	}

	eng, err := engine.New(e.engineOpts...)
	if err != nil {
		return err
	}
	e.eng = eng

	return vessel.Provide(fapp.Container(), func() (*engine.Engine, error) {
		return e.eng, nil
	})
}

// Start implements [forge.Extension].
func (e *Extension) Start(_ context.Context) error {
	e.MarkStarted()
	return nil
}

// Stop implements [forge.Extension].
func (e *Extension) Stop(ctx context.Context) error {
	if e.eng != nil {
		if err := e.eng.Stop(ctx); err != nil {
			e.MarkStopped()
			return err
		}
	}
	e.MarkStopped()
	return nil
}

// Health implements [forge.Extension].
func (e *Extension) Health(_ context.Context) error {
	return nil
}

// --- Config Loading (mirrors grove extension pattern) ---

// loadConfiguration loads config from YAML files or programmatic sources.
func (e *Extension) loadConfiguration() error {
	programmaticConfig := e.config

	// Try loading from config file.
	fileConfig, configLoaded := e.tryLoadFromConfigFile()

	if !configLoaded {
		if programmaticConfig.RequireConfig {
			return errors.New("shield: configuration is required but not found in config files; " +
				"ensure 'extensions.shield' or 'shield' key exists in your config")
		}

		// Use programmatic config merged with defaults.
		e.config = e.mergeWithDefaults(programmaticConfig)
	} else {
		// Config loaded from YAML — merge with programmatic options.
		e.config = e.mergeConfigurations(fileConfig, programmaticConfig)
	}

	// Enable grove resolution if YAML config specifies a grove database.
	if e.config.GroveDatabase != "" {
		e.useGrove = true
	}

	e.Logger().Debug("shield: configuration loaded",
		forge.F("disable_routes", e.config.DisableRoutes),
		forge.F("disable_migrate", e.config.DisableMigrate),
		forge.F("base_path", e.config.BasePath),
		forge.F("grove_database", e.config.GroveDatabase),
	)

	return nil
}

// tryLoadFromConfigFile attempts to load config from YAML files.
func (e *Extension) tryLoadFromConfigFile() (Config, bool) {
	cm := e.App().Config()
	var cfg Config

	// Try "extensions.shield" first (namespaced pattern).
	if cm.IsSet("extensions.shield") {
		if err := cm.Bind("extensions.shield", &cfg); err == nil {
			e.Logger().Debug("shield: loaded config from file",
				forge.F("key", "extensions.shield"),
			)
			return cfg, true
		}
		e.Logger().Warn("shield: failed to bind extensions.shield config",
			forge.F("error", "bind failed"),
		)
	}

	// Try legacy "shield" key.
	if cm.IsSet("shield") {
		if err := cm.Bind("shield", &cfg); err == nil {
			e.Logger().Debug("shield: loaded config from file",
				forge.F("key", "shield"),
			)
			return cfg, true
		}
		e.Logger().Warn("shield: failed to bind shield config",
			forge.F("error", "bind failed"),
		)
	}

	return Config{}, false
}

// mergeWithDefaults fills zero-valued fields with defaults.
func (e *Extension) mergeWithDefaults(cfg Config) Config {
	defaults := DefaultConfig()
	if cfg.ShutdownTimeout == 0 {
		cfg.ShutdownTimeout = defaults.ShutdownTimeout
	}
	if cfg.ScanConcurrency == 0 {
		cfg.ScanConcurrency = defaults.ScanConcurrency
	}
	return cfg
}

// mergeConfigurations merges YAML config with programmatic options.
// YAML config takes precedence for most fields; programmatic bool flags fill gaps.
func (e *Extension) mergeConfigurations(yamlConfig, programmaticConfig Config) Config {
	// Programmatic bool flags override when true.
	if programmaticConfig.DisableRoutes {
		yamlConfig.DisableRoutes = true
	}
	if programmaticConfig.DisableMigrate {
		yamlConfig.DisableMigrate = true
	}
	if programmaticConfig.EnableShortCircuit {
		yamlConfig.EnableShortCircuit = true
	}

	// String fields: YAML takes precedence.
	if yamlConfig.BasePath == "" && programmaticConfig.BasePath != "" {
		yamlConfig.BasePath = programmaticConfig.BasePath
	}
	if yamlConfig.GroveDatabase == "" && programmaticConfig.GroveDatabase != "" {
		yamlConfig.GroveDatabase = programmaticConfig.GroveDatabase
	}
	if yamlConfig.DefaultProfile == "" && programmaticConfig.DefaultProfile != "" {
		yamlConfig.DefaultProfile = programmaticConfig.DefaultProfile
	}

	// Duration/int fields: YAML takes precedence, programmatic fills gaps.
	if yamlConfig.ShutdownTimeout == 0 && programmaticConfig.ShutdownTimeout != 0 {
		yamlConfig.ShutdownTimeout = programmaticConfig.ShutdownTimeout
	}
	if yamlConfig.ScanConcurrency == 0 && programmaticConfig.ScanConcurrency != 0 {
		yamlConfig.ScanConcurrency = programmaticConfig.ScanConcurrency
	}

	// Fill remaining zeros with defaults.
	return e.mergeWithDefaults(yamlConfig)
}

// resolveGroveDB resolves a *grove.DB from the DI container.
// If GroveDatabase is set, it looks up the named DB; otherwise it uses the default.
func (e *Extension) resolveGroveDB(fapp forge.App) (*grove.DB, error) {
	if e.config.GroveDatabase != "" {
		db, err := vessel.InjectNamed[*grove.DB](fapp.Container(), e.config.GroveDatabase)
		if err != nil {
			return nil, fmt.Errorf("grove database %q not found in container: %w", e.config.GroveDatabase, err)
		}
		return db, nil
	}
	db, err := vessel.Inject[*grove.DB](fapp.Container())
	if err != nil {
		return nil, fmt.Errorf("default grove database not found in container: %w", err)
	}
	return db, nil
}

// buildStoreFromGroveDB constructs the appropriate store backend
// based on the grove driver type (pg, sqlite, mongo).
func (e *Extension) buildStoreFromGroveDB(db *grove.DB) (store.Store, error) {
	driverName := db.Driver().Name()
	switch driverName {
	case "pg":
		return pgstore.New(db), nil
	case "sqlite":
		return sqlitestore.New(db), nil
	case "mongo":
		return mongostore.New(db), nil
	default:
		return nil, fmt.Errorf("shield: unsupported grove driver %q", driverName)
	}
}
