// Package store defines the composite store interface for Shield.
//
// The composite store composes all subsystem store interfaces into a
// single interface. Implementations (Postgres, SQLite, Memory) satisfy
// the composite.
package store

import (
	"context"

	"github.com/xraph/shield/awareness"
	"github.com/xraph/shield/boundary"
	"github.com/xraph/shield/compliance"
	"github.com/xraph/shield/instinct"
	"github.com/xraph/shield/judgment"
	"github.com/xraph/shield/pii"
	"github.com/xraph/shield/policy"
	"github.com/xraph/shield/profile"
	"github.com/xraph/shield/reflex"
	"github.com/xraph/shield/scan"
	"github.com/xraph/shield/values"
)

// Store is the composite store interface that combines all subsystem stores.
type Store interface {
	instinct.Store
	awareness.Store
	boundary.Store
	values.Store
	judgment.Store
	reflex.Store
	profile.Store
	scan.Store
	policy.Store
	pii.Store
	compliance.Store

	// Migrate runs database migrations.
	Migrate(ctx context.Context) error

	// Ping verifies the store connection is alive.
	Ping(ctx context.Context) error

	// Close releases store resources.
	Close() error
}
