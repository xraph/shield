// Package shield provides composable AI safety and governance for Go.
//
// Shield models safety through human-centric primitives: Instincts, Awareness,
// Boundaries, Values, Judgment, and Reflexes — composed into SafetyProfiles.
package shield

import "time"

// Entity is the base type embedded by all Shield domain objects.
// It provides automatic timestamp tracking.
type Entity struct {
	CreatedAt time.Time `json:"created_at" bun:",nullzero,notnull,default:current_timestamp"`
	UpdatedAt time.Time `json:"updated_at" bun:",nullzero,notnull,default:current_timestamp"`
}
