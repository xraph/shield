package engine

import "context"

// runBoundaries is layer 3: hard topic, action and data limits.
// It does nothing yet; the compiled profile already carries its rows.
func (*Engine) runBoundaries(context.Context, *evaluation) {}
