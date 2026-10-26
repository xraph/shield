package engine

import "context"

// runValues is layer 4: ethical rules such as toxicity and brand safety.
// It does nothing yet; the compiled profile already carries its rows.
func (*Engine) runValues(context.Context, *evaluation) {}
