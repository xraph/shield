package audithook

import "log/slog"

// Option configures an audit hook Extension.
type Option func(*Extension)

// WithActions limits audit emission to the specified actions only.
// By default all actions are enabled.
func WithActions(actions ...string) Option {
	return func(e *Extension) {
		e.enabled = make(map[string]bool, len(actions))
		for _, a := range actions {
			e.enabled[a] = true
		}
	}
}

// WithLogger sets a custom logger for the audit extension.
func WithLogger(l *slog.Logger) Option {
	return func(e *Extension) {
		e.logger = l
	}
}
