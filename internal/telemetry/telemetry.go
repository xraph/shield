// Package telemetry holds the tracing helpers the engine, the plugin
// registry and the admin service share.
//
// Spans go to the global OpenTelemetry tracer provider, which forge.New
// installs.
package telemetry

import (
	"errors"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// ScopeName is the instrumentation scope on every span shield starts.
const ScopeName = "github.com/xraph/shield"

// Tracer returns shield's tracer from the global provider. It is looked up on
// each call, so a provider installed after shield was built still applies.
func Tracer() trace.Tracer { return otel.Tracer(ScopeName) }

// Fail marks span as failed. class is a short, fixed description such as
// "audit_failed". The exception event carries only the error's Go type: error
// messages from drivers and host adapters can quote the values they failed
// on, so they never go on a span.
func Fail(span trace.Span, class string, err error) {
	span.SetStatus(codes.Error, class)
	Exception(span, err)
}

// Exception adds an exception event that carries only the error's Go type,
// for a failure that doesn't fail the span as a whole.
func Exception(span trace.Span, err error) {
	span.AddEvent("exception", trace.WithAttributes(attribute.String("exception.type", ErrorType(err))))
}

// ErrorType returns the Go type of the innermost error in err's chain, the
// value for the exception.type attribute.
func ErrorType(err error) string {
	for {
		next := errors.Unwrap(err)
		if next == nil {
			return fmt.Sprintf("%T", err)
		}
		err = next
	}
}
