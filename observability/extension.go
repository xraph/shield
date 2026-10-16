// Package observability used to hold Shield's metrics plugin.
//
// Deprecated: the engine records its own metrics now, labelled by direction,
// decision and hook. Pass engine.WithMetrics, or let the Forge extension pass
// app.Metrics() for you, and drop this plugin. It implements no hooks and
// records nothing. The dotted counters it used to declare
// (shield.scan.started and the rest) are gone.
package observability

import (
	gu "github.com/xraph/go-utils/metrics"

	"github.com/xraph/shield/plugin"
)

var _ plugin.Plugin = (*MetricsExtension)(nil)

// MetricsExtension is a plugin that implements no hooks.
//
// Deprecated: use engine.WithMetrics. The Forge extension wires app.Metrics()
// into the engine without it.
type MetricsExtension struct{}

// NewMetricsExtension returns a plugin that records nothing.
//
// Deprecated: use engine.WithMetrics.
func NewMetricsExtension() *MetricsExtension { return &MetricsExtension{} }

// NewMetricsExtensionWithFactory returns a plugin that records nothing. The
// factory is ignored.
//
// Deprecated: use engine.WithMetrics with the same metrics.
func NewMetricsExtensionWithFactory(_ gu.MetricFactory) *MetricsExtension {
	return &MetricsExtension{}
}

// Name implements plugin.Plugin.
func (m *MetricsExtension) Name() string { return "observability-metrics" }
