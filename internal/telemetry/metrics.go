package telemetry

import (
	"strings"
	"sync"

	gometrics "github.com/xraph/go-utils/metrics"
)

// vec is a metric family with fixed label keys. A child is built on the first
// use of a label tuple and cached, so a repeat call takes no registry lock.
// Callers only pass values from fixed enums, which bounds the cache.
type vec[T any] struct {
	keys  []string
	build func(labels map[string]string) T
	cache sync.Map // joined label values -> T
}

func (v *vec[T]) with(values []string) (T, bool) {
	var zero T
	if len(values) != len(v.keys) {
		return zero, false
	}
	key := strings.Join(values, "\xff")
	if c, ok := v.cache.Load(key); ok {
		child, isT := c.(T)
		return child, isT
	}
	labels := make(map[string]string, len(v.keys))
	for i, k := range v.keys {
		labels[k] = values[i]
	}
	c, _ := v.cache.LoadOrStore(key, v.build(labels))
	child, isT := c.(T)
	return child, isT
}

// CounterVec is a counter with fixed label keys. A nil *CounterVec records
// nothing, which is what NewCounterVec returns for a nil sink.
type CounterVec struct{ v vec[gometrics.Counter] }

// NewCounterVec declares a counter on m. A nil m returns nil.
func NewCounterVec(m gometrics.Metrics, name, help string, keys ...string) *CounterVec {
	if m == nil {
		return nil
	}
	return &CounterVec{v: vec[gometrics.Counter]{keys: keys, build: func(l map[string]string) gometrics.Counter {
		return m.Counter(name, gometrics.WithDescription(help), gometrics.WithLabels(l))
	}}}
}

// Inc adds one to the series for values, given in the declared key order. A
// call with the wrong number of values records nothing.
func (c *CounterVec) Inc(values ...string) {
	if c == nil {
		return
	}
	if child, ok := c.v.with(values); ok {
		child.Inc()
	}
}

// HistogramVec is a histogram with fixed label keys. A nil *HistogramVec
// records nothing, which is what NewHistogramVec returns for a nil sink.
type HistogramVec struct{ v vec[gometrics.Histogram] }

// NewHistogramVec declares a histogram on m with the given unit and buckets.
// A nil m returns nil.
func NewHistogramVec(m gometrics.Metrics, name, help, unit string, buckets []float64, keys ...string) *HistogramVec {
	if m == nil {
		return nil
	}
	return &HistogramVec{v: vec[gometrics.Histogram]{keys: keys, build: func(l map[string]string) gometrics.Histogram {
		return m.Histogram(name,
			gometrics.WithDescription(help),
			gometrics.WithUnit(unit),
			gometrics.WithBuckets(buckets...),
			gometrics.WithLabels(l),
		)
	}}}
}

// Observe records v in the series for values, given in the declared key
// order. A call with the wrong number of values records nothing.
func (h *HistogramVec) Observe(v float64, values ...string) {
	if h == nil {
		return
	}
	if child, ok := h.v.with(values); ok {
		child.Observe(v)
	}
}
