// Package scoring holds the score arithmetic the detectors and engine layers
// share, so every caller combines independent signals the same way.
package scoring

import (
	"math"
	"slices"
)

// NoisyOr combines independent signal weights as 1 - Π(1 - w). Each weight is
// clamped to [0, 1] and NaN counts as 0, so the result is always in [0, 1]. No
// weights give 0. The weights are multiplied in sorted order, so the result
// does not depend on the order they come in (a map's, say) down to the last
// bit.
func NoisyOr(weights ...float64) float64 {
	sorted := slices.Clone(weights)
	slices.Sort(sorted)
	miss := 1.0
	for _, w := range sorted {
		switch {
		case math.IsNaN(w) || w <= 0:
			continue
		case w >= 1:
			return 1
		}
		miss *= 1 - w
	}
	return 1 - miss
}

// MaxPerKey keeps the highest weight seen for each key, so a signal that
// fires many times counts once. Its NoisyOr is the score of a set of
// detections: noisy-or over distinct keys, each at its highest weight.
type MaxPerKey[K comparable] map[K]float64

// Add records weight w for key. NaN is ignored.
func (m MaxPerKey[K]) Add(key K, w float64) {
	if math.IsNaN(w) {
		return
	}
	if old, ok := m[key]; !ok || w > old {
		m[key] = w
	}
}

// NoisyOr combines the per-key maxima.
func (m MaxPerKey[K]) NoisyOr() float64 {
	ws := make([]float64, 0, len(m))
	for _, w := range m {
		ws = append(ws, w)
	}
	return NoisyOr(ws...)
}
