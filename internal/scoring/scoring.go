// Package scoring holds the score arithmetic the detectors and engine layers
// share, so every caller combines independent signals the same way.
package scoring

import "math"

// NoisyOr combines independent signal weights as 1 - Π(1 - w). Each weight is
// clamped to [0, 1] and NaN counts as 0, so the result is always in [0, 1]. No
// weights give 0.
func NoisyOr(weights ...float64) float64 {
	miss := 1.0
	for _, w := range weights {
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
