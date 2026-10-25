package scoring_test

import (
	"math"
	"testing"

	"github.com/xraph/shield/internal/scoring"
)

func TestNoisyOr(t *testing.T) {
	cases := []struct {
		name    string
		weights []float64
		want    float64
	}{
		{"none", nil, 0},
		{"one", []float64{0.7}, 0.7},
		{"two", []float64{0.9, 0.8}, 0.98},
		{"three halves", []float64{0.5, 0.5, 0.5}, 0.875},
		{"certain", []float64{0.3, 1}, 1},
		{"clamped", []float64{-1, 2}, 1},
		{"nan ignored", []float64{math.NaN(), 0.5}, 0.5},
	}
	for _, tc := range cases {
		if got := scoring.NoisyOr(tc.weights...); math.Abs(got-tc.want) > 1e-9 {
			t.Errorf("%s: NoisyOr(%v) = %v, want %v", tc.name, tc.weights, got, tc.want)
		}
	}
}
