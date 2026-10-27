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

func TestNoisyOrIsOrderIndependent(t *testing.T) {
	ws := []float64{0.9, 0.7, 0.8, 0.6, 0.65, 0.33}
	want := scoring.NoisyOr(ws...)
	for i := range len(ws) {
		rotated := append(append([]float64{}, ws[i:]...), ws[:i]...)
		if got := scoring.NoisyOr(rotated...); got != want {
			t.Fatalf("NoisyOr(%v) = %v, want exactly %v", rotated, got, want)
		}
	}
	if ws[0] != 0.9 {
		t.Fatal("NoisyOr reordered its input")
	}
}

func TestMaxPerKey(t *testing.T) {
	m := scoring.MaxPerKey[string]{}
	m.Add("override", 0.9)
	m.Add("override", 0.5)
	m.Add("role", 0.7)
	m.Add("role", math.NaN())
	if len(m) != 2 || m["override"] != 0.9 || m["role"] != 0.7 {
		t.Fatalf("MaxPerKey = %v", m)
	}
	if got, want := m.NoisyOr(), 1-(0.1*0.3); math.Abs(got-want) > 1e-9 {
		t.Fatalf("NoisyOr() = %v, want %v", got, want)
	}
	if got := (scoring.MaxPerKey[string]{}).NoisyOr(); got != 0 {
		t.Fatalf("empty NoisyOr() = %v", got)
	}
}
