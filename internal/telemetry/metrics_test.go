package telemetry

import "testing"

func TestNilVecsRecordNothing(t *testing.T) {
	if NewCounterVec(nil, "c_total", "", "k") != nil || NewHistogramVec(nil, "h_seconds", "", "s", nil, "k") != nil {
		t.Fatal("a nil sink should give a nil vec")
	}
	var c *CounterVec
	var h *HistogramVec
	c.Inc("v")
	h.Observe(1, "v")
}
