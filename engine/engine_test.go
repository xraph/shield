package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/xraph/shield/scan"
	"github.com/xraph/shield/store"
)

type failedStore struct{ store.Store }

func (failedStore) Ping(context.Context) error { return errors.New("database offline") }
func TestCurrentScanHasNoEvaluationFindings(t *testing.T) {
	e, _ := New()
	r, err := e.ScanInput(context.Background(), &scan.Input{Text: "example"})
	if err != nil || r.Decision != scan.DecisionAllow || len(r.Findings) != 0 {
		t.Fatalf("recorded limitation changed: %+v %v", r, err)
	}
}
func TestCapabilitiesReportUnavailableEvaluation(t *testing.T) {
	e, _ := New()
	c := e.Capabilities()
	if c.Evaluation || c.Persistence || len(c.Layers) != 6 {
		t.Fatalf("unexpected capabilities: %+v", c)
	}
	if e.Config().ScanConcurrency != 10 {
		t.Fatal("effective default config missing")
	}
}
func TestHealthRefusesMissingAndFailedStore(t *testing.T) {
	e, _ := New()
	if e.Health(context.Background()) == nil {
		t.Fatal("missing storage reported healthy")
	}
	e, _ = New(WithStore(failedStore{}))
	if e.Health(context.Background()) == nil {
		t.Fatal("failed storage reported healthy")
	}
}
