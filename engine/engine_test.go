package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/xraph/shield/store"
)

type failedStore struct{ store.Store }

func (failedStore) Ping(context.Context) error { return errors.New("database offline") }

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
