package telemetry

import (
	"errors"
	"fmt"
	"io/fs"
	"testing"
)

type codedError struct{}

func (*codedError) Error() string { return "coded" }

func TestErrorTypeNamesTheInnermostError(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{errors.New("x"), "*errors.errorString"},
		{fmt.Errorf("outer: %w", &codedError{}), "*telemetry.codedError"},
		{fmt.Errorf("a: %w", fmt.Errorf("b: %w", fs.ErrNotExist)), "*errors.errorString"},
	} {
		if got := ErrorType(tc.err); got != tc.want {
			t.Errorf("ErrorType(%v) = %s, want %s", tc.err, got, tc.want)
		}
	}
}
