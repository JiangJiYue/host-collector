package contracts

import (
	"errors"
	"testing"
)

func TestClassifiedErrorWrapsCodeAndCause(t *testing.T) {
	cause := errors.New("permission denied")
	err := NewCollectorError(ErrorPermissionDenied, "cannot read auth log", cause)

	if err.Code != ErrorPermissionDenied {
		t.Fatalf("expected permission code, got %s", err.Code)
	}
	if !errors.Is(err, cause) {
		t.Fatalf("expected wrapped cause")
	}
	if err.Error() != "permission_denied: cannot read auth log: permission denied" {
		t.Fatalf("unexpected error string: %s", err.Error())
	}
}
