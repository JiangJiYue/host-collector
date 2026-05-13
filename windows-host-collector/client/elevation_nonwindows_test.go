//go:build !windows

package client

import "testing"

func TestEnsureElevatedIsNoopOnNonWindows(t *testing.T) {
	if err := EnsureElevated(); err != nil {
		t.Fatalf("expected EnsureElevated to be a no-op on non-Windows hosts, got %v", err)
	}
}
