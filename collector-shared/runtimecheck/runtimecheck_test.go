package runtimecheck

import (
	"errors"
	"strings"
	"testing"

	"collector-shared/contracts"
)

func TestRequireRootAllowsUIDZero(t *testing.T) {
	result := RequireRoot(0)

	if !result.Allowed || result.Reason != ReasonRootPresent {
		t.Fatalf("expected root to be allowed, got %#v", result)
	}
	if err := result.Err(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestRequireRootRejectsNonZeroUIDWithPermissionError(t *testing.T) {
	result := RequireRoot(1000)

	if result.Allowed {
		t.Fatalf("expected non-root uid to be rejected")
	}
	if result.Requirement != RequirementRoot || result.Reason != ReasonRootRequired {
		t.Fatalf("unexpected rejection metadata: %#v", result)
	}
	err := result.Err()
	if err == nil {
		t.Fatalf("expected permission error")
	}
	var collectorErr *contracts.CollectorError
	if !errors.As(err, &collectorErr) {
		t.Fatalf("expected collector error, got %T %v", err, err)
	}
	if collectorErr.Code != contracts.ErrorPermissionDenied {
		t.Fatalf("expected permission_denied code, got %s", collectorErr.Code)
	}
	if !strings.Contains(err.Error(), "uid=0") {
		t.Fatalf("expected uid=0 in error, got %v", err)
	}
}

func TestRequireAdministratorRejectsNonElevatedProcess(t *testing.T) {
	result := RequireAdministrator(false)

	if result.Allowed {
		t.Fatalf("expected non-administrator process to be rejected")
	}
	if result.Requirement != RequirementAdministrator || result.Reason != ReasonAdministratorRequired {
		t.Fatalf("unexpected rejection metadata: %#v", result)
	}
	if err := result.Err(); err == nil || !strings.Contains(err.Error(), "Administrator") {
		t.Fatalf("expected administrator error, got %v", err)
	}
}

func TestRequireAdministratorAllowsElevatedProcess(t *testing.T) {
	result := RequireAdministrator(true)

	if !result.Allowed || result.Reason != ReasonAdministratorPresent {
		t.Fatalf("expected administrator to be allowed, got %#v", result)
	}
}
