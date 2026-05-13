package hash

import "testing"

func TestDefaultPolicySkipsDirectories(t *testing.T) {
	decision := DefaultPolicy().Decide(0, true)
	if decision.State != StateSkippedDirectory {
		t.Fatalf("expected %q, got %q", StateSkippedDirectory, decision.State)
	}
	if len(decision.Algorithms) != 0 {
		t.Fatalf("expected no algorithms, got %#v", decision.Algorithms)
	}
}

func TestDefaultPolicySkipsOversizedFiles(t *testing.T) {
	policy := DefaultPolicy()
	decision := policy.Decide(policy.MaxBytes+1, false)
	if decision.State != StateSkippedTooLarge {
		t.Fatalf("expected %q, got %q", StateSkippedTooLarge, decision.State)
	}
}

func TestDefaultPolicyHashesRegularFiles(t *testing.T) {
	decision := DefaultPolicy().Decide(1024, false)
	if decision.State != StatePending {
		t.Fatalf("expected %q, got %q", StatePending, decision.State)
	}
	if len(decision.Algorithms) != 3 {
		t.Fatalf("expected 3 algorithms, got %#v", decision.Algorithms)
	}
}
