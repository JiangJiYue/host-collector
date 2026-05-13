package scanner

import "testing"

func TestDeriveExecutionProfileForWindowsCapsDetailWorkers(t *testing.T) {
	profile := deriveExecutionProfileFor(16, "windows")
	if profile.ProcessDetailWorkers != 2 {
		t.Fatalf("expected windows worker cap of 2, got %d", profile.ProcessDetailWorkers)
	}
}

func TestDeriveExecutionProfileForLinuxKeepsAdaptiveWorkers(t *testing.T) {
	profile := deriveExecutionProfileFor(16, "linux")
	if profile.ProcessDetailWorkers != 8 {
		t.Fatalf("expected linux worker cap of 8, got %d", profile.ProcessDetailWorkers)
	}
}

func TestDeriveExecutionProfileDoesNotDisableDeepCollectionForSmallHosts(t *testing.T) {
	profile := deriveExecutionProfileFor(2, "windows")
	if !profile.AllowDeepRegistry {
		t.Fatalf("expected deep registry collection to remain enabled")
	}
}
