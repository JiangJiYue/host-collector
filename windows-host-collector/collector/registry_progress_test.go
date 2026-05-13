package collector

import "testing"

func TestRegistryProgressStateReportsEveryInterval(t *testing.T) {
	state := newRegistryProgressState("HKEY_LOCAL_MACHINE", 2, 5, 3)
	if state.ShouldReport() {
		t.Fatal("did not expect report before any values are read")
	}

	state.ValuesRead = 3
	if !state.ShouldReport() {
		t.Fatal("expected report when interval is reached")
	}

	state.MarkReported()
	if state.ShouldReport() {
		t.Fatal("did not expect duplicate report at same count")
	}

	state.ValuesRead = 6
	if !state.ShouldReport() {
		t.Fatal("expected report at next interval boundary")
	}
}

func TestRegistryCollectorReportsProgressCallback(t *testing.T) {
	var got RegistryProgress
	called := false

	collector := NewRegistryCollector().WithProgress(func(progress RegistryProgress) {
		called = true
		got = progress
	})

	collector.report(RegistryProgress{
		RootName:   "HKEY_USERS",
		RootsDone:  3,
		RootsTotal: 5,
		ValuesRead: 12000,
	})

	if !called {
		t.Fatal("expected progress callback to be invoked")
	}
	if got.RootName != "HKEY_USERS" {
		t.Fatalf("expected root name to be preserved, got %q", got.RootName)
	}
	if got.ValuesRead != 12000 {
		t.Fatalf("expected values read to be preserved, got %d", got.ValuesRead)
	}
}
