//go:build windows

package collector

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestDiscoverChromiumProfiles(t *testing.T) {
	root := t.TempDir()
	mustMkdirAll(t, filepath.Join(root, "Default"))
	mustMkdirAll(t, filepath.Join(root, "Profile 1"))
	mustMkdirAll(t, filepath.Join(root, "System Profile"))
	mustWriteFile(t, filepath.Join(root, "Profile 1", "History"), []byte("history"))
	mustWriteFile(t, filepath.Join(root, "Default", "History"), []byte("history"))

	got := discoverChromiumProfiles(root, "History")
	sort.Strings(got)

	want := []string{
		filepath.Join(root, "Default"),
		filepath.Join(root, "Profile 1"),
	}

	if len(got) != len(want) {
		t.Fatalf("expected %d profiles, got %d: %v", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected profile %q at index %d, got %q", want[i], i, got[i])
		}
	}
}

func TestDiscoverFirefoxProfiles(t *testing.T) {
	root := t.TempDir()
	mustMkdirAll(t, filepath.Join(root, "abc.default-release"))
	mustMkdirAll(t, filepath.Join(root, "orphan.default"))
	mustWriteFile(t, filepath.Join(root, "abc.default-release", "places.sqlite"), []byte("sqlite"))

	got := discoverFirefoxProfiles(root, "places.sqlite")
	if len(got) != 1 {
		t.Fatalf("expected 1 firefox profile, got %d: %v", len(got), got)
	}
	if got[0] != filepath.Join(root, "abc.default-release") {
		t.Fatalf("unexpected firefox profile: %q", got[0])
	}
}

func TestDiscoverProfilesMissingRoot(t *testing.T) {
	got := discoverChromiumProfiles(filepath.Join(t.TempDir(), "missing"), "History")
	if len(got) != 0 {
		t.Fatalf("expected no profiles for missing root, got %v", got)
	}
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func mustWriteFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
