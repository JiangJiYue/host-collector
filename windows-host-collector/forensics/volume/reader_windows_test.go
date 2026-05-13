//go:build windows

package volume

import "testing"

func TestNormalizeVolumePath(t *testing.T) {
	got, err := NormalizeVolumePath("C")
	if err != nil {
		t.Fatalf("NormalizeVolumePath() error = %v", err)
	}
	if got != `\\.\C:` {
		t.Fatalf("expected normalized path, got %q", got)
	}
}

func TestNormalizeVolumePathAcceptsDriveWithBackslash(t *testing.T) {
	got, err := NormalizeVolumePath(`C:\`)
	if err != nil {
		t.Fatalf("NormalizeVolumePath() error = %v", err)
	}
	if got != `\\.\C:` {
		t.Fatalf("expected normalized path, got %q", got)
	}
}
