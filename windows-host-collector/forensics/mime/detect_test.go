package mime

import "testing"

func TestDetectPortableExecutableByMagic(t *testing.T) {
	got := Detect("cmd.exe", []byte("MZ\x90\x00\x03\x00\x00\x00"))
	if got != "application/vnd.microsoft.portable-executable" {
		t.Fatalf("expected PE mime type, got %q", got)
	}
}

func TestDetectFallsBackToExtension(t *testing.T) {
	got := Detect("report.json", []byte("{}"))
	if got != "application/json" {
		t.Fatalf("expected JSON mime type, got %q", got)
	}
}
