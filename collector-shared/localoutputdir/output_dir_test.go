package localoutputdir

import (
	"path/filepath"
	"testing"
)

func TestResolveCreatesScanSubdirectoryForDot(t *testing.T) {
	cwd, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("resolve cwd: %v", err)
	}

	got := Resolve(".", "scan-1")

	if got != filepath.Join(cwd, "host-collector-scan-1") {
		t.Fatalf("unexpected dot output dir: %q", got)
	}
}

func TestResolveCreatesScanSubdirectoryForDotSlash(t *testing.T) {
	cwd, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("resolve cwd: %v", err)
	}

	got := Resolve("./", "scan-1")

	if got != filepath.Join(cwd, "host-collector-scan-1") {
		t.Fatalf("unexpected dot slash output dir: %q", got)
	}
}

func TestResolvePreservesNamedDirectory(t *testing.T) {
	got := Resolve("./out", "scan-1")

	if got != "./out" {
		t.Fatalf("named output dir should be preserved, got %q", got)
	}
}
