package capabilities

import (
	"os"
	"path/filepath"
	"testing"

	"collector-shared/contracts"
)

func TestDetectLinuxCapabilitiesFromFixtureRoot(t *testing.T) {
	root := filepath.Join("testdata", "ubuntu")
	result, err := Detect(root, "amd64")
	if err != nil {
		t.Fatalf("detect capabilities: %v", err)
	}

	if result.Facts.Platform != contracts.PlatformLinux {
		t.Fatalf("expected linux platform, got %#v", result.Facts)
	}
	if result.Facts.OSName != "Ubuntu" || result.Facts.OSVersion != "24.04" {
		t.Fatalf("expected Ubuntu facts, got %#v", result.Facts)
	}
	if result.Facts.Architecture != contracts.ArchitectureAMD64 {
		t.Fatalf("expected amd64 architecture, got %#v", result.Facts)
	}
	if result.Facts.Extensions.Linux["distroId"] != "ubuntu" {
		t.Fatalf("expected distro id in linux extensions, got %#v", result.Facts.Extensions)
	}
	if result.Facts.Extensions.Linux["buildFamily"] != "ubuntu" {
		t.Fatalf("expected ubuntu build family, got %#v", result.Facts.Extensions.Linux)
	}
	if !result.Capabilities.Supports(contracts.CapabilityProcfsRead) {
		t.Fatalf("expected procfs capability")
	}
	if result.Capabilities[contracts.CapabilityRootPrivileges] == "" {
		t.Fatalf("expected root privilege capability status")
	}
	if !result.Capabilities.Supports(contracts.CapabilitySystemdUnits) {
		t.Fatalf("expected systemd capability")
	}
	if !result.Capabilities.Supports(contracts.CapabilityAuthLogRead) {
		t.Fatalf("expected auth log capability")
	}
}

func TestDetectLinuxCapabilitiesFromLoginDatabases(t *testing.T) {
	root := t.TempDir()
	fullPath := filepath.Join(root, "var", "log", "wtmp")
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		t.Fatalf("create wtmp parent: %v", err)
	}
	if err := os.WriteFile(fullPath, []byte("x"), 0o644); err != nil {
		t.Fatalf("write wtmp: %v", err)
	}

	result, err := Detect(root, "amd64")
	if err != nil {
		t.Fatalf("detect capabilities: %v", err)
	}
	if !result.Capabilities.Supports(contracts.CapabilityUtmpRead) {
		t.Fatalf("expected utmp capability from login databases")
	}
}

func TestDetectMinimalRootReportsMissingCapabilities(t *testing.T) {
	root := t.TempDir()
	result, err := Detect(root, "arm64")
	if err != nil {
		t.Fatalf("detect capabilities: %v", err)
	}

	if result.Facts.Architecture != contracts.ArchitectureARM64 {
		t.Fatalf("expected arm64 architecture, got %#v", result.Facts)
	}
	if result.Capabilities.Supports(contracts.CapabilityProcfsRead) {
		t.Fatalf("empty root must not support procfs")
	}
	if result.Support != contracts.SupportUnsupported {
		t.Fatalf("expected unsupported minimal root, got %#v", result)
	}
	if result.Capabilities[contracts.CapabilityRootPrivileges] == "" {
		t.Fatalf("expected root privilege capability status for minimal root")
	}
}
