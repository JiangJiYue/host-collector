package collector

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"windows-host-collector/models"
)

func TestFileIdentityCollectorCollectsHashesAndMetadata(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.exe")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write sample file: %v", err)
	}

	identity := NewFileIdentityCollector().CollectFile(path, []string{"process.image"})

	if identity.MD5 != "5d41402abc4b2a76b9719d911017c592" {
		t.Fatalf("expected md5 digest, got %q", identity.MD5)
	}
	if identity.SHA256 != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Fatalf("expected sha256 digest, got %q", identity.SHA256)
	}
	if identity.HashState != "completed" {
		t.Fatalf("expected completed hash state, got %q", identity.HashState)
	}
	if identity.Basename != "sample.exe" {
		t.Fatalf("expected basename sample.exe, got %q", identity.Basename)
	}
	if identity.Extension != ".exe" {
		t.Fatalf("expected .exe extension, got %q", identity.Extension)
	}
	if len(identity.EvidenceSources) != 1 || identity.EvidenceSources[0] != "process.image" {
		t.Fatalf("expected evidence source to be preserved, got %#v", identity.EvidenceSources)
	}
	if identity.SignatureState == "" {
		t.Fatal("expected signature state to be populated")
	}
}

func TestFileIdentityCollectorDedupesByNormalizedPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.exe")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write sample file: %v", err)
	}

	collector := NewFileIdentityCollector()
	first := collector.CollectFile(path, []string{"process.image"})
	second := collector.CollectFile(path, []string{"registry.value"})

	if first.ID != second.ID {
		t.Fatalf("expected stable ID for same path, got %q and %q", first.ID, second.ID)
	}
	if first.NormalizedPath != second.NormalizedPath {
		t.Fatalf("expected stable normalized path, got %q and %q", first.NormalizedPath, second.NormalizedPath)
	}

	identities := collector.Identities()
	if len(identities) != 1 {
		t.Fatalf("expected one cached identity, got %d", len(identities))
	}
	if identities[0].ID != first.ID {
		t.Fatalf("expected cached identity to match collected ID, got %q", identities[0].ID)
	}
}

func TestFileIdentityCollectorMergesEvidenceSourcesAcrossCalls(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.exe")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write sample file: %v", err)
	}

	collector := NewFileIdentityCollector()
	collector.CollectFile(path, []string{"process.image"})
	collector.CollectFile(path, []string{"registry.value"})

	identities := collector.Identities()
	if len(identities) != 1 {
		t.Fatalf("expected one cached identity, got %d", len(identities))
	}
	if len(identities[0].EvidenceSources) != 2 {
		t.Fatalf("expected merged evidence sources, got %#v", identities[0].EvidenceSources)
	}
	if identities[0].EvidenceSources[0] != "process.image" || identities[0].EvidenceSources[1] != "registry.value" {
		t.Fatalf("expected merged evidence sources in order, got %#v", identities[0].EvidenceSources)
	}
}

func TestFileIdentityCollectorReturnedIdentityDoesNotMutateCache(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.exe")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write sample file: %v", err)
	}

	collector := NewFileIdentityCollector()
	got := collector.CollectFile(path, []string{"process.image"})
	got.EvidenceSources[0] = "mutated"

	fresh := collector.CollectFile(path, nil)
	if len(fresh.EvidenceSources) != 1 || fresh.EvidenceSources[0] != "process.image" {
		t.Fatalf("expected cached evidence sources to remain isolated, got %#v", fresh.EvidenceSources)
	}
}

func TestFileIdentityCollectorStoreMergesSourcesForSamePath(t *testing.T) {
	collector := NewFileIdentityCollector()
	first := models.FileIdentity{
		NormalizedPath:  "c:\\users\\public\\svchost.exe",
		EvidenceSources: []string{"process.image"},
	}
	second := models.FileIdentity{
		NormalizedPath:  "c:\\users\\public\\svchost.exe",
		EvidenceSources: []string{"registry.value"},
	}

	collector.storeIdentity(first)
	collector.storeIdentity(second)

	identities := collector.Identities()
	if len(identities) != 1 {
		t.Fatalf("expected one cached identity, got %d", len(identities))
	}
	if len(identities[0].EvidenceSources) != 2 {
		t.Fatalf("expected merged evidence sources, got %#v", identities[0].EvidenceSources)
	}
	if identities[0].EvidenceSources[0] != "process.image" || identities[0].EvidenceSources[1] != "registry.value" {
		t.Fatalf("expected merged evidence sources in order, got %#v", identities[0].EvidenceSources)
	}
}

func TestFileIdentityCollectorNormalizesWindowsLikePathDeterministically(t *testing.T) {
	got := normalizeIdentityPath(`C:\Users\Public\..\Public\svchost.exe`)
	want := `c:\users\public\svchost.exe`

	if got != want {
		t.Fatalf("expected normalized Windows-like path %q, got %q", want, got)
	}
}

func TestFileIdentityCollectorReportsMissingPathFailure(t *testing.T) {
	identity := NewFileIdentityCollector().CollectFile(filepath.Join(t.TempDir(), "missing.exe"), nil)

	if identity.HashState != "read_error" && identity.HashState != "access_denied" {
		t.Fatalf("expected read_error or access_denied, got %q", identity.HashState)
	}
	if identity.CollectionError == "" {
		t.Fatal("expected collection error to be populated")
	}
}

func TestFileIdentityCollectorSetsDirectorySkipState(t *testing.T) {
	dir := t.TempDir()

	identity := NewFileIdentityCollector().CollectFile(dir, nil)

	if identity.HashState != "skipped_not_file" {
		t.Fatalf("expected skipped_not_file for directories, got %q", identity.HashState)
	}
}

func TestFileIdentityCollectorPopulatesSignatureStateStub(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.exe")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write sample file: %v", err)
	}

	identity := NewFileIdentityCollector().CollectFile(path, nil)

	if runtime.GOOS == "windows" {
		if identity.SignatureState != "unknown" {
			t.Fatalf("expected unknown signature state on windows, got %q", identity.SignatureState)
		}
		return
	}
	if identity.SignatureState != "unsupported" {
		t.Fatalf("expected unsupported signature state on non-windows, got %q", identity.SignatureState)
	}
}
