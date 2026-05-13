package localbundle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"collector-shared/runmode"
)

func TestWriteBundleWritesOnlyManifestAndSections(t *testing.T) {
	dir := t.TempDir()
	largeEvidence := make([]map[string]any, 0, 120)
	for i := 0; i < 120; i++ {
		largeEvidence = append(largeEvidence, map[string]any{"pid": i + 100, "name": "proc-" + string(rune('a'+(i%26)))})
	}

	err := Write(dir, Bundle{
		Metadata: runmode.OutputMetadata{
			Edition:         runmode.EditionOSS,
			RunMode:         runmode.ModeOSSLocal,
			AuthMode:        runmode.AuthNone,
			EncryptionState: runmode.EncryptionNone,
			CollectionScope: []string{"host", "process", "network"},
			ToolVersion:     "test-version",
		},
		Sections: map[string]any{
			"system":    map[string]any{"hostname": "host-1"},
			"processes": largeEvidence,
			"network":   []map[string]any{{"remoteIp": "10.0.0.8"}},
		},
	})
	if err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	for _, rel := range []string{
		"manifest.json",
		filepath.Join("sections", "host.json"),
		filepath.Join("sections", "process.json"),
		filepath.Join("sections", "network.json"),
	} {
		if _, err := os.Stat(filepath.Join(dir, rel)); err != nil {
			t.Fatalf("expected %s: %v", rel, err)
		}
	}
	assertOnlyManifestAndSections(t, dir)

	var manifest Manifest
	readJSON(t, filepath.Join(dir, "manifest.json"), &manifest)
	if manifest.Files.Sections["process"] != filepath.Join("sections", "process.json") {
		t.Fatalf("unexpected process section file: %#v", manifest.Files.Sections)
	}
	if manifest.Domains["process"].ItemCount != 120 {
		t.Fatalf("expected process count, got %#v", manifest.Domains["process"])
	}
}

func TestWriteBundleDoesNotWriteSectionsWithoutCollectionScope(t *testing.T) {
	dir := t.TempDir()
	err := Write(dir, Bundle{
		Metadata: runmode.OutputMetadata{RunMode: runmode.ModeOSSLocal},
		Sections: map[string]any{"system": map[string]any{"hostname": "host-1"}},
	})
	if err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "manifest.json")); err != nil {
		t.Fatalf("expected manifest: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "sections", "host.json")); !os.IsNotExist(err) {
		t.Fatalf("host section should not be written without explicit collection scope")
	}
	assertOnlyManifestAndSections(t, dir)
}

func TestWriteBundleIncludesExplicitRegistryAndFileSystemDomains(t *testing.T) {
	dir := t.TempDir()
	err := Write(dir, Bundle{
		Metadata: runmode.OutputMetadata{
			RunMode:         runmode.ModeOSSLocal,
			CollectionScope: []string{"registry", "file_system"},
		},
		Sections: map[string]any{
			"registries": []map[string]any{{
				"path": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
				"name": "Updater",
				"type": "REG_SZ",
			}},
			"forensicVolumes": []map[string]any{{
				"volumeId": "volume-1",
			}},
			"forensicFileEntries": []map[string]any{{
				"path": "/etc/passwd",
			}},
		},
	})
	if err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	for _, rel := range []string{
		filepath.Join("sections", "registry.json"),
		filepath.Join("sections", "file_system.json"),
	} {
		if _, err := os.Stat(filepath.Join(dir, rel)); err != nil {
			t.Fatalf("expected %s: %v", rel, err)
		}
	}

	var manifest Manifest
	readJSON(t, filepath.Join(dir, "manifest.json"), &manifest)
	if manifest.Domains["registry"].Reason != "" || !manifest.Domains["registry"].OSSIncluded {
		t.Fatalf("registry should be included when section data exists: %#v", manifest.Domains["registry"])
	}
	if manifest.Domains["file_system"].Reason != "" || !manifest.Domains["file_system"].OSSIncluded {
		t.Fatalf("file_system should be included when section data exists: %#v", manifest.Domains["file_system"])
	}
}

func TestWriteBundleIncludesExplicitUserTracesDomain(t *testing.T) {
	dir := t.TempDir()
	err := Write(dir, Bundle{
		Metadata: runmode.OutputMetadata{
			RunMode:         runmode.ModeOSSLocal,
			CollectionScope: []string{"user_traces"},
		},
		Sections: map[string]any{
			"prefetch": []map[string]any{{
				"processName": "powershell.exe",
			}},
			"browserHistory": []map[string]any{{
				"url": "https://example.test",
			}},
			"usbRecords": []map[string]any{{
				"name": "USB Disk",
			}},
			"operationRecords": []map[string]any{{
				"event": "shell_history",
			}},
		},
	})
	if err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	var section map[string]any
	readJSON(t, filepath.Join(dir, "sections", "user_traces.json"), &section)
	for _, key := range []string{"prefetch", "browserHistory", "usbRecords", "operationRecords"} {
		if _, ok := section[key]; !ok {
			t.Fatalf("expected user_traces section to include %s, got %#v", key, section)
		}
	}
	var manifest Manifest
	readJSON(t, filepath.Join(dir, "manifest.json"), &manifest)
	if manifest.Files.Sections["user_traces"] != filepath.Join("sections", "user_traces.json") {
		t.Fatalf("expected user_traces manifest section, got %#v", manifest.Files.Sections)
	}
}

func TestWriteBundleDoesNotEmitUnscopedDomainForEmptyPayload(t *testing.T) {
	dir := t.TempDir()
	err := Write(dir, Bundle{
		Metadata: runmode.OutputMetadata{
			RunMode: runmode.ModeOSSLocal,
		},
		Sections: map[string]any{
			"forensicVolumes":     []map[string]any{},
			"forensicDiagnostics": struct{}{},
		},
	})
	if err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "sections", "file_system.json")); !os.IsNotExist(err) {
		t.Fatalf("file_system section should not be written for empty payload")
	}
}

func TestWriteBundleEmitsExplicitHeavyDomainWithEmptyPayload(t *testing.T) {
	dir := t.TempDir()
	err := Write(dir, Bundle{
		Metadata: runmode.OutputMetadata{
			RunMode:         runmode.ModeOSSLocal,
			CollectionScope: []string{"registry", "file_system"},
		},
		Sections: map[string]any{
			"registries":      []map[string]any{},
			"forensicVolumes": []map[string]any{},
		},
	})
	if err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	for _, rel := range []string{
		filepath.Join("sections", "registry.json"),
		filepath.Join("sections", "file_system.json"),
	} {
		if _, err := os.Stat(filepath.Join(dir, rel)); err != nil {
			t.Fatalf("expected explicit empty heavy domain %s: %v", rel, err)
		}
	}
}

func TestWriteBundleHonorsCollectionScopeForSectionFiles(t *testing.T) {
	dir := t.TempDir()
	err := Write(dir, Bundle{
		Metadata: runmode.OutputMetadata{
			RunMode:         runmode.ModeOSSLocal,
			CollectionScope: []string{"host"},
		},
		Sections: map[string]any{
			"system":              map[string]any{"hostname": "host-1"},
			"registries":          []map[string]any{{"keyPath": "Software\\Microsoft\\Windows\\CurrentVersion\\Run"}},
			"forensicDiagnostics": []map[string]any{{"stage": "skipped", "reason": "file system disabled"}},
			"forensicVolumes":     []map[string]any{{"volumeId": "C:"}},
		},
	})
	if err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	for _, rel := range []string{
		filepath.Join("sections", "registry.json"),
		filepath.Join("sections", "file_system.json"),
	} {
		if _, err := os.Stat(filepath.Join(dir, rel)); !os.IsNotExist(err) {
			t.Fatalf("%s should not be written outside collection scope", rel)
		}
	}

	var manifest Manifest
	readJSON(t, filepath.Join(dir, "manifest.json"), &manifest)
	if _, exists := manifest.Files.Sections["registry"]; exists {
		t.Fatalf("registry should not be present in manifest sections: %#v", manifest.Files.Sections)
	}
	if _, exists := manifest.Files.Sections["file_system"]; exists {
		t.Fatalf("file_system should not be present in manifest sections: %#v", manifest.Files.Sections)
	}
}

func readJSON(t *testing.T, path string, target any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("decode %s: %v\n%s", path, err, data)
	}
}

func assertOnlyManifestAndSections(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read output directory: %v", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if name != "manifest.json" && name != "sections" {
			t.Fatalf("unexpected top-level output %s in sections-only bundle", name)
		}
	}
}
