package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildVersionIsDefined(t *testing.T) {
	if buildVersion == "" {
		t.Fatalf("expected buildVersion to be defined")
	}
}

func TestRunVersionDoesNotRequireRoot(t *testing.T) {
	withEffectiveUID(t, 1000)

	if err := run([]string{"--version"}); err != nil {
		t.Fatalf("version should not require root: %v", err)
	}
}

func TestRunWithoutCommandDefaultsToUploadWorkflow(t *testing.T) {
	withEffectiveUID(t, 0)

	err := run(nil)
	if err == nil {
		t.Fatalf("expected default scan to require output directory")
	}
	if !strings.Contains(err.Error(), "--output-dir") {
		t.Fatalf("expected output-dir error, got %v", err)
	}
}

func TestRunScanRequiresOutputPath(t *testing.T) {
	withEffectiveUID(t, 0)

	err := run([]string{"scan"})
	if err == nil {
		t.Fatalf("expected scan without output to fail")
	}
}

func TestRunScanRequiresRoot(t *testing.T) {
	withEffectiveUID(t, 1000)

	err := run([]string{
		"scan",
		"--output-dir", filepath.Join(t.TempDir(), "out"),
	})
	if err == nil {
		t.Fatalf("expected scan without root to fail")
	}
	if !strings.Contains(err.Error(), "root") && !strings.Contains(err.Error(), "uid=0") {
		t.Fatalf("expected root error, got %v", err)
	}
}

func TestScanOSSLocalWritesSectionsBundle(t *testing.T) {
	withEffectiveUID(t, 0)

	outDir := t.TempDir()
	err := run([]string{"scan", "--include", "host,network", "--root", filepath.Join("..", "..", "internal", "collectors", "testdata", "root"), "--output-dir", outDir})
	if err != nil {
		t.Fatalf("run oss-local: %v", err)
	}
	for _, name := range []string{"manifest.json", filepath.Join("sections", "host.json"), filepath.Join("sections", "network.json")} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Fatalf("expected %s: %v", name, err)
		}
	}
	assertOnlyManifestAndSections(t, outDir)
}

func TestScanOSSLocalPrintsProgressAndOutputDir(t *testing.T) {
	withEffectiveUID(t, 0)

	outDir := t.TempDir()
	stdout := captureStdout(t, func() {
		err := run([]string{
			"scan",
			"--include", "host",
			"--root", filepath.Join("..", "..", "internal", "collectors", "testdata", "root"),
			"--output-dir", outDir,
		})
		if err != nil {
			t.Fatalf("run oss-local: %v", err)
		}
	})
	for _, want := range []string{"主机信息采集中", "主机信息采集完成", outDir} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("expected stdout to contain %q, got:\n%s", want, stdout)
		}
	}
}

func TestScanOSSLocalDotOutputDirCreatesScanSubdirectory(t *testing.T) {
	withEffectiveUID(t, 0)

	baseDir := t.TempDir()
	previousWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	if err := os.Chdir(baseDir); err != nil {
		t.Fatalf("change working directory: %v", err)
	}
	defer func() {
		if err := os.Chdir(previousWD); err != nil {
			t.Fatalf("restore working directory: %v", err)
		}
	}()

	stdout := captureStdout(t, func() {
		err := run([]string{
			"scan",
			"--include", "host",
			"--root", filepath.Join(previousWD, "..", "..", "internal", "collectors", "testdata", "root"),
			"--output-dir", "./",
			"--scan-id", "scan-linux-1",
		})
		if err != nil {
			t.Fatalf("run oss-local: %v", err)
		}
	})

	expectedDir := filepath.Join(baseDir, "host-collector-scan-linux-1")
	if _, err := os.Stat(filepath.Join(expectedDir, "manifest.json")); err != nil {
		t.Fatalf("expected manifest in auto output directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(baseDir, "manifest.json")); !os.IsNotExist(err) {
		t.Fatalf("manifest.json should not be written directly into dot output dir")
	}
	if !strings.Contains(stdout, expectedDir) {
		t.Fatalf("expected stdout to mention auto output directory %q, got:\n%s", expectedDir, stdout)
	}
}

func TestScanOSSLocalWritesSectionsOnlyDirectory(t *testing.T) {
	withEffectiveUID(t, 0)

	outDir := t.TempDir()
	err := run([]string{
		"scan",
		"--include", "host,process",
		"--root", filepath.Join("..", "..", "internal", "collectors", "testdata", "root"),
		"--output-dir", outDir,
	})
	if err != nil {
		t.Fatalf("run oss-local: %v", err)
	}
	for _, name := range []string{
		"manifest.json",
		filepath.Join("sections", "host.json"),
		filepath.Join("sections", "process.json"),
	} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Fatalf("expected %s: %v", name, err)
		}
	}
	assertOnlyManifestAndSections(t, outDir)
	if _, err := os.Stat(filepath.Join(outDir, "scan.json")); !os.IsNotExist(err) {
		t.Fatalf("scan.json should not be written for output-dir bundle")
	}
}

func TestScanOSSLocalWritesFileSystemSectionOnlyWhenIncluded(t *testing.T) {
	withEffectiveUID(t, 0)

	root := filepath.Join("..", "..", "internal", "collectors", "testdata", "root")
	hostOnlyDir := t.TempDir()
	if err := run([]string{
		"scan",
		"--include", "host",
		"--root", root,
		"--output-dir", hostOnlyDir,
	}); err != nil {
		t.Fatalf("run host-only oss-local: %v", err)
	}
	if _, err := os.Stat(filepath.Join(hostOnlyDir, "sections", "file_system.json")); !os.IsNotExist(err) {
		t.Fatalf("file_system section should not be written without explicit include")
	}

	fileSystemDir := t.TempDir()
	if err := run([]string{
		"scan",
		"--include", "file_system",
		"--root", root,
		"--output-dir", fileSystemDir,
	}); err != nil {
		t.Fatalf("run file-system oss-local: %v", err)
	}
	if _, err := os.Stat(filepath.Join(fileSystemDir, "sections", "file_system.json")); err != nil {
		t.Fatalf("expected file_system section: %v", err)
	}
	var manifest struct {
		Files struct {
			Sections map[string]string `json:"sections"`
		} `json:"files"`
	}
	readJSONFile(t, filepath.Join(fileSystemDir, "manifest.json"), &manifest)
	if manifest.Files.Sections["file_system"] != filepath.Join("sections", "file_system.json") {
		t.Fatalf("expected file_system manifest section, got %#v", manifest.Files.Sections)
	}
}

func TestScanOSSLocalWritesUserTracesSectionOnlyWhenIncluded(t *testing.T) {
	withEffectiveUID(t, 0)

	root := filepath.Join("..", "..", "internal", "collectors", "testdata", "root")
	hostOnlyDir := t.TempDir()
	if err := run([]string{
		"scan",
		"--include", "host",
		"--root", root,
		"--output-dir", hostOnlyDir,
	}); err != nil {
		t.Fatalf("run host-only oss-local: %v", err)
	}
	if _, err := os.Stat(filepath.Join(hostOnlyDir, "sections", "user_traces.json")); !os.IsNotExist(err) {
		t.Fatalf("user_traces section should not be written without explicit include")
	}

	userTracesDir := t.TempDir()
	if err := run([]string{
		"scan",
		"--include", "user_traces",
		"--root", root,
		"--output-dir", userTracesDir,
	}); err != nil {
		t.Fatalf("run user-traces oss-local: %v", err)
	}
	if _, err := os.Stat(filepath.Join(userTracesDir, "sections", "user_traces.json")); err != nil {
		t.Fatalf("expected user_traces section: %v", err)
	}
	var manifest struct {
		Files struct {
			Sections map[string]string `json:"sections"`
		} `json:"files"`
	}
	readJSONFile(t, filepath.Join(userTracesDir, "manifest.json"), &manifest)
	if manifest.Files.Sections["user_traces"] != filepath.Join("sections", "user_traces.json") {
		t.Fatalf("expected user_traces manifest section, got %#v", manifest.Files.Sections)
	}
}

func TestScanOSSLocalAppliesIncludeExcludeAndDays(t *testing.T) {
	withEffectiveUID(t, 0)

	outDir := t.TempDir()
	err := run([]string{
		"scan",
		"--include", "host,network",
		"--exclude", "network",
		"--days", "14",
		"--root", filepath.Join("..", "..", "internal", "collectors", "testdata", "root"),
		"--output-dir", outDir,
	})
	if err != nil {
		t.Fatalf("run oss-local: %v", err)
	}

	var manifest struct {
		LocalCLI struct {
			Include []string `json:"include"`
			Exclude []string `json:"exclude"`
			Scope   []string `json:"scope"`
			Days    int      `json:"days"`
		} `json:"local_cli"`
	}
	readJSONFile(t, filepath.Join(outDir, "manifest.json"), &manifest)
	if strings.Join(manifest.LocalCLI.Include, ",") != "host,network" {
		t.Fatalf("unexpected include: %#v", manifest.LocalCLI.Include)
	}
	if strings.Join(manifest.LocalCLI.Exclude, ",") != "network" {
		t.Fatalf("unexpected exclude: %#v", manifest.LocalCLI.Exclude)
	}
	if strings.Join(manifest.LocalCLI.Scope, ",") != "host" || manifest.LocalCLI.Days != 14 {
		t.Fatalf("unexpected effective cli options: %#v", manifest.LocalCLI)
	}

	var manifestSections struct {
		Files struct {
			Sections map[string]string `json:"sections"`
		} `json:"files"`
	}
	readJSONFile(t, filepath.Join(outDir, "manifest.json"), &manifestSections)
	if _, exists := manifestSections.Files.Sections["network"]; exists {
		t.Fatalf("network section should be excluded: %#v", manifestSections.Files.Sections)
	}
	if _, exists := manifestSections.Files.Sections["host"]; !exists {
		t.Fatalf("host/system section should be included")
	}
}

func TestRunScanRejectsUnknownNetworkFlags(t *testing.T) {
	withEffectiveUID(t, 0)

	err := run([]string{
		"scan",
		"--cloud-url", "https://example.invalid",
		"--output-dir", filepath.Join(t.TempDir(), "out"),
	})
	if err == nil {
		t.Fatalf("expected cloud-url flag to be rejected")
	}
	if !strings.Contains(err.Error(), "flag provided but not defined") {
		t.Fatalf("expected undefined flag error, got %v", err)
	}
}

func readJSONFile(t *testing.T, path string, target any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("decode %s: %v\n%s", path, err, data)
	}
}

func assertOnlyManifestAndSections(t *testing.T, outputDir string) {
	t.Helper()
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		t.Fatalf("read output directory: %v", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if name != "manifest.json" && name != "sections" {
			t.Fatalf("unexpected top-level output %s in sections-only output", name)
		}
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	previous := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	os.Stdout = writer
	defer func() {
		os.Stdout = previous
	}()

	fn()
	if err := writer.Close(); err != nil {
		t.Fatalf("close stdout writer: %v", err)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close stdout reader: %v", err)
	}
	return string(data)
}

func withEffectiveUID(t *testing.T, uid int) {
	t.Helper()
	previous := effectiveUID
	effectiveUID = func() int { return uid }
	t.Cleanup(func() {
		effectiveUID = previous
	})
}
