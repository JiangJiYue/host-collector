package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"windows-host-collector/collector"
)

func TestHeadlessOSSLocalWritesSectionsOnly(t *testing.T) {
	dir := t.TempDir()
	outputDir := filepath.Join(dir, "out")

	err := run([]string{
		"--include", "host,process",
		"--output-dir", outputDir,
		"--agent-id", "agent-win-1",
		"--scan-id", "20260526-120000-abcdef12",
	})
	if err != nil {
		t.Fatalf("run headless oss local: %v", err)
	}

	for _, name := range []string{"manifest.json", filepath.Join("sections", "host.json"), filepath.Join("sections", "process.json")} {
		if _, err := os.Stat(filepath.Join(outputDir, name)); err != nil {
			t.Fatalf("expected %s output: %v", name, err)
		}
	}
	assertOnlyManifestAndSections(t, outputDir)
}

func TestHeadlessOSSLocalScanCommandAcceptsOutputDir(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "out")

	err := run([]string{
		"scan",
		"--include", "host,process,network,logs,users,startup,software,timeline,web_logs",
		"--days", "7",
		"--output-dir", outputDir,
		"--agent-id", "agent-win-1",
		"--scan-id", "20260526-120000-abcdef12",
	})
	if err != nil {
		t.Fatalf("run headless oss local scan command: %v", err)
	}

	for _, name := range []string{
		"manifest.json",
		filepath.Join("sections", "host.json"),
	} {
		if _, err := os.Stat(filepath.Join(outputDir, name)); err != nil {
			t.Fatalf("expected %s output: %v", name, err)
		}
	}
	assertOnlyManifestAndSections(t, outputDir)
	var manifest struct {
		LocalCLI struct {
			Include []string `json:"include"`
			Scope   []string `json:"scope"`
			Days    int      `json:"days"`
		} `json:"local_cli"`
		Domains map[string]struct {
			OSSIncluded bool   `json:"oss_included"`
			SectionFile string `json:"section_file"`
		} `json:"domains"`
	}
	readJSONFile(t, filepath.Join(outputDir, "manifest.json"), &manifest)
	wantScope := "host,process,network,logs,users,startup,software,timeline,web_logs"
	if strings.Join(manifest.LocalCLI.Include, ",") != wantScope || strings.Join(manifest.LocalCLI.Scope, ",") != wantScope {
		t.Fatalf("unexpected scan command scope: %#v", manifest.LocalCLI)
	}
	if manifest.LocalCLI.Days != 7 {
		t.Fatalf("unexpected scan command options: %#v", manifest.LocalCLI)
	}
	for _, domain := range strings.Split(wantScope, ",") {
		entry, ok := manifest.Domains[domain]
		if !ok || !entry.OSSIncluded {
			t.Fatalf("expected manifest domain %s to be listed and included: %#v", domain, manifest.Domains)
		}
	}
}

func TestHeadlessOSSLocalScanCommandPrintsProgressToStdout(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "out")

	stdout := captureStdout(t, func() {
		err := run([]string{
			"scan",
			"--include", "host",
			"--output-dir", outputDir,
			"--agent-id", "agent-win-1",
			"--scan-id", "20260526-120000-abcdef12",
		})
		if err != nil {
			t.Fatalf("run headless oss local scan command: %v", err)
		}
	})

	for _, want := range []string{"系统信息采集中", "系统信息采集完成", outputDir} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("expected stdout to contain %q, got:\n%s", want, stdout)
		}
	}
}

func TestHeadlessScanRejectsInvalidScanIDBeforeOutputResolution(t *testing.T) {
	err := run([]string{
		"scan",
		"--include", "host",
		"--output-dir", filepath.Join(t.TempDir(), "out"),
		"--scan-id", "../escape",
	})
	if err == nil {
		t.Fatalf("expected invalid scan id error")
	}
	if !strings.Contains(err.Error(), "invalid scan id") {
		t.Fatalf("expected invalid scan id error, got %v", err)
	}
}

func TestHeadlessOSSLocalDotOutputDirCreatesScanSubdirectory(t *testing.T) {
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
			"--output-dir", ".",
			"--agent-id", "agent-win-1",
			"--scan-id", "20260526-120000-abcdef12",
		})
		if err != nil {
			t.Fatalf("run headless oss local scan command: %v", err)
		}
	})

	expectedDir := filepath.Join(baseDir, "host-collector-20260526-120000-abcdef12")
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

func TestHeadlessOSSLocalWritesSectionsOnlyDirectory(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "out")

	err := run([]string{
		"--include", "host,process",
		"--output-dir", outputDir,
		"--agent-id", "agent-win-1",
		"--scan-id", "20260526-120000-abcdef12",
	})
	if err != nil {
		t.Fatalf("run headless oss local: %v", err)
	}
	for _, name := range []string{
		"manifest.json",
		filepath.Join("sections", "host.json"),
		filepath.Join("sections", "process.json"),
	} {
		if _, err := os.Stat(filepath.Join(outputDir, name)); err != nil {
			t.Fatalf("expected %s output: %v", name, err)
		}
	}
	assertOnlyManifestAndSections(t, outputDir)
	if _, err := os.Stat(filepath.Join(outputDir, "scan.json")); !os.IsNotExist(err) {
		t.Fatalf("scan.json should not be written for output-dir bundle")
	}
}

func TestHeadlessOSSLocalWritesHeavySectionsOnlyWhenIncluded(t *testing.T) {
	hostOnlyDir := filepath.Join(t.TempDir(), "host-only")
	if err := run([]string{
		"scan",
		"--include", "host",
		"--output-dir", hostOnlyDir,
		"--agent-id", "agent-win-1",
		"--scan-id", "20260526-120001-abcdef12",
	}); err != nil {
		t.Fatalf("run host-only oss-local: %v", err)
	}
	for _, name := range []string{"registry.json", "file_system.json"} {
		if _, err := os.Stat(filepath.Join(hostOnlyDir, "sections", name)); !os.IsNotExist(err) {
			t.Fatalf("%s should not be written without explicit include", name)
		}
	}

	heavyDir := filepath.Join(t.TempDir(), "heavy")
	if err := run([]string{
		"scan",
		"--include", "registry,file_system",
		"--output-dir", heavyDir,
		"--agent-id", "agent-win-1",
		"--scan-id", "20260526-120002-abcdef12",
	}); err != nil {
		t.Fatalf("run heavy oss-local: %v", err)
	}
	for _, name := range []string{"registry.json", "file_system.json"} {
		if _, err := os.Stat(filepath.Join(heavyDir, "sections", name)); err != nil {
			t.Fatalf("expected %s section: %v", name, err)
		}
	}
	var manifest struct {
		Files struct {
			Sections map[string]string `json:"sections"`
		} `json:"files"`
	}
	readJSONFile(t, filepath.Join(heavyDir, "manifest.json"), &manifest)
	for _, domain := range []string{"registry", "file_system"} {
		if manifest.Files.Sections[domain] != filepath.Join("sections", domain+".json") {
			t.Fatalf("expected %s manifest section, got %#v", domain, manifest.Files.Sections)
		}
	}
}

func TestHeadlessOSSLocalWritesUserTracesOnlyWhenIncluded(t *testing.T) {
	hostOnlyDir := filepath.Join(t.TempDir(), "host-only")
	if err := run([]string{
		"scan",
		"--include", "host",
		"--output-dir", hostOnlyDir,
		"--agent-id", "agent-win-1",
		"--scan-id", "20260526-120001-abcdef12",
	}); err != nil {
		t.Fatalf("run host-only oss-local: %v", err)
	}
	if _, err := os.Stat(filepath.Join(hostOnlyDir, "sections", "user_traces.json")); !os.IsNotExist(err) {
		t.Fatalf("user_traces section should not be written without explicit include")
	}

	userTracesDir := filepath.Join(t.TempDir(), "user-traces")
	if err := run([]string{
		"scan",
		"--include", "user_traces",
		"--output-dir", userTracesDir,
		"--agent-id", "agent-win-1",
		"--scan-id", "20260526-120003-abcdef12",
	}); err != nil {
		t.Fatalf("run user_traces oss-local: %v", err)
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

func TestHeadlessOSSLocalAppliesIncludeExcludeAndDays(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "out")

	err := run([]string{
		"--include", "host,network",
		"--exclude", "network",
		"--days", "30",
		"--output-dir", outputDir,
		"--agent-id", "agent-win-1",
		"--scan-id", "20260526-120000-abcdef12",
	})
	if err != nil {
		t.Fatalf("run headless oss local: %v", err)
	}

	var manifest struct {
		LocalCLI struct {
			Include []string `json:"include"`
			Exclude []string `json:"exclude"`
			Scope   []string `json:"scope"`
			Days    int      `json:"days"`
		} `json:"local_cli"`
	}
	readJSONFile(t, filepath.Join(outputDir, "manifest.json"), &manifest)
	if strings.Join(manifest.LocalCLI.Include, ",") != "host,network" {
		t.Fatalf("unexpected include: %#v", manifest.LocalCLI.Include)
	}
	if strings.Join(manifest.LocalCLI.Exclude, ",") != "network" {
		t.Fatalf("unexpected exclude: %#v", manifest.LocalCLI.Exclude)
	}
	if strings.Join(manifest.LocalCLI.Scope, ",") != "host" || manifest.LocalCLI.Days != 30 {
		t.Fatalf("unexpected effective cli options: %#v", manifest.LocalCLI)
	}

	assertOnlyManifestAndSections(t, outputDir)
}

func TestHeadlessOSSLocalPassesDaysToScannerPolicyWindow(t *testing.T) {
	var logWindowStarts []time.Time
	restoreObserver := collector.SetLogCollectorWindowObserverForTesting(func(start time.Time) {
		logWindowStarts = append(logWindowStarts, start)
	})
	defer restoreObserver()

	started := time.Now()
	err := run([]string{
		"--include", "logs",
		"--days", "30",
		"--output-dir", filepath.Join(t.TempDir(), "out"),
	})
	finished := time.Now()
	if err != nil {
		t.Fatalf("run headless oss local: %v", err)
	}

	if len(logWindowStarts) != 1 {
		t.Fatalf("expected one log collector window start, got %#v", logWindowStarts)
	}
	if logWindowStarts[0].Before(started.AddDate(0, 0, -30)) || logWindowStarts[0].After(finished.AddDate(0, 0, -30)) {
		t.Fatalf("expected log collector window to use --days=30, got %s for run between %s and %s", logWindowStarts[0], started, finished)
	}
}

func TestHeadlessMainWithoutArgsDoesNotWriteHomeLogFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	err := runDefaultNoArgs()
	if err == nil {
		t.Fatalf("expected default no-args run to require explicit include and output-dir")
	}

	if _, err := os.Stat(filepath.Join(home, ".host-collector")); !os.IsNotExist(err) {
		t.Fatalf("default local scan should not create home log directory, stat err=%v", err)
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
