package collector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"windows-host-collector/models"
)

func TestWebLogCollectorCollectsDiscoveredSourcesAndEntries(t *testing.T) {
	root := t.TempDir()
	logDir := filepath.Join(root, "nginx", "logs")
	confDir := filepath.Join(root, "nginx", "conf")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatalf("mkdir log dir: %v", err)
	}
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatalf("mkdir conf dir: %v", err)
	}

	logPath := filepath.Join(logDir, "access.log")
	logBody := "1.2.3.4 - - [21/Apr/2026:12:01:02 +0800] \"GET / HTTP/1.1\" 200 1234 \"-\" \"curl/8.0\"\n"
	if err := os.WriteFile(logPath, []byte(logBody), 0o644); err != nil {
		t.Fatalf("write access log: %v", err)
	}

	confPath := filepath.Join(confDir, "nginx.conf")
	confBody := "events {}\nhttp {\n  access_log " + filepath.ToSlash(logPath) + ";\n}\n"
	if err := os.WriteFile(confPath, []byte(confBody), 0o644); err != nil {
		t.Fatalf("write nginx conf: %v", err)
	}

	collector := NewWebLogCollector().WithDiscoveryInputs(webLogDiscoveryInputs{
		NginxConfigs: []string{confPath},
	}).WithScanOptions(webLogScanOptions{
		MaxDepth:          2,
		MaxFilesPerRoot:   10,
		MaxTotalFiles:     10,
		MaxSampleBytes:    4096,
		AllowedExtensions: []string{".log", ".txt"},
	})

	result, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect web logs: %v", err)
	}

	webResult, ok := result.(*WebLogCollectionResult)
	if !ok {
		t.Fatalf("expected WebLogCollectionResult, got %T", result)
	}
	if len(webResult.Sources) != 1 {
		t.Fatalf("expected 1 source, got %#v", webResult.Sources)
	}
	if len(webResult.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %#v", webResult.Entries)
	}
	if webResult.Entries[0].Method != "GET" || webResult.Entries[0].URI != "/" {
		t.Fatalf("unexpected parsed entry: %#v", webResult.Entries[0])
	}
	if webResult.Entries[0].Timestamp != "2026-04-21T12:01:02+08:00" {
		t.Fatalf("expected normalized timestamp, got %#v", webResult.Entries[0])
	}
}

func TestWebLogCollectorFiltersEntriesOutsideTimeWindow(t *testing.T) {
	root := t.TempDir()
	logDir := filepath.Join(root, "nginx", "logs")
	confDir := filepath.Join(root, "nginx", "conf")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatalf("mkdir log dir: %v", err)
	}
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatalf("mkdir conf dir: %v", err)
	}

	logPath := filepath.Join(logDir, "access.log")
	logBody := strings.Join([]string{
		`1.2.3.4 - - [21/Apr/2026:12:01:02 +0800] "GET /inside HTTP/1.1" 200 1234 "-" "curl/8.0"`,
		`1.2.3.4 - - [18/Apr/2026:12:01:02 +0800] "GET /outside HTTP/1.1" 200 1234 "-" "curl/8.0"`,
		`1.2.3.4 - - [bad timestamp] "GET /bad HTTP/1.1" 200 1234 "-" "curl/8.0"`,
	}, "\n")
	if err := os.WriteFile(logPath, []byte(logBody), 0o644); err != nil {
		t.Fatalf("write access log: %v", err)
	}

	confPath := filepath.Join(confDir, "nginx.conf")
	confBody := "events {}\nhttp {\n  access_log " + filepath.ToSlash(logPath) + ";\n}\n"
	if err := os.WriteFile(confPath, []byte(confBody), 0o644); err != nil {
		t.Fatalf("write nginx conf: %v", err)
	}

	result, err := NewWebLogCollector().
		WithDiscoveryInputs(webLogDiscoveryInputs{NginxConfigs: []string{confPath}}).
		WithScanOptions(webLogScanOptions{
			MaxDepth:          2,
			MaxFilesPerRoot:   10,
			MaxTotalFiles:     10,
			MaxSampleBytes:    4096,
			AllowedExtensions: []string{".log", ".txt"},
		}).
		WithTimeWindow(mustParseRFC3339(t, "2026-04-20T00:00:00Z")).
		Collect(context.Background())
	if err != nil {
		t.Fatalf("collect web logs: %v", err)
	}

	webResult, ok := result.(*WebLogCollectionResult)
	if !ok {
		t.Fatalf("expected WebLogCollectionResult, got %T", result)
	}
	if len(webResult.Entries) != 1 {
		t.Fatalf("expected only in-window entries, got %#v", webResult.Entries)
	}
	if webResult.Entries[0].URI != "/inside" {
		t.Fatalf("expected inside-window entry to remain, got %#v", webResult.Entries[0])
	}
}

func TestNewWebLogCollectorDiscoversPhpStudyNginxConfigByDefault(t *testing.T) {
	root := t.TempDir()
	logDir := filepath.Join(root, "phpstudy_pro", "Extensions", "Nginx1.23.4", "logs")
	confDir := filepath.Join(root, "phpstudy_pro", "Extensions", "Nginx1.23.4", "conf", "vhosts")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatalf("mkdir log dir: %v", err)
	}
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatalf("mkdir conf dir: %v", err)
	}

	logPath := filepath.Join(logDir, "access.log")
	logBody := "1.2.3.4 - - [21/Apr/2026:12:01:02 +0800] \"GET /phpstudy HTTP/1.1\" 200 1234 \"-\" \"curl/8.0\"\n"
	if err := os.WriteFile(logPath, []byte(logBody), 0o644); err != nil {
		t.Fatalf("write access log: %v", err)
	}

	vhostConf := filepath.Join(confDir, "demo.conf")
	if err := os.WriteFile(vhostConf, []byte("server { access_log "+filepath.ToSlash(logPath)+"; }"), 0o644); err != nil {
		t.Fatalf("write vhost conf: %v", err)
	}

	mainConf := filepath.Join(root, "phpstudy_pro", "Extensions", "Nginx1.23.4", "conf", "nginx.conf")
	mainBody := "events {}\nhttp {\n  include " + filepath.ToSlash(filepath.Join(confDir, "*.conf")) + ";\n}\n"
	if err := os.WriteFile(mainConf, []byte(mainBody), 0o644); err != nil {
		t.Fatalf("write nginx conf: %v", err)
	}

	SetWebLogDiscoveryOverridesForTesting(WebLogDiscoveryOverrideConfig{
		ScanOptions: WebLogScanOverrideConfig{
			MaxDepth:          2,
			MaxFilesPerRoot:   10,
			MaxTotalFiles:     10,
			MaxSampleBytes:    4096,
			AllowedExtensions: []string{".log", ".txt"},
		},
	})
	defer SetWebLogDiscoveryOverridesForTesting(WebLogDiscoveryOverrideConfig{})
	setWebLogDiscoveryRootsForTesting([]string{root})
	defer setWebLogDiscoveryRootsForTesting(nil)

	collector := NewWebLogCollector()
	result, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect web logs: %v", err)
	}

	webResult, ok := result.(*WebLogCollectionResult)
	if !ok {
		t.Fatalf("expected WebLogCollectionResult, got %T", result)
	}
	if len(webResult.Sources) != 1 {
		t.Fatalf("expected 1 source, got %#v", webResult.Sources)
	}
	if len(webResult.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %#v", webResult.Entries)
	}
	if webResult.Entries[0].URI != "/phpstudy" {
		t.Fatalf("unexpected parsed entry: %#v", webResult.Entries[0])
	}
}

func TestWebLogCollectorFallsBackToRuntimePhpStudyDiscovery(t *testing.T) {
	root := t.TempDir()
	phpStudyRoot := filepath.Join(root, "phpstudy_pro")
	logDir := filepath.Join(phpStudyRoot, "Extensions", "Nginx1.23.4", "logs")
	vhostDir := filepath.Join(phpStudyRoot, "Extensions", "Nginx1.23.4", "conf", "vhosts")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatalf("mkdir log dir: %v", err)
	}
	if err := os.MkdirAll(vhostDir, 0o755); err != nil {
		t.Fatalf("mkdir vhost dir: %v", err)
	}

	logPath := filepath.Join(logDir, "access.log")
	logBody := "1.2.3.4 - - [21/Apr/2026:12:01:02 +0800] \"GET /runtime HTTP/1.1\" 200 1234 \"-\" \"curl/8.0\"\n"
	if err := os.WriteFile(logPath, []byte(logBody), 0o644); err != nil {
		t.Fatalf("write access log: %v", err)
	}

	vhostConf := filepath.Join(vhostDir, "demo.conf")
	if err := os.WriteFile(vhostConf, []byte("server { access_log "+filepath.ToSlash(logPath)+"; }"), 0o644); err != nil {
		t.Fatalf("write vhost conf: %v", err)
	}

	mainConf := filepath.Join(phpStudyRoot, "Extensions", "Nginx1.23.4", "conf", "nginx.conf")
	mainBody := "events {}\nhttp {\n  include " + filepath.ToSlash(filepath.Join(vhostDir, "*.conf")) + ";\n}\n"
	if err := os.WriteFile(mainConf, []byte(mainBody), 0o644); err != nil {
		t.Fatalf("write nginx conf: %v", err)
	}

	collector := NewWebLogCollector().WithDiscoveryInputs(webLogDiscoveryInputs{}).WithDiscoveryContext(WebLogDiscoveryContext{
		Processes: []*models.ProcessBasicInfo{
			{PID: 301, ProcessName: "php-cgi.exe"},
		},
		ProcessDetails: map[int]*models.ProcessDetail{
			301: {
				BasicInfo: &models.ProcessBasicInfo{
					PID:         301,
					ProcessName: "php-cgi.exe",
					ImagePath:   stringPtr(strings.ReplaceAll(filepath.Join(phpStudyRoot, "Extensions", "php", "php-cgi.exe"), string(filepath.Separator), `\`)),
				},
				NetworkConnections: []models.ProcessNetworkConnection{
					{LocalPort: 80, StateName: "LISTEN"},
				},
			},
		},
		Software: []models.InstalledSoftwareItem{
			{Name: "phpstudy_pro", InstallLocation: strings.ReplaceAll(phpStudyRoot, string(filepath.Separator), `\`)},
		},
	}).WithScanOptions(webLogScanOptions{
		MaxDepth:          2,
		MaxFilesPerRoot:   10,
		MaxTotalFiles:     10,
		MaxSampleBytes:    4096,
		AllowedExtensions: []string{".log", ".txt"},
	})

	result, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect web logs: %v", err)
	}

	webResult, ok := result.(*WebLogCollectionResult)
	if !ok {
		t.Fatalf("expected WebLogCollectionResult, got %T", result)
	}
	if len(webResult.Sources) != 1 {
		t.Fatalf("expected 1 source, got %#v", webResult.Sources)
	}
	if len(webResult.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %#v", webResult.Entries)
	}
	if webResult.Sources[0].ServerType != "nginx" {
		t.Fatalf("unexpected source: %#v", webResult.Sources[0])
	}
	if webResult.Sources[0].SourceMethod != "runtimeInstallHint" {
		t.Fatalf("expected runtime install hint source method, got %#v", webResult.Sources[0])
	}
	if webResult.Sources[0].Port != 80 {
		t.Fatalf("expected runtime-discovered port, got %#v", webResult.Sources[0])
	}
	if !containsStringWebLog(webResult.Sources[0].Evidence, "LISTEN_PORT_MATCH") {
		t.Fatalf("expected runtime evidence on source, got %#v", webResult.Sources[0].Evidence)
	}
	if webResult.Entries[0].URI != "/runtime" {
		t.Fatalf("unexpected parsed entry: %#v", webResult.Entries[0])
	}
	if webResult.Entries[0].ProcessName != "php-cgi.exe" || webResult.Entries[0].ProcessPID != 301 {
		t.Fatalf("expected runtime process metadata in entry, got %#v", webResult.Entries[0])
	}
}

func TestWebLogCollectorRuntimeProcessConfigSourceMethod(t *testing.T) {
	root := t.TempDir()
	logDir := filepath.Join(root, "nginx", "logs")
	confDir := filepath.Join(root, "nginx", "conf")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatalf("mkdir log dir: %v", err)
	}
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatalf("mkdir conf dir: %v", err)
	}

	logPath := filepath.Join(logDir, "access.log")
	logBody := "1.2.3.4 - - [21/Apr/2026:12:01:02 +0800] \"GET /runtime-config HTTP/1.1\" 200 1234 \"-\" \"curl/8.0\"\n"
	if err := os.WriteFile(logPath, []byte(logBody), 0o644); err != nil {
		t.Fatalf("write access log: %v", err)
	}

	confPath := filepath.Join(confDir, "nginx.conf")
	confBody := "events {}\nhttp {\n  access_log " + filepath.ToSlash(logPath) + ";\n}\n"
	if err := os.WriteFile(confPath, []byte(confBody), 0o644); err != nil {
		t.Fatalf("write nginx conf: %v", err)
	}

	collector := NewWebLogCollector().WithDiscoveryInputs(webLogDiscoveryInputs{}).WithDiscoveryContext(WebLogDiscoveryContext{
		Processes: []*models.ProcessBasicInfo{
			{PID: 101, ProcessName: "nginx.exe"},
		},
		ProcessDetails: map[int]*models.ProcessDetail{
			101: {
				BasicInfo: &models.ProcessBasicInfo{
					PID:         101,
					ProcessName: "nginx.exe",
					CommandLine: stringPtr("nginx.exe -c " + strings.ReplaceAll(confPath, string(filepath.Separator), `\`)),
					ImagePath:   stringPtr(strings.ReplaceAll(filepath.Join(root, "nginx", "nginx.exe"), string(filepath.Separator), `\`)),
				},
				NetworkConnections: []models.ProcessNetworkConnection{
					{LocalPort: 8080, StateName: "LISTEN"},
				},
			},
		},
	}).WithScanOptions(webLogScanOptions{
		MaxDepth:          2,
		MaxFilesPerRoot:   10,
		MaxTotalFiles:     10,
		MaxSampleBytes:    4096,
		AllowedExtensions: []string{".log", ".txt"},
	})

	result, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect web logs: %v", err)
	}

	webResult, ok := result.(*WebLogCollectionResult)
	if !ok {
		t.Fatalf("expected WebLogCollectionResult, got %T", result)
	}
	if len(webResult.Sources) != 1 {
		t.Fatalf("expected 1 source, got %#v", webResult.Sources)
	}
	if len(webResult.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %#v", webResult.Entries)
	}

	source := webResult.Sources[0]
	if source.SourceMethod != "runtimeProcessConfig" {
		t.Fatalf("expected runtimeProcessConfig source method, got %#v", source)
	}
	if source.Port != 8080 {
		t.Fatalf("expected runtime-discovered port, got %#v", source)
	}
	if !containsStringWebLog(source.Evidence, "PROCESS_COMMANDLINE_CONFIG") {
		t.Fatalf("expected process config evidence on source, got %#v", source.Evidence)
	}

	entry := webResult.Entries[0]
	if entry.URI != "/runtime-config" {
		t.Fatalf("unexpected parsed entry: %#v", entry)
	}
	if entry.ProcessName != "nginx.exe" || entry.ProcessPID != 101 {
		t.Fatalf("expected runtime process metadata in entry, got %#v", entry)
	}
}

func TestWebLogCollectorMergesRuntimeEvidenceWithoutOverridingConfigSource(t *testing.T) {
	root := t.TempDir()
	phpStudyRoot := filepath.Join(root, "phpstudy_pro")
	logDir := filepath.Join(phpStudyRoot, "Extensions", "Nginx1.23.4", "logs")
	vhostDir := filepath.Join(phpStudyRoot, "Extensions", "Nginx1.23.4", "conf", "vhosts")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatalf("mkdir log dir: %v", err)
	}
	if err := os.MkdirAll(vhostDir, 0o755); err != nil {
		t.Fatalf("mkdir vhost dir: %v", err)
	}

	logPath := filepath.Join(logDir, "access.log")
	logBody := "1.2.3.4 - - [21/Apr/2026:12:01:02 +0800] \"GET /merged HTTP/1.1\" 200 1234 \"-\" \"curl/8.0\"\n"
	if err := os.WriteFile(logPath, []byte(logBody), 0o644); err != nil {
		t.Fatalf("write access log: %v", err)
	}

	vhostConf := filepath.Join(vhostDir, "demo.conf")
	if err := os.WriteFile(vhostConf, []byte("server { access_log "+filepath.ToSlash(logPath)+"; }"), 0o644); err != nil {
		t.Fatalf("write vhost conf: %v", err)
	}

	mainConf := filepath.Join(phpStudyRoot, "Extensions", "Nginx1.23.4", "conf", "nginx.conf")
	mainBody := "events {}\nhttp {\n  include " + filepath.ToSlash(filepath.Join(vhostDir, "*.conf")) + ";\n}\n"
	if err := os.WriteFile(mainConf, []byte(mainBody), 0o644); err != nil {
		t.Fatalf("write nginx conf: %v", err)
	}

	collector := NewWebLogCollector().WithDiscoveryInputs(webLogDiscoveryInputs{
		NginxConfigs: []string{mainConf},
	}).WithDiscoveryContext(WebLogDiscoveryContext{
		Processes: []*models.ProcessBasicInfo{
			{PID: 301, ProcessName: "php-cgi.exe"},
		},
		ProcessDetails: map[int]*models.ProcessDetail{
			301: {
				BasicInfo: &models.ProcessBasicInfo{
					PID:         301,
					ProcessName: "php-cgi.exe",
					ImagePath:   stringPtr(strings.ReplaceAll(filepath.Join(phpStudyRoot, "Extensions", "php", "php-cgi.exe"), string(filepath.Separator), `\`)),
				},
				NetworkConnections: []models.ProcessNetworkConnection{
					{LocalPort: 80, StateName: "LISTEN"},
				},
			},
		},
		Software: []models.InstalledSoftwareItem{
			{Name: "phpstudy_pro", InstallLocation: strings.ReplaceAll(phpStudyRoot, string(filepath.Separator), `\`)},
		},
	}).WithScanOptions(webLogScanOptions{
		MaxDepth:          2,
		MaxFilesPerRoot:   10,
		MaxTotalFiles:     10,
		MaxSampleBytes:    4096,
		AllowedExtensions: []string{".log", ".txt"},
	})

	result, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect web logs: %v", err)
	}

	webResult, ok := result.(*WebLogCollectionResult)
	if !ok {
		t.Fatalf("expected WebLogCollectionResult, got %T", result)
	}
	if len(webResult.Sources) != 1 {
		t.Fatalf("expected 1 source, got %#v", webResult.Sources)
	}
	if len(webResult.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %#v", webResult.Entries)
	}

	source := webResult.Sources[0]
	if source.SourceMethod != "nginxConfig" {
		t.Fatalf("expected source method nginxConfig, got %#v", source)
	}
	if source.Port != 80 {
		t.Fatalf("expected runtime port supplement, got %#v", source)
	}
	if !containsStringWebLog(source.Evidence, "LISTEN_PORT_MATCH") {
		t.Fatalf("expected runtime evidence in source, got %#v", source.Evidence)
	}

	entry := webResult.Entries[0]
	if entry.URI != "/merged" {
		t.Fatalf("unexpected parsed entry: %#v", entry)
	}
	if entry.ProcessName != "php-cgi.exe" || entry.ProcessPID != 301 {
		t.Fatalf("expected runtime process info in entry, got %#v", entry)
	}
}

func containsStringWebLog(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
