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
			MaxSampleBytes:    300 * 1024 * 1024,
			AllowedExtensions: []string{".log", ".txt"},
		}).
		WithFullModeThresholds(1, 0).
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

func TestWebLogCollectorKeepsSmallLogsFullDespiteTimeWindow(t *testing.T) {
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
		`1.2.3.4 - - [26/Feb/2024:23:01:14 +0800] "GET /old-hack168$ HTTP/1.1" 200 1234 "-" "curl/8.0"`,
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

	webResult := result.(*WebLogCollectionResult)
	if len(webResult.Entries) != 2 {
		t.Fatalf("expected small web log to be collected fully, got %#v", webResult.Entries)
	}
	if webResult.CollectionPlan == nil || webResult.CollectionPlan.Mode != "full" {
		t.Fatalf("expected full collection plan, got %#v", webResult.CollectionPlan)
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

func TestWebLogCollectorDiscoversPhpStudyDefaultAccessLogsAndSkipsErrorLogs(t *testing.T) {
	root := t.TempDir()
	phpStudyRoot := filepath.Join(root, "phpstudy_pro")
	apacheLogDir := filepath.Join(phpStudyRoot, "Extensions", "Apache2.4.39", "logs")
	nginxLogDir := filepath.Join(phpStudyRoot, "Extensions", "Nginx1.15.11", "logs")
	if err := os.MkdirAll(apacheLogDir, 0o755); err != nil {
		t.Fatalf("mkdir apache log dir: %v", err)
	}
	if err := os.MkdirAll(nginxLogDir, 0o755); err != nil {
		t.Fatalf("mkdir nginx log dir: %v", err)
	}

	files := map[string]string{
		filepath.Join(apacheLogDir, "access.log"):          "",
		filepath.Join(apacheLogDir, "access.log.20260523"): `127.0.0.1 - - [09/May/2026:08:00:01 +0000] "GET /phpstudy HTTP/1.1" 200 123 "-" "curl/8"` + "\n",
		filepath.Join(apacheLogDir, "error.log"):           "[Mon Feb 26 23:01:14.000000 2024] [php7:error] [pid 1234] webshell touched hack168$\n",
		filepath.Join(nginxLogDir, "access.log"):           "",
		filepath.Join(nginxLogDir, "error.log"):            "",
	}
	for path, body := range files {
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	SetWebLogDiscoveryOverridesForTesting(WebLogDiscoveryOverrideConfig{
		ScanOptions: WebLogScanOverrideConfig{
			MaxDepth:          1,
			MaxFilesPerRoot:   10,
			MaxTotalFiles:     10,
			MaxSampleBytes:    4096,
			AllowedExtensions: []string{".log", ".txt", ".20260523"},
		},
	})
	defer SetWebLogDiscoveryOverridesForTesting(WebLogDiscoveryOverrideConfig{})
	setWebLogDiscoveryRootsForTesting([]string{root})
	defer setWebLogDiscoveryRootsForTesting(nil)

	result, err := NewWebLogCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("collect web logs: %v", err)
	}
	webResult := result.(*WebLogCollectionResult)

	if len(webResult.Sources) != 3 {
		t.Fatalf("expected phpStudy default access log sources only, got %#v", webResult.Sources)
	}
	sourcePaths := make([]string, 0, len(webResult.Sources))
	for _, source := range webResult.Sources {
		sourcePaths = append(sourcePaths, source.Path)
		if !containsStringWebLog(source.Evidence, "PHPSTUDY_DEFAULT_LOG_PATH") {
			t.Fatalf("expected phpStudy default evidence on source %#v", source)
		}
	}
	for _, path := range []string{
		filepath.Join(apacheLogDir, "access.log"),
		filepath.Join(apacheLogDir, "access.log.20260523"),
		filepath.Join(nginxLogDir, "access.log"),
	} {
		if !containsStringWebLog(sourcePaths, filepath.Clean(path)) {
			t.Fatalf("expected source path %q in %#v", path, sourcePaths)
		}
	}
	for _, path := range []string{
		filepath.Join(apacheLogDir, "error.log"),
		filepath.Join(nginxLogDir, "error.log"),
	} {
		if containsStringWebLog(sourcePaths, filepath.Clean(path)) {
			t.Fatalf("did not expect error log source path %q in %#v", path, sourcePaths)
		}
	}

	if len(webResult.Entries) != 1 {
		t.Fatalf("expected one access entry for rotated access log, got %#v", webResult.Entries)
	}
	if webResult.Entries[0].Method != "GET" || webResult.Entries[0].URI != "/phpstudy" {
		t.Fatalf("expected parsed access log entry, got %#v", webResult.Entries[0])
	}
}

func TestWebLogCollectorParsesPhpStudyRotatedCommonAccessLog(t *testing.T) {
	root := t.TempDir()
	apacheLogDir := filepath.Join(root, "phpstudy_pro", "Extensions", "Apache2.4.39", "logs")
	if err := os.MkdirAll(apacheLogDir, 0o755); err != nil {
		t.Fatalf("mkdir apache log dir: %v", err)
	}
	logPath := filepath.Join(apacheLogDir, "access.log.1708905600")
	logBody := strings.Join([]string{
		`::1 - - [26/Feb/2024:22:24:20 +0800] "GET / HTTP/1.1" 302 -`,
		`::1 - - [26/Feb/2024:22:24:20 +0800] "GET /install.php HTTP/1.1" 200 8321`,
		`::1 - - [26/Feb/2024:22:25:32 +0800] "POST /install.php?action=install HTTP/1.1" 200 1302`,
	}, "\n") + "\n"
	if err := os.WriteFile(logPath, []byte(logBody), 0o644); err != nil {
		t.Fatalf("write rotated access log: %v", err)
	}

	SetWebLogDiscoveryOverridesForTesting(WebLogDiscoveryOverrideConfig{
		ScanOptions: WebLogScanOverrideConfig{
			MaxDepth:          1,
			MaxFilesPerRoot:   10,
			MaxTotalFiles:     10,
			MaxSampleBytes:    4096,
			AllowedExtensions: []string{".log", ".txt"},
		},
	})
	defer SetWebLogDiscoveryOverridesForTesting(WebLogDiscoveryOverrideConfig{})
	setWebLogDiscoveryRootsForTesting([]string{root})
	defer setWebLogDiscoveryRootsForTesting(nil)

	result, err := NewWebLogCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("collect web logs: %v", err)
	}
	webResult := result.(*WebLogCollectionResult)
	if len(webResult.Sources) != 1 {
		t.Fatalf("expected rotated access source, got %#v", webResult.Sources)
	}
	if len(webResult.Entries) != 3 {
		t.Fatalf("expected common access entries from rotated log, got %#v", webResult.Entries)
	}
	if webResult.Entries[1].URI != "/install.php" || webResult.Entries[1].BytesSent != 8321 {
		t.Fatalf("expected install.php entry, got %#v", webResult.Entries[1])
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
