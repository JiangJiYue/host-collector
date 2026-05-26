package collector

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"windows-host-collector/models"
	"windows-host-collector/utils"
)

func TestDiscoverIISWebLogSourcesFromApplicationHostConfig(t *testing.T) {
	root := t.TempDir()
	logDir := filepath.Join(root, "inetpub", "logs", "LogFiles", "W3SVC1")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatalf("mkdir log dir: %v", err)
	}
	logFile := filepath.Join(logDir, "u_ex260421.log")
	if err := os.WriteFile(logFile, []byte("#Fields: date time c-ip cs-method cs-uri-stem sc-status\r\n"), 0o644); err != nil {
		t.Fatalf("write log file: %v", err)
	}

	configPath := filepath.Join(root, "applicationHost.config")
	config := `<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.applicationHost>
    <sites>
      <site name="Default Web Site" id="1">
        <logFile directory="` + filepath.ToSlash(logDir) + `" />
        <bindings>
          <binding protocol="http" bindingInformation="*:80:" />
        </bindings>
      </site>
    </sites>
  </system.applicationHost>
</configuration>`
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	sources, err := discoverIISWebLogSources(configPath, 10)
	if err != nil {
		t.Fatalf("discover iis sources: %v", err)
	}
	if len(sources) != 1 {
		t.Fatalf("expected 1 source, got %#v", sources)
	}
	if sources[0].Path != logFile {
		t.Fatalf("expected discovered log path %q, got %#v", logFile, sources[0])
	}
	if sources[0].SiteName != "Default Web Site" || sources[0].ServerType != "iis" {
		t.Fatalf("unexpected IIS source metadata: %#v", sources[0])
	}
}

func TestDiscoverWebLogPathsFromNginxConfigWithInclude(t *testing.T) {
	root := t.TempDir()
	logDir := filepath.Join(root, "nginx", "logs")
	confDir := filepath.Join(root, "nginx", "conf")
	extraDir := filepath.Join(confDir, "conf.d")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatalf("mkdir log dir: %v", err)
	}
	if err := os.MkdirAll(extraDir, 0o755); err != nil {
		t.Fatalf("mkdir conf.d dir: %v", err)
	}

	accessLog := filepath.Join(logDir, "access.log")
	if err := os.WriteFile(accessLog, []byte("1.2.3.4 - - [21/Apr/2026:12:01:02 +0800] \"GET / HTTP/1.1\" 200 1234 \"-\" \"curl/8.0\"\n"), 0o644); err != nil {
		t.Fatalf("write access log: %v", err)
	}

	serverConf := filepath.Join(extraDir, "default.conf")
	if err := os.WriteFile(serverConf, []byte("server { access_log "+filepath.ToSlash(accessLog)+"; }"), 0o644); err != nil {
		t.Fatalf("write server conf: %v", err)
	}

	mainConf := filepath.Join(confDir, "nginx.conf")
	mainBody := "events {}\nhttp {\n  include " + filepath.ToSlash(filepath.Join(extraDir, "*.conf")) + ";\n}\n"
	if err := os.WriteFile(mainConf, []byte(mainBody), 0o644); err != nil {
		t.Fatalf("write nginx conf: %v", err)
	}

	paths, err := discoverWebLogPathsFromConfig(mainConf, "nginx")
	if err != nil {
		t.Fatalf("discover nginx paths: %v", err)
	}
	if len(paths) != 1 || paths[0] != accessLog {
		t.Fatalf("expected nginx access log path, got %#v", paths)
	}
}

func TestDiscoverWebLogPathsFromApacheConfig(t *testing.T) {
	root := t.TempDir()
	logDir := filepath.Join(root, "Apache24", "logs")
	confDir := filepath.Join(root, "Apache24", "conf")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatalf("mkdir log dir: %v", err)
	}
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatalf("mkdir conf dir: %v", err)
	}

	accessLog := filepath.Join(logDir, "access.log")
	if err := os.WriteFile(accessLog, []byte("1.2.3.4 - - [21/Apr/2026:12:01:02 +0800] \"GET / HTTP/1.1\" 200 1234 \"-\" \"curl/8.0\"\n"), 0o644); err != nil {
		t.Fatalf("write access log: %v", err)
	}

	httpdConf := filepath.Join(confDir, "httpd.conf")
	confBody := `CustomLog "` + filepath.ToSlash(accessLog) + `" combined`
	if err := os.WriteFile(httpdConf, []byte(confBody), 0o644); err != nil {
		t.Fatalf("write httpd conf: %v", err)
	}

	paths, err := discoverWebLogPathsFromConfig(httpdConf, "apache")
	if err != nil {
		t.Fatalf("discover apache paths: %v", err)
	}
	if len(paths) != 1 || paths[0] != accessLog {
		t.Fatalf("expected apache access log path, got %#v", paths)
	}
}

func TestDiscoverWebLogPathsFromTomcatServerXML(t *testing.T) {
	root := t.TempDir()
	logDir := filepath.Join(root, "tomcat", "logs")
	confDir := filepath.Join(root, "tomcat", "conf")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatalf("mkdir log dir: %v", err)
	}
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatalf("mkdir conf dir: %v", err)
	}

	accessLog := filepath.Join(logDir, "localhost_access_log.2026-04-21.txt")
	if err := os.WriteFile(accessLog, []byte("1.2.3.4 - - [21/Apr/2026:12:01:02 +0800] \"GET / HTTP/1.1\" 200 1234\n"), 0o644); err != nil {
		t.Fatalf("write tomcat access log: %v", err)
	}

	serverXML := filepath.Join(confDir, "server.xml")
	body := `<?xml version="1.0" encoding="UTF-8"?>
<Server>
  <Service name="Catalina">
    <Engine name="Catalina" defaultHost="localhost">
      <Host name="localhost" appBase="webapps">
        <Valve className="org.apache.catalina.valves.AccessLogValve"
               directory="` + filepath.ToSlash(logDir) + `"
               prefix="localhost_access_log"
               suffix=".txt" />
      </Host>
    </Engine>
  </Service>
</Server>`
	if err := os.WriteFile(serverXML, []byte(body), 0o644); err != nil {
		t.Fatalf("write server xml: %v", err)
	}

	paths, err := discoverWebLogPathsFromConfig(serverXML, "tomcat")
	if err != nil {
		t.Fatalf("discover tomcat paths: %v", err)
	}
	if len(paths) != 1 || paths[0] != accessLog {
		t.Fatalf("expected tomcat access log path, got %#v", paths)
	}
}

func TestDiscoverWebLogPathsFromPhpStudyNginxConfig(t *testing.T) {
	root := t.TempDir()
	logDir := filepath.Join(root, "phpstudy_pro", "Extensions", "Nginx1.23.4", "logs")
	confDir := filepath.Join(root, "phpstudy_pro", "Extensions", "Nginx1.23.4", "conf", "vhosts")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatalf("mkdir log dir: %v", err)
	}
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatalf("mkdir conf dir: %v", err)
	}

	accessLog := filepath.Join(logDir, "demo-access.log")
	if err := os.WriteFile(accessLog, []byte("1.2.3.4 - - [21/Apr/2026:12:01:02 +0800] \"GET /demo HTTP/1.1\" 200 1234 \"-\" \"curl/8.0\"\n"), 0o644); err != nil {
		t.Fatalf("write access log: %v", err)
	}

	vhostConf := filepath.Join(confDir, "demo.conf")
	if err := os.WriteFile(vhostConf, []byte("server { access_log "+filepath.ToSlash(accessLog)+"; }"), 0o644); err != nil {
		t.Fatalf("write vhost conf: %v", err)
	}

	mainConf := filepath.Join(root, "phpstudy_pro", "Extensions", "Nginx1.23.4", "conf", "nginx.conf")
	mainBody := "events {}\nhttp {\n  include " + filepath.ToSlash(filepath.Join(confDir, "*.conf")) + ";\n}\n"
	if err := os.WriteFile(mainConf, []byte(mainBody), 0o644); err != nil {
		t.Fatalf("write nginx conf: %v", err)
	}

	paths, err := discoverWebLogPathsFromConfig(mainConf, "nginx")
	if err != nil {
		t.Fatalf("discover phpstudy nginx paths: %v", err)
	}
	if len(paths) != 1 || paths[0] != accessLog {
		t.Fatalf("expected phpstudy nginx access log path, got %#v", paths)
	}
}

func TestDiscoverWebLogPathsFromPhpStudyNginxConfigResolvesRelativeLogPathFromInstallRoot(t *testing.T) {
	root := t.TempDir()
	logDir := filepath.Join(root, "phpstudy_pro", "Extensions", "Nginx1.15.11", "logs")
	confDir := filepath.Join(root, "phpstudy_pro", "Extensions", "Nginx1.15.11", "conf")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatalf("mkdir log dir: %v", err)
	}
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatalf("mkdir conf dir: %v", err)
	}

	accessLog := filepath.Join(logDir, "access.log")
	if err := os.WriteFile(accessLog, []byte(""), 0o644); err != nil {
		t.Fatalf("write access log: %v", err)
	}

	mainConf := filepath.Join(confDir, "nginx.conf")
	mainBody := "events {}\nhttp {\n  access_log logs/access.log;\n}\n"
	if err := os.WriteFile(mainConf, []byte(mainBody), 0o644); err != nil {
		t.Fatalf("write nginx conf: %v", err)
	}

	paths, err := discoverWebLogPathsFromConfig(mainConf, "nginx")
	if err != nil {
		t.Fatalf("discover phpstudy nginx paths: %v", err)
	}
	if len(paths) != 1 || paths[0] != accessLog {
		t.Fatalf("expected phpstudy nginx relative access log path %q, got %#v", accessLog, paths)
	}
}

func TestDiscoverWebLogPathsFromPhpStudyApacheConfigResolvesRelativeLogPathFromInstallRoot(t *testing.T) {
	root := t.TempDir()
	logDir := filepath.Join(root, "phpstudy_pro", "Extensions", "Apache2.4.39", "logs")
	confDir := filepath.Join(root, "phpstudy_pro", "Extensions", "Apache2.4.39", "conf")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatalf("mkdir log dir: %v", err)
	}
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatalf("mkdir conf dir: %v", err)
	}

	accessLog := filepath.Join(logDir, "access.log")
	if err := os.WriteFile(accessLog, []byte(""), 0o644); err != nil {
		t.Fatalf("write access log: %v", err)
	}

	httpdConf := filepath.Join(confDir, "httpd.conf")
	confBody := `CustomLog "logs/access.log" combined`
	if err := os.WriteFile(httpdConf, []byte(confBody), 0o644); err != nil {
		t.Fatalf("write httpd conf: %v", err)
	}

	paths, err := discoverWebLogPathsFromConfig(httpdConf, "apache")
	if err != nil {
		t.Fatalf("discover phpstudy apache paths: %v", err)
	}
	if len(paths) != 1 || paths[0] != accessLog {
		t.Fatalf("expected phpstudy apache relative access log path %q, got %#v", accessLog, paths)
	}
}

func TestWebLogCollectorLogsDiscoveryAndEmptyReasons(t *testing.T) {
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
	if err := os.WriteFile(logPath, []byte("not-a-web-log-line\n"), 0o644); err != nil {
		t.Fatalf("write access log: %v", err)
	}

	confPath := filepath.Join(confDir, "nginx.conf")
	confBody := "events {}\nhttp {\n  access_log " + filepath.ToSlash(logPath) + ";\n}\n"
	if err := os.WriteFile(confPath, []byte(confBody), 0o644); err != nil {
		t.Fatalf("write nginx conf: %v", err)
	}

	clientLogDir := filepath.Join(root, "collector-logs")
	utils.InitLogger(clientLogDir, utils.DEBUG)

	collector := NewWebLogCollector().WithDiscoveryInputs(webLogDiscoveryInputs{
		NginxConfigs: []string{confPath},
	}).WithScanOptions(webLogScanOptions{
		MaxDepth:          2,
		MaxFilesPerRoot:   10,
		MaxTotalFiles:     10,
		MaxSampleBytes:    4096,
		AllowedExtensions: []string{".log", ".txt"},
	})

	result, err := collector.Collect(t.Context())
	if err != nil {
		t.Fatalf("collect web logs: %v", err)
	}
	webResult := result.(*WebLogCollectionResult)
	if len(webResult.Sources) != 1 {
		t.Fatalf("expected 1 source, got %#v", webResult.Sources)
	}
	if len(webResult.Entries) != 0 {
		t.Fatalf("expected 0 entries, got %#v", webResult.Entries)
	}

	logFiles, err := filepath.Glob(filepath.Join(clientLogDir, "windows-host-collector-*.log"))
	if err != nil || len(logFiles) != 1 {
		t.Fatalf("expected one log file, got %v, err=%v", logFiles, err)
	}
	logBytes, err := os.ReadFile(logFiles[0])
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	logOutput := string(logBytes)
	if !strings.Contains(logOutput, "Web日志最终候选来源汇总") {
		t.Fatalf("expected discovery summary log, got %s", logOutput)
	}
	if !strings.Contains(logOutput, "Web日志候选文件") {
		t.Fatalf("expected candidate file log, got %s", logOutput)
	}
	if !strings.Contains(logOutput, "Web日志文件未解析出记录") {
		t.Fatalf("expected empty parse reason log, got %s", logOutput)
	}
}

func TestWebLogCollectorLogsRuntimeDiscoverySignals(t *testing.T) {
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
	logBody := "1.2.3.4 - - [21/Apr/2026:12:01:02 +0800] \"GET /runtime-log HTTP/1.1\" 200 1234 \"-\" \"curl/8.0\"\n"
	if err := os.WriteFile(logPath, []byte(logBody), 0o644); err != nil {
		t.Fatalf("write access log: %v", err)
	}

	confPath := filepath.Join(confDir, "nginx.conf")
	confBody := "events {}\nhttp {\n  access_log " + filepath.ToSlash(logPath) + ";\n}\n"
	if err := os.WriteFile(confPath, []byte(confBody), 0o644); err != nil {
		t.Fatalf("write nginx conf: %v", err)
	}

	clientLogDir := filepath.Join(root, "collector-logs")
	utils.InitLogger(clientLogDir, utils.DEBUG)

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

	result, err := collector.Collect(t.Context())
	if err != nil {
		t.Fatalf("collect web logs: %v", err)
	}
	webResult := result.(*WebLogCollectionResult)
	if len(webResult.Sources) != 1 || len(webResult.Entries) != 1 {
		t.Fatalf("expected one runtime-discovered source and entry, got sources=%#v entries=%#v", webResult.Sources, webResult.Entries)
	}

	logFiles, err := filepath.Glob(filepath.Join(clientLogDir, "windows-host-collector-*.log"))
	if err != nil || len(logFiles) != 1 {
		t.Fatalf("expected one log file, got %v, err=%v", logFiles, err)
	}
	logBytes, err := os.ReadFile(logFiles[0])
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	logOutput := string(logBytes)

	expectedSnippets := []string{
		"Web日志运行时发现候选进程",
		"Web日志运行时监听端口关联",
		"Web日志运行时配置推导",
		"Web日志运行时补充发现命中",
		"serverType=nginx",
		"processName=nginx.exe",
		"processPid=101",
		"port=8080",
		"configPath=" + confPath,
		"evidence=[",
		"LISTEN_PORT_MATCH",
		"PROCESS_COMMANDLINE_CONFIG",
		"PROCESS_NAME_MATCH",
	}
	for _, snippet := range expectedSnippets {
		if !strings.Contains(logOutput, snippet) {
			t.Fatalf("expected runtime discovery log snippet %q, got %s", snippet, logOutput)
		}
	}
}

func TestWebLogCollectorLogsFinalCandidateSummaryFromRuntimeResults(t *testing.T) {
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
	if err := os.WriteFile(logPath, []byte("1.2.3.4 - - [21/Apr/2026:12:01:02 +0800] \"GET /summary HTTP/1.1\" 200 1234 \"-\" \"curl/8.0\"\n"), 0o644); err != nil {
		t.Fatalf("write access log: %v", err)
	}

	confPath := filepath.Join(confDir, "nginx.conf")
	confBody := "events {}\nhttp {\n  access_log " + filepath.ToSlash(logPath) + ";\n}\n"
	if err := os.WriteFile(confPath, []byte(confBody), 0o644); err != nil {
		t.Fatalf("write nginx conf: %v", err)
	}

	clientLogDir := filepath.Join(root, "collector-logs")
	utils.InitLogger(clientLogDir, utils.DEBUG)

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

	result, err := collector.Collect(t.Context())
	if err != nil {
		t.Fatalf("collect web logs: %v", err)
	}
	webResult := result.(*WebLogCollectionResult)
	if len(webResult.Sources) != 1 {
		t.Fatalf("expected 1 source, got %#v", webResult.Sources)
	}

	logFiles, err := filepath.Glob(filepath.Join(clientLogDir, "windows-host-collector-*.log"))
	if err != nil || len(logFiles) != 1 {
		t.Fatalf("expected one log file, got %v, err=%v", logFiles, err)
	}
	logBytes, err := os.ReadFile(logFiles[0])
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	logOutput := string(logBytes)
	if !strings.Contains(logOutput, "Web日志最终候选来源汇总: iis=0 nginx=1 apache=0 tomcat=0 total=1") {
		t.Fatalf("expected final candidate summary to include runtime nginx source, got %s", logOutput)
	}
}

func TestWebLogCollectorSkipsDirectoryLogPathCandidates(t *testing.T) {
	root := t.TempDir()
	siteRoot := filepath.Join(root, "WWW")
	confDir := filepath.Join(root, "nginx", "conf")
	if err := os.MkdirAll(siteRoot, 0o755); err != nil {
		t.Fatalf("mkdir site root: %v", err)
	}
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatalf("mkdir conf dir: %v", err)
	}

	confPath := filepath.Join(confDir, "nginx.conf")
	confBody := "events {}\nhttp {\n  access_log " + filepath.ToSlash(siteRoot) + ";\n}\n"
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

	result, err := collector.Collect(t.Context())
	if err != nil {
		t.Fatalf("collect web logs: %v", err)
	}
	webResult := result.(*WebLogCollectionResult)
	if len(webResult.Sources) != 0 {
		t.Fatalf("expected directory candidate to be skipped, got %#v", webResult.Sources)
	}
}

func TestScanWebLogCandidateFilesRespectsLimits(t *testing.T) {
	root := t.TempDir()
	logDir := filepath.Join(root, "logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatalf("mkdir log dir: %v", err)
	}
	files := []string{
		filepath.Join(logDir, "access.log"),
		filepath.Join(logDir, "error.log"),
		filepath.Join(logDir, "app.log"),
	}
	for _, file := range files {
		if err := os.WriteFile(file, []byte("2026-04-21 test\n"), 0o644); err != nil {
			t.Fatalf("write file %s: %v", file, err)
		}
	}

	got, err := scanWebLogCandidateFiles([]string{logDir}, webLogScanOptions{
		MaxDepth:          2,
		MaxFilesPerRoot:   2,
		MaxTotalFiles:     2,
		MaxSampleBytes:    128,
		AllowedExtensions: []string{".log", ".txt"},
	})
	if err != nil {
		t.Fatalf("scan candidates: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected exactly 2 candidates due to limits, got %#v", got)
	}
}

func TestReadFileSampleIncludesTailForLargeAccessLogs(t *testing.T) {
	root := t.TempDir()
	logPath := filepath.Join(root, "access.log")
	body := strings.Repeat("old line\n", 1024) +
		`::1 - - [26/Feb/2024:22:24:20 +0800] "GET /install.php HTTP/1.1" 200 8321` + "\n"
	if err := os.WriteFile(logPath, []byte(body), 0o644); err != nil {
		t.Fatalf("write access log: %v", err)
	}

	got, err := readFileSample(logPath, 256)
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}
	if !strings.Contains(string(got), "/install.php") {
		t.Fatalf("expected tail sample to include recent access line, got %q", string(got))
	}
}

func TestReadFileSampleDecompressesGzipAccessLogs(t *testing.T) {
	root := t.TempDir()
	logPath := filepath.Join(root, "access.log.1.gz")
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte(`127.0.0.1 - - [26/Feb/2024:22:25:37 +0800] "GET /gzip HTTP/1.1" 200 2653` + "\n")); err != nil {
		t.Fatalf("write gzip payload: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	if err := os.WriteFile(logPath, compressed.Bytes(), 0o644); err != nil {
		t.Fatalf("write gzip log: %v", err)
	}

	got, err := readFileSample(logPath, 4096)
	if err != nil {
		t.Fatalf("read gzip sample: %v", err)
	}
	if !strings.Contains(string(got), "/gzip") {
		t.Fatalf("expected decompressed gzip sample, got %q", string(got))
	}
}
