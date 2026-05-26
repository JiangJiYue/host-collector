package weblogs

import (
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"

	"linux-host-collector/internal/collectors/network"
	"linux-host-collector/internal/collectors/process"
)

func TestCollectDiscoversNginxLogsFromRuntimeSignals(t *testing.T) {
	root := filepath.Join("..", "testdata", "root")
	processResult, err := process.Collect(root)
	if err != nil {
		t.Fatalf("collect processes: %v", err)
	}
	networkResult, err := network.Collect(root)
	if err != nil {
		t.Fatalf("collect network: %v", err)
	}

	result, err := Collect(Config{
		Root:        root,
		Processes:   processResult.Processes,
		Connections: networkResult.Connections,
	})
	if err != nil {
		t.Fatalf("collect web logs: %v", err)
	}
	if len(result.Sources) != 1 {
		t.Fatalf("expected one source, got %#v", result.Sources)
	}
	source := result.Sources[0]
	if source.Path != "/var/log/nginx/access.log.txt" || source.ServerType != "nginx" || source.SourceMethod != "runtimeProcessConfig" {
		t.Fatalf("unexpected source: %#v", source)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("expected one entry, got %#v", result.Entries)
	}
	entry := result.Entries[0]
	if entry.ClientIP != "127.0.0.1" || entry.Method != "GET" || entry.URI != "/index.html" || entry.Status != 200 || entry.ServerType != "nginx" {
		t.Fatalf("unexpected entry: %#v", entry)
	}
}

func TestCollectWebLogMatrixFixtures(t *testing.T) {
	root := t.TempDir()
	line := `127.0.0.1 - - [09/May/2026:08:00:01 +0000] "GET /index.html HTTP/1.1" 200 123 "-" "curl/8"` + "\n"
	mustWrite(t, filepath.Join(root, "etc", "nginx", "nginx.conf"), "access_log /var/log/nginx/access.log;\n")
	mustWrite(t, filepath.Join(root, "var", "log", "nginx", "access.log"), line)
	mustWrite(t, filepath.Join(root, "var", "log", "nginx", "access.log.1"), line)
	mustWrite(t, filepath.Join(root, "var", "log", "nginx", "access.log.20260523"), line)
	mustWriteGzip(t, filepath.Join(root, "var", "log", "nginx", "access.log.2.gz"), line)
	mustWrite(t, filepath.Join(root, "etc", "httpd", "conf", "httpd.conf"), "CustomLog /var/log/httpd/access_log combined\n")
	mustWrite(t, filepath.Join(root, "var", "log", "httpd", "access_log"), line)
	mustWrite(t, filepath.Join(root, "opt", "tomcat", "conf", "server.xml"), `<Server><Service><Engine><Host><Valve className="org.apache.catalina.valves.AccessLogValve" directory="/opt/tomcat/logs" prefix="localhost_access_log" suffix=".txt" /></Host></Engine></Service></Server>`)
	mustWrite(t, filepath.Join(root, "opt", "tomcat", "logs", "localhost_access_log.2026-05-09.txt"), line)

	result, err := Collect(Config{
		Root: root,
		Processes: []process.Process{
			{PID: 10, Name: "nginx", CommandLine: "nginx -c /etc/nginx/nginx.conf"},
			{PID: 11, Name: "httpd", CommandLine: "httpd -f /etc/httpd/conf/httpd.conf"},
			{PID: 12, Name: "java", CommandLine: "java -Dcatalina.base=/opt/tomcat -jar bootstrap.jar"},
		},
		Connections: []network.Connection{
			{LocalPort: 80, Listen: true},
			{LocalPort: 8080, Listen: true},
		},
	})
	if err != nil {
		t.Fatalf("collect web logs: %v", err)
	}

	for _, want := range []string{
		"/var/log/nginx/access.log",
		"/var/log/nginx/access.log.1",
		"/var/log/nginx/access.log.20260523",
		"/var/log/nginx/access.log.2.gz",
		"/var/log/httpd/access_log",
		"/opt/tomcat/logs/localhost_access_log.2026-05-09.txt",
	} {
		if !hasSourcePath(result.Sources, want) {
			t.Fatalf("expected source %s in %#v", want, result.Sources)
		}
	}
	if len(result.Entries) != 6 {
		t.Fatalf("expected six web log entries, got %#v", result.Entries)
	}
}

func TestCollectDiscoversBaoTaWebsiteLogsFromPanelVhostConfigs(t *testing.T) {
	root := t.TempDir()
	line := `127.0.0.1 - - [09/May/2026:08:00:01 +0000] "GET /bt-site HTTP/1.1" 200 123 "-" "curl/8"` + "\n"
	mustWrite(t, filepath.Join(root, "www", "server", "panel", "vhost", "nginx", "example.com.conf"), `
server {
    server_name example.com;
    access_log /www/wwwlogs/example.com.log;
}
`)
	mustWrite(t, filepath.Join(root, "www", "wwwlogs", "example.com.log"), line)
	mustWrite(t, filepath.Join(root, "www", "server", "panel", "logs", "panel.log"), line)

	result, err := Collect(Config{Root: root})
	if err != nil {
		t.Fatalf("collect web logs: %v", err)
	}
	if len(result.Sources) != 1 {
		t.Fatalf("expected only the website source, got %#v", result.Sources)
	}
	source := result.Sources[0]
	if source.Path != "/www/wwwlogs/example.com.log" || source.ServerType != "nginx" || source.SourceMethod != "baotaPanelVhostConfig" {
		t.Fatalf("unexpected baota website source: %#v", source)
	}
	if !containsString(source.Evidence, "BAOTA_PANEL_VHOST_CONFIG") {
		t.Fatalf("expected baota panel vhost evidence, got %#v", source.Evidence)
	}
	if len(result.Entries) != 1 || result.Entries[0].URI != "/bt-site" {
		t.Fatalf("expected baota website access entry, got %#v", result.Entries)
	}
}

func TestCollectDiscoversOnePanelWebsiteLogsFromOpenRestyContainerPaths(t *testing.T) {
	root := t.TempDir()
	line := `127.0.0.1 - - [09/May/2026:08:00:01 +0000] "GET /onepanel-site HTTP/1.1" 200 123 "-" "curl/8"` + "\n"
	mustWrite(t, filepath.Join(root, "opt", "1panel", "apps", "openresty", "openresty", "conf", "conf.d", "example.com.conf"), `
server {
    server_name example.com;
    access_log /www/sites/example.com/log/access.log main;
}
`)
	mustWrite(t, filepath.Join(root, "opt", "1panel", "apps", "openresty", "openresty", "www", "sites", "example.com", "log", "access.log"), line)
	mustWrite(t, filepath.Join(root, "opt", "1panel", "logs", "1Panel.log"), line)

	result, err := Collect(Config{Root: root})
	if err != nil {
		t.Fatalf("collect web logs: %v", err)
	}
	if len(result.Sources) != 1 {
		t.Fatalf("expected only the website source, got %#v", result.Sources)
	}
	source := result.Sources[0]
	wantPath := "/opt/1panel/apps/openresty/openresty/www/sites/example.com/log/access.log"
	if source.Path != wantPath || source.ServerType != "openresty" || source.SourceMethod != "onePanelWebsiteConfig" {
		t.Fatalf("unexpected 1Panel website source: %#v", source)
	}
	if !containsString(source.Evidence, "ONEPANEL_OPENRESTY_WEBSITE_CONFIG") || !containsString(source.Evidence, "ONEPANEL_CONTAINER_PATH_MAPPING") {
		t.Fatalf("expected 1Panel website evidence, got %#v", source.Evidence)
	}
	if len(result.Entries) != 1 || result.Entries[0].URI != "/onepanel-site" {
		t.Fatalf("expected 1Panel website access entry, got %#v", result.Entries)
	}
}

func TestCollectDiscoversPhpStudyDefaultAccessLogsAndSkipsErrorLogs(t *testing.T) {
	root := t.TempDir()
	line := `127.0.0.1 - - [09/May/2026:08:00:01 +0000] "GET /phpstudy HTTP/1.1" 200 123 "-" "curl/8"` + "\n"
	errorLine := "[Mon Feb 26 23:01:14.000000 2024] [php7:error] [pid 1234] webshell touched hack168$\n"
	mustWrite(t, filepath.Join(root, "phpstudy_pro", "Extensions", "Apache2.4.39", "logs", "access.log"), "")
	mustWrite(t, filepath.Join(root, "phpstudy_pro", "Extensions", "Apache2.4.39", "logs", "access.log.20260523"), line)
	mustWrite(t, filepath.Join(root, "phpstudy_pro", "Extensions", "Apache2.4.39", "logs", "error.log"), errorLine)
	mustWrite(t, filepath.Join(root, "phpstudy_pro", "Extensions", "Nginx1.23.4", "logs", "access.log"), "")
	mustWrite(t, filepath.Join(root, "phpstudy_pro", "Extensions", "Nginx1.23.4", "logs", "error.log"), "")

	result, err := Collect(Config{Root: root})
	if err != nil {
		t.Fatalf("collect web logs: %v", err)
	}

	for _, want := range []string{
		"/phpstudy_pro/Extensions/Apache2.4.39/logs/access.log",
		"/phpstudy_pro/Extensions/Apache2.4.39/logs/access.log.20260523",
		"/phpstudy_pro/Extensions/Nginx1.23.4/logs/access.log",
	} {
		if !hasSourcePath(result.Sources, want) {
			t.Fatalf("expected phpStudy source %s in %#v", want, result.Sources)
		}
	}
	if hasSourcePath(result.Sources, "/phpstudy_pro/Extensions/Apache2.4.39/logs/error.log") ||
		hasSourcePath(result.Sources, "/phpstudy_pro/Extensions/Nginx1.23.4/logs/error.log") {
		t.Fatalf("did not expect phpStudy error.log sources, got %#v", result.Sources)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("expected only access entries, got %#v", result.Entries)
	}
	if !hasEntry(result.Entries, "GET", "/phpstudy") {
		t.Fatalf("expected parsed phpStudy access entry, got %#v", result.Entries)
	}
	if hasEntry(result.Entries, "RAW", errorLine[:len(errorLine)-1]) {
		t.Fatalf("did not expect raw phpStudy error entry, got %#v", result.Entries)
	}
}

func hasSourcePath(sources []Source, path string) bool {
	for _, source := range sources {
		if source.Path == path {
			return true
		}
	}
	return false
}

func hasEntry(entries []Entry, method string, uri string) bool {
	for _, entry := range entries {
		if entry.Method == method && entry.URI == uri {
			return true
		}
	}
	return false
}

func containsString(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func mustWrite(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir fixture: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

func mustWriteGzip(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir gzip fixture: %v", err)
	}
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create gzip fixture: %v", err)
	}
	writer := gzip.NewWriter(file)
	if _, err := writer.Write([]byte(content)); err != nil {
		t.Fatalf("write gzip fixture: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close gzip file: %v", err)
	}
}
