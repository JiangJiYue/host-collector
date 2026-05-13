package collector

import (
	"testing"

	"windows-host-collector/models"
)

func TestBuildRuntimeWebLogCandidatesUsesExplicitNginxConfig(t *testing.T) {
	ctx := WebLogDiscoveryContext{
		Processes: []*models.ProcessBasicInfo{
			{PID: 101, ProcessName: "nginx.exe"},
		},
		ProcessDetails: map[int]*models.ProcessDetail{
			101: {
				BasicInfo: &models.ProcessBasicInfo{
					PID:         101,
					ProcessName: "nginx.exe",
					CommandLine: stringPtr(`nginx.exe -c D:\Env\nginx\conf\nginx.conf`),
					ImagePath:   stringPtr(`D:\Env\nginx\nginx.exe`),
				},
			},
		},
		NetworkSessions: []models.NetworkSession{
			{ProcessName: "nginx.exe", LocalPort: 80, StateName: "LISTEN"},
		},
	}

	got := buildRuntimeWebLogCandidates(ctx)
	if len(got) != 1 {
		t.Fatalf("expected 1 candidate, got %#v", got)
	}
	if len(got[0].ConfigHints) != 1 || got[0].ConfigHints[0] != `D:\Env\nginx\conf\nginx.conf` {
		t.Fatalf("unexpected config hints: %#v", got[0].ConfigHints)
	}
	if len(got[0].ListenPorts) != 1 || got[0].ListenPorts[0] != 80 {
		t.Fatalf("unexpected listen ports: %#v", got[0].ListenPorts)
	}
	if !containsString(got[0].Evidence, "PROCESS_NAME_MATCH") ||
		!containsString(got[0].Evidence, "PROCESS_COMMANDLINE_CONFIG") ||
		!containsString(got[0].Evidence, "LISTEN_PORT_MATCH") {
		t.Fatalf("unexpected evidence: %#v", got[0].Evidence)
	}
}

func TestBuildRuntimeWebLogCandidatesDerivesApacheConfigFromExecutablePath(t *testing.T) {
	ctx := WebLogDiscoveryContext{
		Processes: []*models.ProcessBasicInfo{
			{PID: 201, ProcessName: "httpd.exe"},
		},
		ProcessDetails: map[int]*models.ProcessDetail{
			201: {
				BasicInfo: &models.ProcessBasicInfo{
					PID:         201,
					ProcessName: "httpd.exe",
					ImagePath:   stringPtr(`D:\Apache24\bin\httpd.exe`),
				},
			},
		},
	}

	got := buildRuntimeWebLogCandidates(ctx)
	if len(got) != 1 {
		t.Fatalf("expected 1 candidate, got %#v", got)
	}
	if !containsString(got[0].ConfigHints, `D:\Apache24\conf\httpd.conf`) {
		t.Fatalf("expected apache config hint, got %#v", got[0].ConfigHints)
	}
	if !containsString(got[0].Evidence, "PROCESS_PATH_HINT") {
		t.Fatalf("unexpected evidence: %#v", got[0].Evidence)
	}
}

func TestBuildRuntimeWebLogCandidatesDerivesPhpStudyNginxLayout(t *testing.T) {
	ctx := WebLogDiscoveryContext{
		Processes: []*models.ProcessBasicInfo{
			{PID: 301, ProcessName: "php-cgi.exe"},
		},
		ProcessDetails: map[int]*models.ProcessDetail{
			301: {
				BasicInfo: &models.ProcessBasicInfo{
					PID:         301,
					ProcessName: "php-cgi.exe",
					ImagePath:   stringPtr(`D:\Env\phpstudy_pro\Extensions\php\php-cgi.exe`),
				},
			},
		},
		Software: []models.InstalledSoftwareItem{
			{Name: "phpstudy_pro", InstallLocation: `D:\Env\phpstudy_pro`},
		},
	}

	got := buildRuntimeWebLogCandidates(ctx)
	if len(got) != 3 {
		t.Fatalf("expected 3 candidates, got %#v", got)
	}

	expected := map[string]string{
		"nginx":  `D:\Env\phpstudy_pro\Extensions\Nginx*\conf\nginx.conf`,
		"apache": `D:\Env\phpstudy_pro\Extensions\Apache*\conf\httpd.conf`,
		"tomcat": `D:\Env\phpstudy_pro\Extensions\Tomcat*\conf\server.xml`,
	}
	for _, candidate := range got {
		hint, ok := expected[candidate.ServerType]
		if !ok {
			t.Fatalf("unexpected server type: %#v", candidate)
		}
		if len(candidate.ConfigHints) != 1 || candidate.ConfigHints[0] != hint {
			t.Fatalf("unexpected config hints for %s: %#v", candidate.ServerType, candidate.ConfigHints)
		}
		if candidate.ProcessName != "php-cgi.exe" || candidate.ProcessPID != 301 {
			t.Fatalf("unexpected process info for %s: %#v", candidate.ServerType, candidate)
		}
		if candidate.InstallLocation != `D:\Env\phpstudy_pro` {
			t.Fatalf("unexpected install location for %s: %#v", candidate.ServerType, candidate.InstallLocation)
		}
		if !containsString(candidate.Evidence, "SOFTWARE_INSTALL_LOCATION_HINT") ||
			!containsString(candidate.Evidence, "PHPSTUDY_LAYOUT_MATCH") {
			t.Fatalf("unexpected evidence for %s: %#v", candidate.ServerType, candidate.Evidence)
		}
		delete(expected, candidate.ServerType)
	}
	if len(expected) != 0 {
		t.Fatalf("missing expected server types: %#v", expected)
	}
}

func TestBuildRuntimeWebLogCandidatesDoesNotInventConfigHintsFromPortsOnly(t *testing.T) {
	ctx := WebLogDiscoveryContext{
		Processes: []*models.ProcessBasicInfo{
			{PID: 401, ProcessName: "unknown.exe"},
		},
		NetworkSessions: []models.NetworkSession{
			{ProcessName: "unknown.exe", LocalPort: 8080, StateName: "LISTEN"},
		},
	}

	got := buildRuntimeWebLogCandidates(ctx)
	if len(got) != 0 {
		t.Fatalf("expected no candidates, got %#v", got)
	}
}

func TestBuildRuntimeWebLogCandidatesDedupesAndSortsStably(t *testing.T) {
	ctx := WebLogDiscoveryContext{
		Processes: []*models.ProcessBasicInfo{
			{PID: 201, ProcessName: "httpd.exe"},
			{PID: 101, ProcessName: "nginx.exe"},
			{PID: 101, ProcessName: "nginx.exe"},
		},
		ProcessDetails: map[int]*models.ProcessDetail{
			101: {
				BasicInfo: &models.ProcessBasicInfo{
					PID:         101,
					ProcessName: "nginx.exe",
					CommandLine: stringPtr(`nginx.exe -c D:\Env\nginx\conf\nginx.conf`),
					ImagePath:   stringPtr(`D:\Env\nginx\nginx.exe`),
				},
			},
			201: {
				BasicInfo: &models.ProcessBasicInfo{
					PID:         201,
					ProcessName: "httpd.exe",
					ImagePath:   stringPtr(`D:\Apache24\bin\httpd.exe`),
				},
			},
		},
		NetworkSessions: []models.NetworkSession{
			{ProcessName: "nginx.exe", LocalPort: 80, StateName: "LISTEN"},
			{ProcessName: "nginx.exe", LocalPort: 80, StateName: "LISTEN"},
		},
	}

	got := buildRuntimeWebLogCandidates(ctx)
	if len(got) != 2 {
		t.Fatalf("expected 2 candidates, got %#v", got)
	}
	if got[0].ProcessName != "httpd.exe" || got[1].ProcessName != "nginx.exe" {
		t.Fatalf("unexpected candidate order: %#v", got)
	}
	if len(got[1].ListenPorts) != 1 || got[1].ListenPorts[0] != 80 {
		t.Fatalf("expected deduped listen port list, got %#v", got[1].ListenPorts)
	}
}

func TestBuildRuntimeWebLogCandidatesPrefersPerPIDListenPorts(t *testing.T) {
	ctx := WebLogDiscoveryContext{
		Processes: []*models.ProcessBasicInfo{
			{PID: 501, ProcessName: "nginx.exe"},
			{PID: 502, ProcessName: "nginx.exe"},
		},
		ProcessDetails: map[int]*models.ProcessDetail{
			501: {
				BasicInfo: &models.ProcessBasicInfo{
					PID:         501,
					ProcessName: "nginx.exe",
					CommandLine: stringPtr(`nginx.exe -c D:\Env\nginx-a\conf\nginx.conf`),
					ImagePath:   stringPtr(`D:\Env\nginx-a\nginx.exe`),
				},
				NetworkConnections: []models.ProcessNetworkConnection{
					{LocalPort: 80, StateName: "LISTEN"},
				},
			},
			502: {
				BasicInfo: &models.ProcessBasicInfo{
					PID:         502,
					ProcessName: "nginx.exe",
					CommandLine: stringPtr(`nginx.exe -c D:\Env\nginx-b\conf\nginx.conf`),
					ImagePath:   stringPtr(`D:\Env\nginx-b\nginx.exe`),
				},
				NetworkConnections: []models.ProcessNetworkConnection{
					{LocalPort: 8080, StateName: "LISTEN"},
				},
			},
		},
		NetworkSessions: []models.NetworkSession{
			{ProcessName: "nginx.exe", LocalPort: 80, StateName: "LISTEN"},
			{ProcessName: "nginx.exe", LocalPort: 8080, StateName: "LISTEN"},
		},
	}

	got := buildRuntimeWebLogCandidates(ctx)
	if len(got) != 2 {
		t.Fatalf("expected 2 candidates, got %#v", got)
	}
	if got[0].ProcessPID != 501 || len(got[0].ListenPorts) != 1 || got[0].ListenPorts[0] != 80 {
		t.Fatalf("unexpected ports for pid 501: %#v", got[0])
	}
	if got[1].ProcessPID != 502 || len(got[1].ListenPorts) != 1 || got[1].ListenPorts[0] != 8080 {
		t.Fatalf("unexpected ports for pid 502: %#v", got[1])
	}
}

func stringPtr(v string) *string {
	return &v
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsGlobHint(values []string, target string) bool {
	return containsString(values, target)
}
