package weblogdiscovery

import (
	"strings"
	"testing"
)

func TestBuildRuntimeCandidatesInfersLinuxNginxConfigFromCommandLine(t *testing.T) {
	got := BuildRuntimeCandidates(Context{
		Platform: PlatformLinux,
		Processes: []ProcessSignal{{
			PID:            101,
			Name:           "nginx",
			ExecutablePath: "/usr/sbin/nginx",
			CommandLine:    `nginx -c /opt/nginx/conf/nginx.conf -g "daemon off;"`,
		}},
		Listeners: []ListenerSignal{{ProcessPID: 101, ProcessName: "nginx", Port: 8080}},
	})

	if len(got) != 1 {
		t.Fatalf("expected one candidate, got %#v", got)
	}
	candidate := got[0]
	if candidate.ServerType != "nginx" || candidate.ProcessPID != 101 || candidate.ProcessName != "nginx" {
		t.Fatalf("unexpected candidate identity: %#v", candidate)
	}
	if strings.Join(candidate.ConfigHints, ",") != "/opt/nginx/conf/nginx.conf,/usr/sbin/conf/nginx.conf" {
		t.Fatalf("unexpected config hints: %#v", candidate.ConfigHints)
	}
	if len(candidate.ListenPorts) != 1 || candidate.ListenPorts[0] != 8080 {
		t.Fatalf("unexpected listen ports: %#v", candidate.ListenPorts)
	}
	assertEvidence(t, candidate.Evidence, EvidenceProcessCommandLineConfig)
	assertEvidence(t, candidate.Evidence, EvidenceProcessPathHint)
	assertEvidence(t, candidate.Evidence, EvidenceListenPortMatch)
}

func TestBuildRuntimeCandidatesInfersLinuxApacheConfigFromExecutablePath(t *testing.T) {
	got := BuildRuntimeCandidates(Context{
		Platform: PlatformLinux,
		Processes: []ProcessSignal{{
			PID:            202,
			Name:           "apache2",
			ExecutablePath: "/usr/sbin/apache2",
			CommandLine:    "apache2 -DFOREGROUND",
		}},
	})

	if len(got) != 1 {
		t.Fatalf("expected one candidate, got %#v", got)
	}
	want := "/etc/apache2/apache2.conf,/etc/httpd/conf/httpd.conf,/usr/sbin/conf/httpd.conf"
	if strings.Join(got[0].ConfigHints, ",") != want {
		t.Fatalf("unexpected config hints: %#v", got[0].ConfigHints)
	}
}

func TestBuildRuntimeCandidatesInfersLinuxTomcatServerXML(t *testing.T) {
	got := BuildRuntimeCandidates(Context{
		Platform: PlatformLinux,
		Processes: []ProcessSignal{{
			PID:         303,
			Name:        "java",
			CommandLine: `java -Dcatalina.base=/opt/tomcat -jar bootstrap.jar`,
		}},
	})

	if len(got) != 1 {
		t.Fatalf("expected one candidate, got %#v", got)
	}
	if got[0].ServerType != "tomcat" || strings.Join(got[0].ConfigHints, ",") != "/opt/tomcat/conf/server.xml" {
		t.Fatalf("unexpected tomcat candidate: %#v", got[0])
	}
	assertEvidence(t, got[0].Evidence, EvidenceProcessCommandLineConfig)
}

func assertEvidence(t *testing.T, evidence []string, want string) {
	t.Helper()
	for _, item := range evidence {
		if item == want {
			return
		}
	}
	t.Fatalf("missing evidence %q in %#v", want, evidence)
}
