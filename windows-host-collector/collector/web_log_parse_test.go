package collector

import "testing"

func TestParseWebLogLineParsesIISW3CEntry(t *testing.T) {
	source := webLogSourceCandidate{
		ServerType:  "iis",
		SiteName:    "Default Web Site",
		ProcessName: "w3wp.exe",
		ProcessPID:  1234,
	}
	state := webLogParseState{
		Format:    webLogFormatIISW3C,
		IISFields: []string{"date", "time", "c-ip", "cs-method", "cs-uri-stem", "cs-uri-query", "cs-host", "sc-status", "sc-bytes", "cs(User-Agent)", "cs(Referer)"},
	}

	entry, nextState, ok := parseWebLogLine("sha256:source", source, state, `2026-04-21 12:01:02 1.2.3.4 POST /upload/index.php id=1 example.com 200 1234 curl/8.0 -`)
	if !ok {
		t.Fatal("expected IIS W3C line to parse")
	}
	if entry.SourceID != "sha256:source" || entry.Method != "POST" || entry.URI != "/upload/index.php?id=1" {
		t.Fatalf("unexpected IIS entry: %#v", entry)
	}
	if entry.ClientIP != "1.2.3.4" || entry.Status != 200 || entry.BytesSent != 1234 {
		t.Fatalf("unexpected IIS entry fields: %#v", entry)
	}
	if entry.ServerType != "iis" || entry.SiteName != "Default Web Site" || entry.ProcessPID != 1234 {
		t.Fatalf("expected source metadata to flow into entry, got %#v", entry)
	}
	if nextState.Format != webLogFormatIISW3C {
		t.Fatalf("expected IIS parse state to remain intact, got %#v", nextState)
	}
}

func TestParseWebLogLineParsesCombinedEntry(t *testing.T) {
	source := webLogSourceCandidate{ServerType: "nginx"}
	state := webLogParseState{Format: webLogFormatCombined}

	entry, _, ok := parseWebLogLine("sha256:source", source, state, `1.2.3.4 - - [21/Apr/2026:12:01:02 +0800] "GET /index.html HTTP/1.1" 200 1234 "https://example.com/start" "curl/8.0"`)
	if !ok {
		t.Fatal("expected combined line to parse")
	}
	if entry.Method != "GET" || entry.URI != "/index.html" || entry.Protocol != "HTTP/1.1" {
		t.Fatalf("unexpected combined entry: %#v", entry)
	}
	if entry.Timestamp != "2026-04-21T12:01:02+08:00" {
		t.Fatalf("expected combined timestamp normalized to RFC3339, got %#v", entry.Timestamp)
	}
	if entry.Referer != "https://example.com/start" || entry.UserAgent != "curl/8.0" {
		t.Fatalf("unexpected combined metadata: %#v", entry)
	}
}

func TestParseWebLogLineParsesCommonAccessEntry(t *testing.T) {
	source := webLogSourceCandidate{ServerType: "apache", SiteName: "phpstudy"}
	state := webLogParseState{Format: webLogFormatCombined}

	entry, _, ok := parseWebLogLine("sha256:source", source, state, `::1 - - [26/Feb/2024:22:24:20 +0800] "GET /install.php HTTP/1.1" 200 8321`)
	if !ok {
		t.Fatal("expected common access line to parse")
	}
	if entry.ClientIP != "::1" || entry.Method != "GET" || entry.URI != "/install.php" || entry.Protocol != "HTTP/1.1" {
		t.Fatalf("unexpected common access entry: %#v", entry)
	}
	if entry.Status != 200 || entry.BytesSent != 8321 {
		t.Fatalf("unexpected common response fields: %#v", entry)
	}
	if entry.Timestamp != "2024-02-26T22:24:20+08:00" {
		t.Fatalf("expected common timestamp normalized to RFC3339, got %#v", entry.Timestamp)
	}
}

func TestParseWebLogLineParsesForwardedAndTimedAccessEntry(t *testing.T) {
	source := webLogSourceCandidate{ServerType: "nginx", SiteName: "admin"}
	state := webLogParseState{Format: webLogFormatCombined}

	entry, _, ok := parseWebLogLine("sha256:source", source, state, `admin.example.com 10.0.0.5 203.0.113.9 - - [26/Feb/2024:22:25:36 +0800] "GET /admin.php HTTP/1.1" 403 6182 "https://example.com/" "Mozilla/5.0" 0.123`)
	if !ok {
		t.Fatal("expected forwarded timed access line to parse")
	}
	if entry.Host != "admin.example.com" || entry.ClientIP != "203.0.113.9" {
		t.Fatalf("expected host and forwarded client IP, got %#v", entry)
	}
	if entry.URI != "/admin.php" || entry.Status != 403 || entry.BytesSent != 6182 {
		t.Fatalf("unexpected parsed forwarded timed entry: %#v", entry)
	}
}

func TestParseWebLogLineParsesTomcatAccessEntry(t *testing.T) {
	source := webLogSourceCandidate{ServerType: "tomcat"}
	state := webLogParseState{Format: webLogFormatCombined}

	entry, _, ok := parseWebLogLine("sha256:source", source, state, `127.0.0.1 - - [26/Feb/2024:22:25:37 +0800] "GET /manager/html HTTP/1.1" 401 2653 12`)
	if !ok {
		t.Fatal("expected tomcat access line with elapsed time to parse")
	}
	if entry.ClientIP != "127.0.0.1" || entry.URI != "/manager/html" || entry.Status != 401 {
		t.Fatalf("unexpected tomcat access entry: %#v", entry)
	}
}

func TestParseWebLogLineFallsBackToRawForUnknownAccessLine(t *testing.T) {
	source := webLogSourceCandidate{ServerType: "custom"}
	state := webLogParseState{Format: webLogFormatUnknown}
	line := `2024-02-26 22:24:20 127.0.0.1 GET /install.php status=200 bytes=8321`

	entry, _, ok := parseWebLogLine("sha256:source", source, state, line)
	if !ok {
		t.Fatal("expected unknown access-like line to be preserved as raw")
	}
	if entry.Method != "RAW" || entry.URI != line || entry.Raw != line {
		t.Fatalf("expected raw fallback entry, got %#v", entry)
	}
}

func TestParseWebLogLineParsesJSONAccessEntry(t *testing.T) {
	source := webLogSourceCandidate{ServerType: "custom"}
	state := webLogParseState{Format: webLogFormatJSONAccess}

	entry, _, ok := parseWebLogLine("sha256:source", source, state, `{"time":"2026-04-21T12:01:02Z","remote_addr":"1.2.3.4","method":"GET","request_uri":"/","status":200,"body_bytes_sent":1234,"http_user_agent":"curl/8.0","http_referer":"-"}`)
	if !ok {
		t.Fatal("expected JSON access line to parse")
	}
	if entry.Timestamp != "2026-04-21T12:01:02Z" || entry.ClientIP != "1.2.3.4" {
		t.Fatalf("unexpected json entry: %#v", entry)
	}
	if entry.Method != "GET" || entry.URI != "/" || entry.Status != 200 {
		t.Fatalf("unexpected json entry values: %#v", entry)
	}
}
