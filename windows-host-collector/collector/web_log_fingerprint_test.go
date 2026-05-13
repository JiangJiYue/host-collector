package collector

import "testing"

func TestFingerprintWebLogSampleDetectsIISW3C(t *testing.T) {
	sample := []byte("#Software: Microsoft Internet Information Services 10.0\r\n#Fields: date time c-ip cs-method cs-uri-stem cs-uri-query s-port cs(User-Agent) cs(Referer) cs-host sc-status sc-bytes\r\n2026-04-21 12:01:02 1.2.3.4 GET /index.php id=1 80 Mozilla/5.0 - example.com 200 1234\r\n")

	got := fingerprintWebLogSample(`C:\inetpub\logs\LogFiles\W3SVC1\u_ex260421.log`, sample)

	if got.Format != webLogFormatIISW3C {
		t.Fatalf("expected IIS W3C format, got %#v", got)
	}
	if got.Confidence != webLogConfidenceHigh {
		t.Fatalf("expected high confidence, got %#v", got.Confidence)
	}
	if !hasString(got.Evidence, "IIS_FIELDS_HEADER") {
		t.Fatalf("expected IIS_FIELDS_HEADER evidence, got %#v", got.Evidence)
	}
}

func TestFingerprintWebLogSampleDetectsCombinedFormat(t *testing.T) {
	sample := []byte("1.2.3.4 - - [21/Apr/2026:12:01:02 +0800] \"POST /upload HTTP/1.1\" 200 1234 \"https://example.com\" \"curl/8.0\"\n")

	got := fingerprintWebLogSample(`C:\nginx\logs\access.log`, sample)

	if got.Format != webLogFormatCombined {
		t.Fatalf("expected combined format, got %#v", got)
	}
	if got.Confidence != webLogConfidenceHigh {
		t.Fatalf("expected high confidence, got %#v", got.Confidence)
	}
	if !hasString(got.Evidence, "COMBINED_LOG_PATTERN") {
		t.Fatalf("expected COMBINED_LOG_PATTERN evidence, got %#v", got.Evidence)
	}
}

func TestFingerprintWebLogSampleDetectsJSONAccessFormat(t *testing.T) {
	sample := []byte("{\"time\":\"2026-04-21T12:01:02Z\",\"remote_addr\":\"1.2.3.4\",\"method\":\"GET\",\"request_uri\":\"/\",\"status\":200,\"body_bytes_sent\":1234,\"http_user_agent\":\"curl/8.0\"}\n")

	got := fingerprintWebLogSample(`C:\app\logs\access.json.log`, sample)

	if got.Format != webLogFormatJSONAccess {
		t.Fatalf("expected json access format, got %#v", got)
	}
	if got.Confidence != webLogConfidenceHigh {
		t.Fatalf("expected high confidence, got %#v", got.Confidence)
	}
	if !hasString(got.Evidence, "JSON_ACCESS_KEYS") {
		t.Fatalf("expected JSON_ACCESS_KEYS evidence, got %#v", got.Evidence)
	}
}

func TestFingerprintWebLogSampleReturnsLowConfidenceForGenericLog(t *testing.T) {
	sample := []byte("2026-04-21 12:01:02 INFO background task started\n")

	got := fingerprintWebLogSample(`C:\app\logs\app.log`, sample)

	if got.Format != webLogFormatUnknown {
		t.Fatalf("expected unknown format, got %#v", got)
	}
	if got.Confidence != webLogConfidenceLow {
		t.Fatalf("expected low confidence, got %#v", got.Confidence)
	}
}
