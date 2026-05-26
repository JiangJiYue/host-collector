package collector

import (
	"encoding/json"
	"strings"
)

func fingerprintWebLogSample(path string, sample []byte) webLogFingerprint {
	text := strings.TrimSpace(strings.ReplaceAll(string(sample), "\r\n", "\n"))
	lowerPath := strings.ToLower(path)

	if strings.Contains(text, "#Fields:") && strings.Contains(text, "cs-method") && strings.Contains(text, "sc-status") {
		return webLogFingerprint{
			Format:     webLogFormatIISW3C,
			Confidence: webLogConfidenceHigh,
			Evidence:   []string{"IIS_FIELDS_HEADER"},
		}
	}

	if looksLikeCombinedLog(text) {
		return webLogFingerprint{
			Format:     webLogFormatCombined,
			Confidence: webLogConfidenceHigh,
			Evidence:   []string{"COMBINED_LOG_PATTERN"},
		}
	}

	if looksLikeJSONAccessLog(text) {
		return webLogFingerprint{
			Format:     webLogFormatJSONAccess,
			Confidence: webLogConfidenceHigh,
			Evidence:   []string{"JSON_ACCESS_KEYS"},
		}
	}

	if strings.Contains(lowerPath, `\inetpub\logs\`) || strings.Contains(lowerPath, `\nginx\logs\`) || isAccessLogPath(path) {
		return webLogFingerprint{
			Format:     webLogFormatUnknown,
			Confidence: webLogConfidenceMedium,
			Evidence:   []string{"WEB_LOG_PATH_HINT"},
		}
	}

	return webLogFingerprint{
		Format:     webLogFormatUnknown,
		Confidence: webLogConfidenceLow,
		Evidence:   nil,
	}
}

func looksLikeCombinedLog(text string) bool {
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if combinedLogPattern.MatchString(line) {
			return true
		}
		if forwardedTimedLogPattern.MatchString(line) {
			return true
		}
	}
	return false
}

func looksLikeJSONAccessLog(text string) bool {
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(line), &payload); err != nil {
			continue
		}
		if hasAnyKey(payload, "remote_addr", "client_ip", "c_ip") &&
			hasAnyKey(payload, "request_uri", "uri", "url") &&
			hasAnyKey(payload, "status", "status_code") {
			return true
		}
	}
	return false
}

func hasAnyKey(payload map[string]any, keys ...string) bool {
	for _, key := range keys {
		if _, ok := payload[key]; ok {
			return true
		}
	}
	return false
}

func hasString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
