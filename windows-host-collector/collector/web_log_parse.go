package collector

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"windows-host-collector/models"
)

var combinedLogPattern = regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) ([^ ]+) ([^"]+)" (\d{3}) (\d+|-)(?: "([^"]*)" "([^"]*)")?(?: \S+)?$`)
var forwardedTimedLogPattern = regexp.MustCompile(`^(\S+) (\S+) (\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) ([^ ]+) ([^"]+)" (\d{3}) (\d+|-)(?: "([^"]*)" "([^"]*)")?(?: \S+)?$`)

func parseWebLogLine(sourceID string, source webLogSourceCandidate, state webLogParseState, line string) (models.WebLogEntry, webLogParseState, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return models.WebLogEntry{}, state, false
	}

	if state.Format == webLogFormatIISW3C {
		if strings.HasPrefix(line, "#Fields:") {
			next := state
			next.IISFields = strings.Fields(strings.TrimSpace(strings.TrimPrefix(line, "#Fields:")))
			return models.WebLogEntry{}, next, false
		}
		if strings.HasPrefix(line, "#") || len(state.IISFields) == 0 {
			return models.WebLogEntry{}, state, false
		}
		entry, ok := parseIISW3CLine(sourceID, source, state.IISFields, line)
		return entry, state, ok
	}

	if state.Format == webLogFormatCombined {
		entry, ok := parseCombinedLine(sourceID, source, line)
		return entry, state, ok
	}

	if state.Format == webLogFormatJSONAccess {
		entry, ok := parseJSONAccessLine(sourceID, source, line)
		return entry, state, ok
	}

	if state.Format == webLogFormatRaw {
		return models.WebLogEntry{
			SourceID:    sourceID,
			Method:      "RAW",
			URI:         line,
			ServerType:  source.ServerType,
			SiteName:    source.SiteName,
			ProcessName: source.ProcessName,
			ProcessPID:  source.ProcessPID,
			Raw:         line,
		}, state, true
	}

	if looksLikeAccessLogLine(line) {
		return rawWebLogEntry(sourceID, source, line), state, true
	}

	return models.WebLogEntry{}, state, false
}

func parseIISW3CLine(sourceID string, source webLogSourceCandidate, fields []string, line string) (models.WebLogEntry, bool) {
	values := strings.Fields(line)
	if len(values) < len(fields) {
		return models.WebLogEntry{}, false
	}
	row := make(map[string]string, len(fields))
	for idx, field := range fields {
		row[field] = values[idx]
	}

	status, err := strconv.Atoi(defaultString(row["sc-status"], "0"))
	if err != nil {
		return models.WebLogEntry{}, false
	}
	bytesSent, err := strconv.ParseInt(defaultString(row["sc-bytes"], "0"), 10, 64)
	if err != nil {
		return models.WebLogEntry{}, false
	}

	uri := row["cs-uri-stem"]
	if query := row["cs-uri-query"]; query != "" && query != "-" {
		uri = uri + "?" + query
	}

	return models.WebLogEntry{
		SourceID:    sourceID,
		Timestamp:   strings.TrimSpace(row["date"] + "T" + row["time"] + "Z"),
		ClientIP:    normalizeDash(row["c-ip"]),
		Method:      normalizeDash(row["cs-method"]),
		URI:         normalizeDash(uri),
		Status:      status,
		BytesSent:   bytesSent,
		UserAgent:   normalizeDash(row["cs(User-Agent)"]),
		Referer:     normalizeDash(row["cs(Referer)"]),
		Host:        normalizeDash(row["cs-host"]),
		ServerType:  source.ServerType,
		SiteName:    source.SiteName,
		ProcessName: source.ProcessName,
		ProcessPID:  source.ProcessPID,
	}, true
}

func parseCombinedLine(sourceID string, source webLogSourceCandidate, line string) (models.WebLogEntry, bool) {
	if entry, ok := parseForwardedTimedLine(sourceID, source, line); ok {
		return entry, true
	}
	matches := combinedLogPattern.FindStringSubmatch(line)
	if len(matches) != 10 {
		return models.WebLogEntry{}, false
	}

	status, err := strconv.Atoi(matches[6])
	if err != nil {
		return models.WebLogEntry{}, false
	}
	bytesSent, err := strconv.ParseInt(strings.ReplaceAll(matches[7], "-", "0"), 10, 64)
	if err != nil {
		return models.WebLogEntry{}, false
	}
	return models.WebLogEntry{
		SourceID:    sourceID,
		Timestamp:   normalizeApacheTimestamp(matches[2]),
		ClientIP:    matches[1],
		Method:      matches[3],
		URI:         matches[4],
		Protocol:    matches[5],
		Status:      status,
		BytesSent:   bytesSent,
		Referer:     normalizeDash(matches[8]),
		UserAgent:   normalizeDash(matches[9]),
		ServerType:  source.ServerType,
		SiteName:    source.SiteName,
		ProcessName: source.ProcessName,
		ProcessPID:  source.ProcessPID,
	}, true
}

func parseForwardedTimedLine(sourceID string, source webLogSourceCandidate, line string) (models.WebLogEntry, bool) {
	matches := forwardedTimedLogPattern.FindStringSubmatch(line)
	if len(matches) != 12 {
		return models.WebLogEntry{}, false
	}

	status, err := strconv.Atoi(matches[8])
	if err != nil {
		return models.WebLogEntry{}, false
	}
	bytesSent, err := strconv.ParseInt(strings.ReplaceAll(matches[9], "-", "0"), 10, 64)
	if err != nil {
		return models.WebLogEntry{}, false
	}
	timestamp := normalizeApacheTimestamp(matches[4])
	clientIP := normalizeDash(matches[3])
	if clientIP == "" {
		clientIP = normalizeDash(matches[2])
	}

	return models.WebLogEntry{
		SourceID:    sourceID,
		Timestamp:   timestamp,
		ClientIP:    clientIP,
		Method:      matches[5],
		URI:         matches[6],
		Protocol:    matches[7],
		Status:      status,
		BytesSent:   bytesSent,
		Referer:     normalizeDash(matches[10]),
		UserAgent:   normalizeDash(matches[11]),
		Host:        normalizeDash(matches[1]),
		ServerType:  source.ServerType,
		SiteName:    source.SiteName,
		ProcessName: source.ProcessName,
		ProcessPID:  source.ProcessPID,
	}, true
}

func normalizeApacheTimestamp(value string) string {
	timestamp, err := time.Parse("02/Jan/2006:15:04:05 -0700", value)
	if err != nil {
		return value
	}
	return timestamp.Format(time.RFC3339)
}

func looksLikeAccessLogLine(line string) bool {
	return strings.Contains(line, " ") &&
		(strings.Contains(line, "GET ") ||
			strings.Contains(line, "POST ") ||
			strings.Contains(line, "PUT ") ||
			strings.Contains(line, "DELETE ") ||
			strings.Contains(line, "PATCH ") ||
			strings.Contains(line, "HEAD ") ||
			strings.Contains(line, "OPTIONS "))
}

func rawWebLogEntry(sourceID string, source webLogSourceCandidate, line string) models.WebLogEntry {
	return models.WebLogEntry{
		SourceID:    sourceID,
		Method:      "RAW",
		URI:         line,
		ServerType:  source.ServerType,
		SiteName:    source.SiteName,
		ProcessName: source.ProcessName,
		ProcessPID:  source.ProcessPID,
		Raw:         line,
	}
}

func parseJSONAccessLine(sourceID string, source webLogSourceCandidate, line string) (models.WebLogEntry, bool) {
	var payload map[string]any
	if err := json.Unmarshal([]byte(line), &payload); err != nil {
		return models.WebLogEntry{}, false
	}

	status, ok := jsonNumberToInt(payload["status"])
	if !ok {
		status, ok = jsonNumberToInt(payload["status_code"])
		if !ok {
			return models.WebLogEntry{}, false
		}
	}
	bytesSent, _ := jsonNumberToInt64(firstValue(payload, "body_bytes_sent", "bytes_sent", "response_size"))

	return models.WebLogEntry{
		SourceID:    sourceID,
		Timestamp:   stringValue(firstValue(payload, "time", "timestamp", "@timestamp")),
		ClientIP:    stringValue(firstValue(payload, "remote_addr", "client_ip", "c_ip")),
		Method:      stringValue(firstValue(payload, "method", "request_method")),
		URI:         stringValue(firstValue(payload, "request_uri", "uri", "url")),
		Status:      status,
		BytesSent:   bytesSent,
		UserAgent:   stringValue(firstValue(payload, "http_user_agent", "user_agent")),
		Referer:     stringValue(firstValue(payload, "http_referer", "referer")),
		ServerType:  source.ServerType,
		SiteName:    source.SiteName,
		ProcessName: source.ProcessName,
		ProcessPID:  source.ProcessPID,
	}, true
}

func firstValue(payload map[string]any, keys ...string) any {
	for _, key := range keys {
		if value, ok := payload[key]; ok {
			return value
		}
	}
	return nil
}

func jsonNumberToInt(value any) (int, bool) {
	switch v := value.(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	case string:
		parsed, err := strconv.Atoi(v)
		return parsed, err == nil
	default:
		return 0, false
	}
}

func jsonNumberToInt64(value any) (int64, bool) {
	switch v := value.(type) {
	case float64:
		return int64(v), true
	case int64:
		return v, true
	case int:
		return int64(v), true
	case string:
		parsed, err := strconv.ParseInt(v, 10, 64)
		return parsed, err == nil
	default:
		return 0, false
	}
}

func stringValue(value any) string {
	switch v := value.(type) {
	case string:
		return normalizeDash(v)
	case nil:
		return ""
	default:
		return normalizeDash(fmt.Sprint(v))
	}
}

func defaultString(value string, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func normalizeDash(value string) string {
	if value == "-" {
		return ""
	}
	return value
}
