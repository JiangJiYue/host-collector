//go:build windows

package collector

import (
	"context"
	"strings"
	"time"

	"github.com/StackExchange/wmi"
)

type windowsSessionAccountProvider struct{}

type win32LogonSession struct {
	LogonID   string
	LogonType uint32
	StartTime string
}

type win32LoggedOnUser struct {
	Antecedent string
	Dependent  string
}

func (p windowsSessionAccountProvider) collect(ctx context.Context) ([]accountSourceRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var sessions []win32LogonSession
	if err := wmi.Query(
		"SELECT LogonId, LogonType, StartTime FROM Win32_LogonSession WHERE LogonType = 2 OR LogonType = 10",
		&sessions,
	); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	sessionByID := make(map[string]win32LogonSession, len(sessions))
	for _, session := range sessions {
		sessionID := normalizeLogonID(session.LogonID)
		if sessionID == "" {
			continue
		}
		sessionByID[sessionID] = session
	}
	if len(sessionByID) == 0 {
		return []accountSourceRecord{}, nil
	}

	var bindings []win32LoggedOnUser
	if err := wmi.Query("SELECT Antecedent, Dependent FROM Win32_LoggedOnUser", &bindings); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	recordsByUser := map[string]accountSourceRecord{}
	for _, binding := range bindings {
		username := parseLoggedOnUsername(binding.Antecedent)
		if username == "" {
			continue
		}
		logonID := parseDependentLogonID(binding.Dependent)
		session, ok := sessionByID[logonID]
		if !ok {
			continue
		}
		startTime := parseWMIDateTime(session.StartTime)
		if startTime == nil {
			continue
		}

		key := normalizeUsername(username)
		existing, exists := recordsByUser[key]
		if !exists || shouldPreferSessionTime(startTime, existing.LastLogon) {
			rec := accountSourceRecord{
				Username:  username,
				Source:    accountSourceSession,
				LastLogon: startTime,
			}
			recordsByUser[key] = rec
		}
	}

	records := make([]accountSourceRecord, 0, len(recordsByUser))
	for _, rec := range recordsByUser {
		records = append(records, rec)
	}
	return records, nil
}

func normalizeLogonID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return strings.TrimLeft(value, "0")
}

func parseLoggedOnUsername(antecedent string) string {
	name := extractQuotedWMIValue(antecedent, "Name")
	if name == "" {
		return ""
	}
	return strings.TrimSpace(name)
}

func parseDependentLogonID(dependent string) string {
	return normalizeLogonID(extractQuotedWMIValue(dependent, "LogonId"))
}

func extractQuotedWMIValue(input, key string) string {
	pattern := key + "=\""
	start := strings.Index(input, pattern)
	if start < 0 {
		return ""
	}
	start += len(pattern)
	end := strings.Index(input[start:], "\"")
	if end < 0 {
		return ""
	}
	return input[start : start+end]
}

func parseWMIDateTime(value string) *string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) < 22 {
		return nil
	}
	base, err := time.Parse("20060102150405.000000", value[:21])
	if err != nil {
		return nil
	}
	sign := value[21]
	offsetMinutesRaw := strings.TrimSpace(value[22:])
	if sign != '+' && sign != '-' {
		return nil
	}
	offsetMinutes, err := time.ParseDuration(offsetMinutesRaw + "m")
	if err != nil {
		return nil
	}
	offsetSeconds := int(offsetMinutes / time.Second)
	if sign == '-' {
		offsetSeconds = -offsetSeconds
	}
	location := time.FixedZone("WMI", offsetSeconds)
	parsed := time.Date(base.Year(), base.Month(), base.Day(), base.Hour(), base.Minute(), base.Second(), 0, location)
	formatted := parsed.Format(time.RFC3339)
	return &formatted
}

func shouldPreferSessionTime(candidate *string, current *string) bool {
	if candidate == nil {
		return false
	}
	if current == nil || strings.TrimSpace(*current) == "" {
		return true
	}
	currentTime, currentErr := time.Parse(time.RFC3339, strings.TrimSpace(*current))
	candidateTime, candidateErr := time.Parse(time.RFC3339, strings.TrimSpace(*candidate))
	if currentErr != nil || candidateErr != nil {
		return false
	}
	return candidateTime.After(currentTime)
}
