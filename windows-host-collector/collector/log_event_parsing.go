package collector

import (
	"encoding/xml"
	"fmt"
	"sort"
	"strings"
	"time"
	"windows-host-collector/models"
)

type eventXML struct {
	XMLName xml.Name `xml:"Event"`
	System  struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID struct {
			Value int `xml:",chardata"`
		} `xml:"EventID"`
		Level struct {
			Value int `xml:",chardata"`
		} `xml:"Level"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Computer string `xml:"Computer"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

func parseEventXML(xmlStr string, logType string, index int) *models.WindowsLogItem {
	if xmlStr == "" {
		return nil
	}
	var event eventXML
	if err := xml.Unmarshal([]byte(xmlStr), &event); err != nil {
		return nil
	}

	ts := event.System.TimeCreated.SystemTime
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		ts = t.Format(time.RFC3339)
	}

	summary := extractSummary(&event, event.System.EventID.Value)
	processName := extractProcessName(&event)
	logonType := extractLogonType(&event, logType, event.System.EventID.Value)
	hostApp := extractHostApplication(&event, logType)
	eventData := extractEventData(&event)
	normalizedFields := normalizeEventFields(&event, logType, eventData)
	keywords := extractEventKeywords(event.System.EventID.Value, eventData, normalizedFields)

	return &models.WindowsLogItem{
		ID:               fmt.Sprintf("log-%s-%d-%d", logType, event.System.EventID.Value, index),
		LogType:          logType,
		Level:            convertLogLevel(event.System.Level.Value),
		EventID:          event.System.EventID.Value,
		Summary:          truncateString(summary, 500),
		Timestamp:        ts,
		DetailsXml:       xmlStr,
		ProcessName:      processName,
		LogonType:        logonType,
		HostApplication:  hostApp,
		EventData:        eventData,
		NormalizedFields: normalizedFields,
		Keywords:         keywords,
	}
}

func normalizeLogType(channel string) string {
	lower := strings.ToLower(channel)
	switch {
	case strings.Contains(lower, "security"):
		return "security"
	case strings.Contains(lower, "system"):
		return "system"
	case strings.Contains(lower, "application"):
		return "application"
	case strings.Contains(lower, "powershell"):
		return "powershell"
	default:
		return "other"
	}
}

func extractSummary(event *eventXML, eventID int) string {
	var parts []string
	for _, d := range event.EventData.Data {
		if d.Value != "" {
			parts = append(parts, d.Name+"="+d.Value)
		}
	}
	if len(parts) > 0 {
		return fmt.Sprintf("Event %d: %s", eventID, strings.Join(parts, "; "))
	}
	return fmt.Sprintf("Event %d", eventID)
}

func extractProcessName(event *eventXML) *string {
	for _, d := range event.EventData.Data {
		name := strings.ToLower(d.Name)
		if (name == "newprocessname" || name == "processname" || name == "image") && d.Value != "" {
			return &d.Value
		}
	}
	return nil
}

func extractLogonType(event *eventXML, logType string, eventID int) *int {
	if logType != "security" {
		return nil
	}
	if eventID != 4624 && eventID != 4625 && eventID != 4634 {
		return nil
	}
	for _, d := range event.EventData.Data {
		if strings.ToLower(d.Name) == "logontype" && d.Value != "" {
			var lt int
			fmt.Sscanf(d.Value, "%d", &lt)
			if lt > 0 {
				return &lt
			}
		}
	}
	return nil
}

func extractHostApplication(event *eventXML, logType string) *string {
	if logType != "powershell" {
		return nil
	}
	for _, d := range event.EventData.Data {
		name := strings.ToLower(d.Name)
		if (name == "hostapplication" || name == "commandline") && d.Value != "" {
			return &d.Value
		}
	}
	return nil
}

func extractEventData(event *eventXML) map[string]string {
	fields := make(map[string]string)
	for _, d := range event.EventData.Data {
		if d.Name == "" || d.Value == "" {
			continue
		}
		fields[d.Name] = d.Value
	}
	if len(fields) == 0 {
		return nil
	}
	return fields
}

func normalizeEventFields(event *eventXML, logType string, eventData map[string]string) map[string]string {
	if len(eventData) == 0 {
		return nil
	}

	fields := make(map[string]string)
	for key, value := range eventData {
		assignNormalizedField(fields, key, value)
	}

	if logType == "security" {
		fields["eventCategory"] = "security"
	}
	applySecurityEventAliases(fields, event.System.EventID.Value, eventData)
	if len(fields) == 0 {
		return nil
	}
	return fields
}

func assignNormalizedField(fields map[string]string, rawKey string, value string) {
	if value == "" || value == "-" {
		return
	}
	switch strings.ToLower(rawKey) {
	case "subjectusersid":
		setIfEmpty(fields, "actorSecurityId", value)
		setIfEmpty(fields, "securityId", value)
	case "subjectusername":
		setIfEmpty(fields, "actorAccountName", value)
	case "subjectdomainname":
		setIfEmpty(fields, "actorAccountDomain", value)
	case "targetusersid":
		setIfEmpty(fields, "targetSecurityId", value)
		setIfEmpty(fields, "securityId", value)
	case "targetsid":
		setIfEmpty(fields, "targetSecurityId", value)
	case "targetusername":
		setIfEmpty(fields, "targetAccountName", value)
		setIfEmpty(fields, "accountName", value)
	case "targetdomainname":
		setIfEmpty(fields, "targetAccountDomain", value)
		setIfEmpty(fields, "accountDomain", value)
	case "failurereason":
		fields["failureReason"] = value
	case "status":
		fields["status"] = value
	case "substatus":
		fields["subStatus"] = value
	case "processname":
		fields["processName"] = value
	case "newprocessname":
		fields["newProcessName"] = value
		setIfEmpty(fields, "processName", value)
	case "parentprocessname":
		fields["parentProcessName"] = value
	case "processcommandline":
		fields["commandLine"] = value
	case "commandline":
		setIfEmpty(fields, "commandLine", value)
		setIfEmpty(fields, "hostApplication", value)
	case "hostapplication":
		setIfEmpty(fields, "hostApplication", value)
	case "ipaddress":
		fields["ipAddress"] = value
	case "ipport":
		fields["ipPort"] = value
	case "workstationname":
		fields["workstationName"] = value
	case "logontype":
		fields["logonType"] = value
	case "tokenelevationtype":
		fields["tokenElevationType"] = value
	case "mandatorylabel":
		fields["mandatoryLabel"] = value
	case "newprocessid":
		fields["newProcessId"] = value
	case "samaccountname":
		fields["samAccountName"] = value
	case "displayname":
		fields["displayName"] = value
	case "userprincipalname":
		fields["userPrincipalName"] = value
	case "homedirectory":
		fields["homeDirectory"] = value
	case "servicename":
		fields["serviceName"] = value
	case "ticketoptions":
		fields["ticketOptions"] = value
	case "preauthtype":
		fields["preAuthType"] = value
	}
}

func applySecurityEventAliases(fields map[string]string, eventID int, eventData map[string]string) {
	switch eventID {
	case 4624, 4625, 4634, 4648, 4672, 4776:
		promoteIfPresent(fields, "actorAccountName", "accountName")
		promoteIfPresent(fields, "actorAccountDomain", "accountDomain")
	case 4688:
		promote(fields, "actorAccountName", eventData["SubjectUserName"])
		promote(fields, "actorAccountDomain", eventData["SubjectDomainName"])
		promote(fields, "actorSecurityId", eventData["SubjectUserSid"])
	case 4720, 4726, 4728, 4732, 4740, 4768, 4769, 4771:
		promote(fields, "actorAccountName", eventData["SubjectUserName"])
		promote(fields, "actorAccountDomain", eventData["SubjectDomainName"])
		promote(fields, "actorSecurityId", eventData["SubjectUserSid"])
		promote(fields, "targetAccountName", firstNonEmpty(eventData["TargetUserName"], eventData["MemberName"]))
		promote(fields, "targetAccountDomain", eventData["TargetDomainName"])
		promote(fields, "targetSecurityId", firstNonEmpty(eventData["TargetUserSid"], eventData["TargetSid"], eventData["MemberSid"]))
	}
}

func setIfEmpty(fields map[string]string, key string, value string) {
	if value == "" || value == "-" {
		return
	}
	if fields[key] == "" {
		fields[key] = value
	}
}

func promote(fields map[string]string, key string, value string) {
	if value == "" || value == "-" {
		return
	}
	fields[key] = value
}

func promoteIfPresent(fields map[string]string, target string, source string) {
	if value := fields[source]; value != "" && value != "-" {
		fields[target] = value
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" && value != "-" {
			return value
		}
	}
	return ""
}

func extractEventKeywords(eventID int, eventData map[string]string, normalizedFields map[string]string) []string {
	seen := make(map[string]struct{})
	var keywords []string
	add := func(value string) {
		token := strings.TrimSpace(strings.ToLower(value))
		if token == "" || token == "-" {
			return
		}
		if _, exists := seen[token]; exists {
			return
		}
		seen[token] = struct{}{}
		keywords = append(keywords, token)
	}

	add(fmt.Sprintf("%d", eventID))
	for _, value := range eventData {
		add(value)
	}
	for _, value := range normalizedFields {
		add(value)
	}
	sort.Strings(keywords)
	return keywords
}
