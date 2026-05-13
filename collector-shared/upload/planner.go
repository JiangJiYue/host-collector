package upload

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

var legacyPackageFields = []string{
	"packageSha256",
	"package_sha256",
	"rawPackage",
	"raw_package",
}

func LinuxPlans() []Plan {
	return []Plan{
		{
			ItemID:   "host",
			ItemKind: "sectionGroup",
			Sections: []string{
				"system",
				"resources",
				"hardware",
				"platformFacts",
			},
		},
		{
			ItemID:   "process",
			ItemKind: "sectionGroup",
			Sections: []string{
				"processes",
				"processDetails",
				"processTree",
			},
		},
		{
			ItemID:   "file_identity",
			ItemKind: "section",
			Sections: []string{
				"fileIdentities",
			},
		},
		{
			ItemID:   "network",
			ItemKind: "section",
			Sections: []string{
				"network",
			},
		},
		{
			ItemID:   "startup",
			ItemKind: "sectionGroup",
			Sections: []string{
				"services",
				"timers",
				"cronJobs",
				"persistenceItems",
			},
		},
		{
			ItemID:   "users",
			ItemKind: "sectionGroup",
			Sections: []string{
				"users",
				"groups",
				"privilegeEvidence",
			},
		},
		{
			ItemID:   "env_vars",
			ItemKind: "section",
			Sections: []string{
				"envVars",
			},
		},
		{
			ItemID:   "software",
			ItemKind: "section",
			Sections: []string{
				"software",
			},
		},
		{
			ItemID:   "operation_records",
			ItemKind: "section",
			Sections: []string{
				"operationRecords",
			},
		},
		{
			ItemID:   "logs",
			ItemKind: "sectionGroup",
			Sections: []string{
				"linuxLogSources",
				"linuxLogEvents",
			},
		},
		{
			ItemID:   "web_logs",
			ItemKind: "sectionGroup",
			Sections: []string{
				"webLogSources",
				"webLogEntries",
			},
		},
		{
			ItemID:   "file_system",
			ItemKind: "sectionGroup",
			Sections: []string{
				"forensicVolumes",
				"forensicDirectoryNodes",
				"forensicFileEntries",
				"forensicTimelineEvents",
			},
		},
		{
			ItemID:   "timeline",
			ItemKind: "section",
			Sections: []string{
				"timelineEvents",
			},
		},
		{
			ItemID:   "diagnostics",
			ItemKind: "sectionGroup",
			Sections: []string{
				"platformProfile",
				"stageDiagnostics",
			},
		},
	}
}

func PlanLinuxItems(payload map[string]any, metadata Metadata) ([]Item, error) {
	return PlanItems(payload, metadata, LinuxPlans())
}

func WindowsCompatiblePlans() []Plan {
	return []Plan{
		{
			ItemID:   "host",
			ItemKind: "sectionGroup",
			Sections: []string{
				"system",
				"resources",
				"hardware",
			},
		},
		{
			ItemID:   "process",
			ItemKind: "sectionGroup",
			Sections: []string{
				"processes",
				"processDetails",
			},
		},
		{
			ItemID:   "file_identity",
			ItemKind: "section",
			Sections: []string{
				"fileIdentities",
			},
		},
		{
			ItemID:   "network",
			ItemKind: "section",
			Sections: []string{
				"network",
			},
		},
		{
			ItemID:   "startup",
			ItemKind: "sectionGroup",
			Sections: []string{
				"services",
			},
		},
		{
			ItemID:   "users",
			ItemKind: "sectionGroup",
			Sections: []string{
				"users",
			},
		},
		{
			ItemID:   "env_vars",
			ItemKind: "section",
			Sections: []string{
				"envVars",
			},
		},
		{
			ItemID:   "software",
			ItemKind: "section",
			Sections: []string{
				"software",
			},
		},
		{
			ItemID:   "prefetch",
			ItemKind: "section",
			Sections: []string{
				"prefetch",
			},
		},
		{
			ItemID:   "browser_history",
			ItemKind: "section",
			Sections: []string{
				"browserHistory",
			},
		},
		{
			ItemID:   "web_logs",
			ItemKind: "sectionGroup",
			Sections: []string{
				"webLogSources",
				"webLogEntries",
			},
		},
		{
			ItemID:   "usb_records",
			ItemKind: "section",
			Sections: []string{
				"usbRecords",
			},
		},
		{
			ItemID:   "operation_records",
			ItemKind: "section",
			Sections: []string{
				"operationRecords",
			},
		},
		{
			ItemID:   "registry",
			ItemKind: "section",
			Sections: []string{
				"registries",
			},
		},
		{
			ItemID:   "windows_event_logs",
			ItemKind: "section",
			Sections: []string{
				"windowsEventLogs",
			},
		},
		{
			ItemID:   "file_system",
			ItemKind: "sectionGroup",
			Sections: []string{
				"forensicVolumes",
				"forensicDirectoryNodes",
				"forensicFileEntries",
				"forensicTimelineEvents",
				"forensicDiagnostics",
			},
		},
		{
			ItemID:   "diagnostics",
			ItemKind: "sectionGroup",
			Sections: []string{
				"platformProfile",
				"stageDiagnostics",
			},
		},
	}
}

func PlanWindowsItems(payload map[string]any, metadata Metadata) ([]Item, error) {
	if _, legacy := payload["logs"]; legacy {
		return nil, fmt.Errorf("legacy payload key %q is not supported; use %q", "logs", "windowsEventLogs")
	}

	platformContext := windowsPlatformContextFromProfile(payload["platformProfile"])
	planningPayload := payload
	if len(platformContext) > 0 {
		planningPayload = make(map[string]any, len(payload)+len(platformContext))
		for key, value := range payload {
			planningPayload[key] = value
		}
		for key, value := range platformContext {
			planningPayload[key] = value
		}
	}

	return PlanItems(planningPayload, metadata, WindowsCompatiblePlans())
}

func PlanItems(payload map[string]any, metadata Metadata, plans []Plan) ([]Item, error) {
	for _, field := range legacyPackageFields {
		if _, exists := payload[field]; exists {
			return nil, fmt.Errorf("legacy package field %q is not supported", field)
		}
	}

	items := make([]Item, 0, len(plans))
	for _, plan := range plans {
		sections := collectSections(payload, plan.Sections)
		if len(sections) == 0 {
			continue
		}

		body := map[string]any{
			"protocolVersion": ProtocolVersionUploadItemsV1,
			"agentId":         metadata.AgentID,
			"scanId":          metadata.ScanID,
			"scanType":        metadata.ScanType,
			"itemId":          plan.ItemID,
			"itemKind":        plan.ItemKind,
			"itemName":        plan.ItemID,
			"sections":        sections,
		}
		copyPlatformContext(payload, body)
		if collectedAt := strings.TrimSpace(metadata.CollectedAt); collectedAt != "" {
			body["collectedAt"] = collectedAt
		}

		payloadJSON, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal upload item %q: %w", plan.ItemID, err)
		}

		items = append(items, Item{
			ItemID:          plan.ItemID,
			ItemKind:        plan.ItemKind,
			ItemName:        plan.ItemID,
			AgentID:         metadata.AgentID,
			ScanID:          metadata.ScanID,
			ScanType:        metadata.ScanType,
			CollectedAt:     metadata.CollectedAt,
			ContentType:     "application/json",
			ContentEncoding: "gzip",
			PayloadJSON:     payloadJSON,
		})
	}

	for index := range items {
		items[index].ItemIndex = index + 1
		items[index].ItemCount = len(items)
	}

	return items, nil
}

func windowsPlatformContextFromProfile(value any) map[string]any {
	profile, ok := value.(map[string]any)
	if !ok {
		return nil
	}

	context := map[string]any{}
	for _, key := range []string{"platform", "supportLevel", "capabilitiesVersion"} {
		if text, ok := profile[key].(string); ok && text != "" {
			context[key] = text
		}
	}

	capabilitiesMap, ok := profile["capabilities"].(map[string]any)
	if !ok {
		return context
	}
	capabilities := make([]string, 0, len(capabilitiesMap))
	for name, supported := range capabilitiesMap {
		if value, ok := supported.(bool); ok && value {
			capabilities = append(capabilities, name)
		}
	}
	sort.Strings(capabilities)
	if len(capabilities) > 0 {
		context["capabilities"] = capabilities
	}
	return context
}

func collectSections(payload map[string]any, sectionNames []string) map[string]any {
	sections := make(map[string]any, len(sectionNames))
	for _, name := range sectionNames {
		if value, exists := payload[name]; exists {
			sections[name] = value
		}
	}
	return sections
}

func copyPlatformContext(source map[string]any, target map[string]any) {
	for _, key := range []string{
		"platform",
		"platformExtensions",
		"supportLevel",
		"capabilitiesVersion",
		"capabilities",
		"capabilityStatuses",
	} {
		if value, exists := source[key]; exists {
			target[key] = value
		}
	}
}
