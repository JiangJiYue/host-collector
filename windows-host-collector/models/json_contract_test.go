package models

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"

	"windows-host-collector/forensics/filesystem"
)

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func TestProcessThreadUsesThreadIDJsonField(t *testing.T) {
	body, err := json.Marshal(ProcessThread{
		ThreadID: 452,
		State:    "Running",
	})
	if err != nil {
		t.Fatalf("marshal process thread: %v", err)
	}

	got := string(body)
	if !strings.Contains(got, `"threadId":452`) {
		t.Fatalf("expected threadId in json, got %s", got)
	}
	if strings.Contains(got, `"id":452`) {
		t.Fatalf("expected semantic thread identifier to stop using id, got %s", got)
	}
}

func TestSystemProcessMasqueradeModelsUseCamelCaseContractFields(t *testing.T) {
	fileIdentityID := "file-identity-1"
	sha256 := "0123456789abcdef"
	hashState := "computed"
	signatureState := "trusted"
	signerSubject := "CN=Microsoft Windows"
	originalFilename := "svchost.exe"
	referencedPath := `C:\Windows\System32\svchost.exe`

	cases := []struct {
		name string
		body []byte
		want []string
	}{
		{
			name: "file identity",
			body: mustMarshalContract(t, FileIdentity{
				ID:             fileIdentityID,
				Path:           referencedPath,
				SHA256:         sha256,
				HashState:      hashState,
				SignatureState: signatureState,
			}),
			want: []string{"sha256", "hashState", "signatureState"},
		},
		{
			name: "process basic info",
			body: mustMarshalContract(t, ProcessBasicInfo{
				ProcessName:         "svchost.exe",
				PID:                 948,
				FileIdentityID:      &fileIdentityID,
				SHA256:              &sha256,
				HashState:           &hashState,
				SignatureState:      &signatureState,
				SignerSubject:       &signerSubject,
				PEOriginalFilename:  &originalFilename,
				MasqueradeRiskLevel: ptrString("medium"),
				MasqueradeSignals:   []MasqueradeSignal{{Code: "path_mismatch", Severity: "medium", Message: "System process outside expected path"}},
			}),
			want: []string{"fileIdentityId", "sha256", "hashState", "signatureState", "masqueradeSignals"},
		},
		{
			name: "registry value",
			body: mustMarshalContract(t, RegistryValue{
				ID:                       "reg-1",
				Name:                     "ServiceDll",
				Type:                     "REG_EXPAND_SZ",
				Data:                     referencedPath,
				Path:                     `HKLM\SYSTEM\CurrentControlSet\Services\Example`,
				CollectionCategory:       "persistence",
				RiskPurpose:              "autoload",
				ReferencedPath:           &referencedPath,
				ReferencedFileIdentityID: &fileIdentityID,
			}),
			want: []string{"collectionCategory", "riskPurpose", "referencedFileIdentityId"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var decoded map[string]any
			if err := json.Unmarshal(tc.body, &decoded); err != nil {
				t.Fatalf("decode %s: %v", tc.name, err)
			}
			for _, want := range tc.want {
				if _, exists := decoded[want]; !exists {
					t.Fatalf("expected %s field in %s, got keys=%v json=%s", want, tc.name, sortedKeys(decoded), string(tc.body))
				}
			}
		})
	}
}

func mustMarshalContract(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal contract value: %v", err)
	}
	return body
}

func ptrString(value string) *string {
	return &value
}

func TestQuickScanDataUsesCamelCaseContractFields(t *testing.T) {
	// The fixture represents the target client contract shape we will enforce at service boundaries.
	body, err := os.ReadFile("testdata/client_contract_minified.json")
	if err != nil {
		t.Fatal(err)
	}

	var fixture map[string]any
	if err := json.Unmarshal(body, &fixture); err != nil {
		t.Fatal(err)
	}

	if _, ok := fixture["windowsEventLogs"]; !ok {
		t.Fatalf("fixture must include windowsEventLogs top-level field, got keys=%v", sortedKeys(fixture))
	}
	if _, legacy := fixture["logs"]; legacy {
		t.Fatalf("fixture must not include legacy logs field")
	}

	// Enforce the client contract: QuickScanData must emit `windowsEventLogs` and must not emit legacy `logs`.
	encoded, err := json.Marshal(
		QuickScanData{
			Version:   "v1",
			Timestamp: "2026-04-18T15:30:09+08:00",
			System: &HostIdentityInfo{
				Hostname:  "DESKTOP-NJIVMOJ",
				OSVersion: "Windows 11",
				Username:  "Administrator",
			},
			Registries: []RegistryValue{
				{
					ID:   "reg-1",
					Path: `HKLM\\Software\\Microsoft`,
					Name: "Run",
					Type: "REG_SZ",
					Data: "cmd.exe",
				},
			},
			WindowsEventLogs: []WindowsLogItem{
				{
					ID:         "log-1",
					LogType:    "security",
					Level:      "info",
					EventID:    4624,
					Summary:    "Login success",
					Timestamp:  "2026-04-18T15:30:09+08:00",
					DetailsXml: "<EventData />",
					EventData: map[string]string{
						"TargetUserName":   "alice",
						"TargetDomainName": "CONTOSO",
					},
					NormalizedFields: map[string]string{
						"accountName":   "alice",
						"accountDomain": "CONTOSO",
					},
					Keywords: []string{"4624", "alice", "contoso"},
				},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}

	if _, ok := decoded["windowsEventLogs"]; !ok {
		t.Fatalf("expected windowsEventLogs top-level field, got keys=%v", sortedKeys(decoded))
	}
	if _, legacy := decoded["logs"]; legacy {
		t.Fatalf("legacy logs field must not exist")
	}

	rows, ok := decoded["windowsEventLogs"].([]any)
	if !ok || len(rows) != 1 {
		t.Fatalf("expected one windowsEventLogs row, got %#v", decoded["windowsEventLogs"])
	}
	row, ok := rows[0].(map[string]any)
	if !ok {
		t.Fatalf("expected windowsEventLogs row object, got %#v", rows[0])
	}
	for _, want := range []string{"id", "logType", "level", "eventId", "summary", "timestamp", "detailsXml"} {
		if _, exists := row[want]; !exists {
			t.Fatalf("expected %s field in windowsEventLogs row, got keys=%v", want, sortedKeys(row))
		}
	}
	for _, optional := range []string{"eventData", "normalizedFields", "keywords"} {
		if _, exists := row[optional]; exists {
			continue
		}
	}
	for _, forbidden := range []string{"channel", "provider", "message", "eventTimestamp", "event_timestamp", "details_xml"} {
		if _, exists := row[forbidden]; exists {
			t.Fatalf("did not expect legacy %s field in windowsEventLogs row, got %#v", forbidden, row)
		}
	}
}

func TestQuickScanDataIncludesPlatformCapabilitiesAndStageDiagnostics(t *testing.T) {
	body, err := json.Marshal(QuickScanData{
		Version:   "v1",
		Timestamp: "2026-05-02T00:00:00Z",
		PlatformProfile: &PlatformProfile{
			Platform:            "windows",
			SupportLevel:        "legacy",
			BuildFamily:         "windows_7_or_server_2008_r2",
			Architecture:        "amd64",
			CapabilitiesVersion: "windows-capabilities-v1",
			Capabilities:        []string{"wmi", "registry", "event_log_api"},
			CapabilityStatuses: map[string]any{
				"prefetch_win10_layout": map[string]any{
					"supported": false,
					"reason":    "legacy_prefetch_layout",
					"evidence":  "windows_7_or_server_2008_r2",
				},
			},
			Facts: map[string]any{
				"osFamily":         "workstation",
				"productName":      "Windows 7 Professional",
				"editionId":        "Professional",
				"installationType": "Client",
				"buildNumber":      7601,
				"ubr":              123,
			},
		},
		StageDiagnostics: []StageDiagnostic{
			{
				Stage:      "prefetch",
				State:      string(StageSkipped),
				ReasonCode: "missing_capability",
				Capability: "prefetch_win10_layout",
				Evidence:   "windows_7_or_server_2008_r2",
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal quick scan data: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decode quick scan data: %v", err)
	}

	profile, ok := decoded["platformProfile"].(map[string]any)
	if !ok {
		t.Fatalf("expected platformProfile object, got keys=%v", sortedKeys(decoded))
	}
	if profile["supportLevel"] != "legacy" || profile["buildFamily"] != "windows_7_or_server_2008_r2" {
		t.Fatalf("unexpected platform profile: %#v", profile)
	}
	facts, ok := profile["facts"].(map[string]any)
	if !ok || facts["osFamily"] != "workstation" || facts["editionId"] != "Professional" {
		t.Fatalf("expected detailed platform facts, got %#v", profile["facts"])
	}
	capabilities, ok := profile["capabilities"].([]any)
	if !ok || len(capabilities) != 3 {
		t.Fatalf("expected capabilities array, got %#v", profile["capabilities"])
	}
	statuses, ok := profile["capabilityStatuses"].(map[string]any)
	if !ok {
		t.Fatalf("expected capabilityStatuses object, got %#v", profile["capabilityStatuses"])
	}
	prefetchStatus, ok := statuses["prefetch_win10_layout"].(map[string]any)
	if !ok || prefetchStatus["supported"] != false || prefetchStatus["reason"] != "legacy_prefetch_layout" {
		t.Fatalf("expected structured prefetch capability status, got %#v", statuses)
	}

	diagnostics, ok := decoded["stageDiagnostics"].([]any)
	if !ok || len(diagnostics) != 1 {
		t.Fatalf("expected one stage diagnostic, got %#v", decoded["stageDiagnostics"])
	}
	diagnostic, ok := diagnostics[0].(map[string]any)
	if !ok {
		t.Fatalf("expected stage diagnostic object, got %#v", diagnostics[0])
	}
	for _, want := range []string{"stage", "state", "reasonCode", "capability", "evidence"} {
		if _, exists := diagnostic[want]; !exists {
			t.Fatalf("expected %s in stage diagnostic, got keys=%v", want, sortedKeys(diagnostic))
		}
	}
}

func TestQuickScanDataUsesWebLogContractFields(t *testing.T) {
	body, err := json.Marshal(QuickScanData{
		Version:   "v1",
		Timestamp: "2026-04-21T12:00:00Z",
		WebLogSources: []WebLogSource{
			{
				ID:               "sha256:source",
				Path:             `C:\inetpub\logs\LogFiles\W3SVC1\u_ex260421.log`,
				ServerType:       "iis",
				Format:           "iisW3C",
				SiteName:         "Default Web Site",
				Port:             80,
				Protocol:         "HTTP",
				SourceMethod:     "iisConfig",
				Confidence:       "high",
				Evidence:         []string{"IIS_CONFIG_LOG_DIRECTORY", "IIS_FIELDS_HEADER"},
				Size:             1234567,
				ModifiedAt:       "2026-04-21T12:00:00Z",
				Truncated:        true,
				TruncationReason: "file_tail_limit",
			},
		},
		WebLogEntries: []WebLogEntry{
			{
				SourceID:    "sha256:source",
				Timestamp:   "2026-04-21T12:01:02Z",
				ClientIP:    "1.2.3.4",
				Method:      "POST",
				URI:         "/upload/index.php",
				Status:      200,
				BytesSent:   1234,
				UserAgent:   "curl/8.0",
				Referer:     "-",
				Protocol:    "HTTP",
				Host:        "example.com",
				ServerType:  "iis",
				SiteName:    "Default Web Site",
				ProcessName: "w3wp.exe",
				ProcessPID:  1234,
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal quick scan data: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("unmarshal quick scan data: %v", err)
	}

	sources, ok := decoded["webLogSources"].([]any)
	if !ok || len(sources) != 1 {
		t.Fatalf("expected one webLogSources row, got %#v", decoded["webLogSources"])
	}
	source, ok := sources[0].(map[string]any)
	if !ok {
		t.Fatalf("expected webLogSources row object, got %#v", sources[0])
	}
	for _, want := range []string{"id", "path", "serverType", "format", "siteName", "port", "protocol", "sourceMethod", "confidence", "evidence", "size", "modifiedAt", "truncated", "truncationReason"} {
		if _, exists := source[want]; !exists {
			t.Fatalf("expected %s field in webLogSources row, got keys=%v", want, sortedKeys(source))
		}
	}

	entries, ok := decoded["webLogEntries"].([]any)
	if !ok || len(entries) != 1 {
		t.Fatalf("expected one webLogEntries row, got %#v", decoded["webLogEntries"])
	}
	entry, ok := entries[0].(map[string]any)
	if !ok {
		t.Fatalf("expected webLogEntries row object, got %#v", entries[0])
	}
	for _, want := range []string{"sourceId", "timestamp", "clientIp", "method", "uri", "status", "bytesSent", "userAgent", "referer", "protocol", "host", "serverType", "siteName", "processName", "processPid"} {
		if _, exists := entry[want]; !exists {
			t.Fatalf("expected %s field in webLogEntries row, got keys=%v", want, sortedKeys(entry))
		}
	}
	for _, forbidden := range []string{"riskLabels", "riskReason", "client_ip", "bytes_sent", "process_pid"} {
		if _, exists := entry[forbidden]; exists {
			t.Fatalf("did not expect %s in webLogEntries row, got %#v", forbidden, entry)
		}
	}
}

func TestQuickScanDataKeepsCanonicalLogAndProcessDetailJsonFields(t *testing.T) {
	body, err := json.Marshal(QuickScanData{
		Version: "v1",
		WindowsEventLogs: []WindowsLogItem{
			{
				ID:         "log-1",
				LogType:    "powershell",
				EventID:    403,
				Timestamp:  "2026-04-16T03:02:35Z",
				DetailsXml: "<Event />",
				EventData: map[string]string{
					"HostApplication": "powershell.exe -NoProfile",
				},
				NormalizedFields: map[string]string{
					"hostApplication": "powershell.exe -NoProfile",
				},
				Keywords: []string{"403", "powershell.exe -noprofile"},
			},
		},
		ProcessDetails: map[int]*ProcessDetail{
			400: {
				Threads: []ProcessThread{
					{
						ThreadID: 452,
						State:    "Running",
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal quick scan data: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("unmarshal quick scan data: %v", err)
	}

	processDetails, ok := decoded["processDetails"].(map[string]any)
	if !ok {
		t.Fatalf("expected processDetails object, got %#v", decoded["processDetails"])
	}
	p400, ok := processDetails["400"].(map[string]any)
	if !ok {
		t.Fatalf("expected process detail for pid 400, got %#v", processDetails["400"])
	}
	threads, ok := p400["threads"].([]any)
	if !ok || len(threads) != 1 {
		t.Fatalf("expected one thread row, got %#v", p400["threads"])
	}
	thread, ok := threads[0].(map[string]any)
	if !ok {
		t.Fatalf("expected thread row object, got %#v", threads[0])
	}
	if thread["threadId"] != float64(452) {
		t.Fatalf("expected threadId 452, got %#v", thread["threadId"])
	}
	if _, exists := thread["id"]; exists {
		t.Fatalf("did not expect legacy id field in thread row, got %#v", thread)
	}

	if _, exists := decoded["logs"]; exists {
		t.Fatalf("did not expect legacy logs field in payload, got keys=%v", sortedKeys(decoded))
	}

	logs, ok := decoded["windowsEventLogs"].([]any)
	if !ok || len(logs) != 1 {
		t.Fatalf("expected one windowsEventLogs row, got %#v", decoded["windowsEventLogs"])
	}
	logRow, ok := logs[0].(map[string]any)
	if !ok {
		t.Fatalf("expected log row object, got %#v", logs[0])
	}
	if logRow["detailsXml"] != "<Event />" {
		t.Fatalf("expected detailsXml to round-trip, got %#v", logRow["detailsXml"])
	}
	if logRow["logType"] != "powershell" {
		t.Fatalf("expected logType powershell, got %#v", logRow["logType"])
	}
	if logRow["timestamp"] != "2026-04-16T03:02:35Z" {
		t.Fatalf("expected timestamp to round-trip, got %#v", logRow["timestamp"])
	}
	if _, exists := logRow["eventData"]; !exists {
		t.Fatalf("expected eventData field in windowsEventLogs row, got keys=%v", sortedKeys(logRow))
	}
	if _, exists := logRow["normalizedFields"]; !exists {
		t.Fatalf("expected normalizedFields field in windowsEventLogs row, got keys=%v", sortedKeys(logRow))
	}
	if _, exists := logRow["keywords"]; !exists {
		t.Fatalf("expected keywords field in windowsEventLogs row, got keys=%v", sortedKeys(logRow))
	}
	if _, exists := logRow["log_type"]; exists {
		t.Fatalf("did not expect legacy snake_case log_type field, got %#v", logRow)
	}
	if _, exists := logRow["details_xml"]; exists {
		t.Fatalf("did not expect legacy snake_case details_xml field, got %#v", logRow)
	}
	for _, forbidden := range []string{"channel", "provider", "message", "eventTimestamp"} {
		if _, exists := logRow[forbidden]; exists {
			t.Fatalf("did not expect %s in canonical log payload, got %#v", forbidden, logRow)
		}
	}
}

func TestQuickScanDataIncludesFileIdentities(t *testing.T) {
	body, err := json.Marshal(QuickScanData{
		Version: "v1",
		FileIdentities: []FileIdentity{
			{
				ID:        "file-id-1",
				Path:      `C:\Users\Public\svchost.exe`,
				SHA256:    "sha256-value",
				HashState: "completed",
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal quick scan data: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("unmarshal quick scan data: %v", err)
	}
	rows, ok := decoded["fileIdentities"].([]any)
	if !ok || len(rows) != 1 {
		t.Fatalf("expected fileIdentities array, got %#v", decoded["fileIdentities"])
	}
	row, ok := rows[0].(map[string]any)
	if !ok || row["sha256"] != "sha256-value" {
		t.Fatalf("expected file identity row to be preserved, got %#v", rows[0])
	}
}

func TestQuickScanDataUsesForensicFileSystemContractFields(t *testing.T) {
	body, err := json.Marshal(QuickScanData{
		Version:   "v1",
		Timestamp: "2026-04-22T00:00:00Z",
		ForensicVolumes: []filesystem.VolumeInfo{
			{
				VolumeID:             "volume-1",
				DevicePath:           `\\.\C:`,
				DriveLetter:          "C:",
				FileSystem:           "NTFS",
				FilesystemProbeError: "device not ready",
				SerialNumber:         "A1B2C3D4",
				BytesPerSector:       512,
				SectorsPerCluster:    8,
				ClusterSize:          4096,
				MFTStartLCN:          786432,
				FileRecordSize:       1024,
			},
		},
		ForensicDirectoryNodes: []filesystem.DirectoryNode{
			{
				NodeID:         "volume-1:5",
				VolumeID:       "volume-1",
				MFTEntry:       5,
				MFTSequence:    1,
				ParentMFTEntry: 5,
				Path:           `\Users`,
				ParentPath:     `\`,
				Name:           "Users",
			},
		},
		ForensicFileEntries: []filesystem.FileEntry{
			{
				EntryID:         "volume-1:42",
				VolumeID:        "volume-1",
				MFTEntry:        42,
				MFTSequence:     2,
				ParentMFTEntry:  5,
				Path:            `\Users\alice\note.txt`,
				ParentPath:      `\Users\alice`,
				Name:            "note.txt",
				Extension:       ".txt",
				IsDirectory:     false,
				IsDeleted:       false,
				IsAllocated:     true,
				IsOrphan:        false,
				Size:            12,
				AllocatedSize:   4096,
				MimeType:        "text/plain; charset=utf-8",
				HashState:       "pending",
				CreatedAt:       "2026-04-22T00:00:00Z",
				ModifiedAt:      "2026-04-22T00:00:01Z",
				AccessedAt:      "2026-04-22T00:00:02Z",
				ChangedAt:       "2026-04-22T00:00:03Z",
				TimestampSource: "file_name",
				RecordFlags:     []string{"in_use"},
				NameType:        "win32",
			},
		},
		ForensicTimelineEvents: []filesystem.TimelineEvent{
			{
				EventID:   "event-1",
				VolumeID:  "volume-1",
				EntryID:   "volume-1:42",
				Path:      `\Users\alice\note.txt`,
				EventType: "modified",
				Timestamp: "2026-04-22T00:00:01Z",
				Source:    "file_name",
			},
		},
		ForensicDiagnostics: filesystem.CollectorDiagnostics{
			TotalParsedRecords:        2,
			TotalEntriesEmitted:       2,
			TotalFileEntriesEmitted:   1,
			TimestampCoverageModified: 1,
			SkippedVolumes: []filesystem.VolumeSkipDiagnostic{
				{
					VolumeID:    "vol:e",
					DriveLetter: "E:",
					FileSystem:  "ReFS",
					ReasonCode:  "unsupported_filesystem",
					Evidence:    "ReFS",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal quick scan data: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("unmarshal quick scan data: %v", err)
	}

	for _, key := range []string{"forensicVolumes", "forensicDirectoryNodes", "forensicFileEntries", "forensicTimelineEvents"} {
		rows, ok := decoded[key].([]any)
		if !ok || len(rows) != 1 {
			t.Fatalf("expected one %s row, got %#v", key, decoded[key])
		}
	}
	if _, exists := decoded["forensicDiagnostics"]; !exists {
		t.Fatalf("expected forensicDiagnostics object, got keys=%v", sortedKeys(decoded))
	}

	volume, ok := decoded["forensicVolumes"].([]any)[0].(map[string]any)
	if !ok {
		t.Fatalf("expected forensicVolumes row object, got %#v", decoded["forensicVolumes"])
	}
	for _, want := range []string{"volumeId", "devicePath", "driveLetter", "filesystem", "filesystemProbeError", "serialNumber", "bytesPerSector", "sectorsPerCluster", "clusterSize", "mftStartLcn", "fileRecordSize"} {
		if _, exists := volume[want]; !exists {
			t.Fatalf("expected %s field in forensicVolumes row, got keys=%v", want, sortedKeys(volume))
		}
	}

	entry, ok := decoded["forensicFileEntries"].([]any)[0].(map[string]any)
	if !ok {
		t.Fatalf("expected forensicFileEntries row object, got %#v", decoded["forensicFileEntries"])
	}
	for _, want := range []string{"entryId", "volumeId", "mftEntry", "mftSequence", "parentMftEntry", "path", "parentPath", "name", "extension", "isDirectory", "isDeleted", "isAllocated", "isOrphan", "size", "allocatedSize", "mimeType", "hashState", "createdAt", "modifiedAt", "accessedAt", "changedAt", "timestampSource", "recordFlags", "nameType"} {
		if _, exists := entry[want]; !exists {
			t.Fatalf("expected %s field in forensicFileEntries row, got keys=%v", want, sortedKeys(entry))
		}
	}

	event, ok := decoded["forensicTimelineEvents"].([]any)[0].(map[string]any)
	if !ok {
		t.Fatalf("expected forensicTimelineEvents row object, got %#v", decoded["forensicTimelineEvents"])
	}
	for _, want := range []string{"eventId", "volumeId", "entryId", "path", "eventType", "timestamp", "source"} {
		if _, exists := event[want]; !exists {
			t.Fatalf("expected %s field in forensicTimelineEvents row, got keys=%v", want, sortedKeys(event))
		}
	}

	diagnostics, ok := decoded["forensicDiagnostics"].(map[string]any)
	if !ok {
		t.Fatalf("expected forensicDiagnostics object, got %#v", decoded["forensicDiagnostics"])
	}
	for _, want := range []string{"totalParsedRecords", "totalEntriesEmitted", "totalFileEntriesEmitted", "timestampCoverageModified", "skippedVolumes"} {
		if _, exists := diagnostics[want]; !exists {
			t.Fatalf("expected %s field in forensicDiagnostics, got keys=%v", want, sortedKeys(diagnostics))
		}
	}
	skippedVolumes, ok := diagnostics["skippedVolumes"].([]any)
	if !ok || len(skippedVolumes) != 1 {
		t.Fatalf("expected one skipped volume diagnostic, got %#v", diagnostics["skippedVolumes"])
	}
	skippedVolume, ok := skippedVolumes[0].(map[string]any)
	if !ok || skippedVolume["reasonCode"] != "unsupported_filesystem" || skippedVolume["driveLetter"] != "E:" {
		t.Fatalf("expected structured skipped volume diagnostic, got %#v", skippedVolumes)
	}
}
