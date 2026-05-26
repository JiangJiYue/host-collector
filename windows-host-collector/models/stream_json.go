package models

import (
	"io"

	"collector-shared/streamjson"
)

func WriteScanEnvelopeJSON(writer io.Writer, scan *ScanEnvelope) error {
	if scan == nil {
		_, err := io.WriteString(writer, "null")
		return err
	}
	return streamjson.WriteObject(writer, scanJSONFields(scan))
}

func scanJSONFields(scan *ScanEnvelope) []streamjson.Field {
	fields := make([]streamjson.Field, 0, 32)
	add := func(name string, value any) {
		if isEmptyUploadPayloadValue(value) {
			return
		}
		fields = append(fields, streamjson.Field{Name: name, Value: value})
	}
	add("version", scan.Version)
	add("timestamp", scan.Timestamp)
	add("platformProfile", scan.PlatformProfile)
	add("stageDiagnostics", scan.StageDiagnostics)
	add("system", scan.System)
	add("resources", scan.Resources)
	add("hardware", scan.Hardware)
	add("processes", scan.Processes)
	add("processDetails", scan.ProcessDetails)
	add("fileIdentities", scan.FileIdentities)
	add("network", scan.Network)
	add("services", scan.Services)
	add("users", scan.Users)
	add("envVars", scan.EnvVars)
	add("software", scan.Software)
	add("prefetch", scan.Prefetch)
	add("browserHistory", scan.BrowserHistory)
	add("webLogSources", scan.WebLogSources)
	add("webLogEntries", scan.WebLogEntries)
	add("usbRecords", scan.UsbRecords)
	add("operationRecords", scan.OperationRecords)
	add("registries", scan.Registries)
	add("windowsEventLogs", scan.WindowsEventLogs)
	add("forensicVolumes", scan.ForensicVolumes)
	add("forensicDirectoryNodes", scan.ForensicDirectoryNodes)
	add("forensicFileEntries", scan.ForensicFileEntries)
	add("forensicTimelineEvents", scan.ForensicTimelineEvents)
	add("forensicDiagnostics", scan.ForensicDiagnostics)
	return fields
}
