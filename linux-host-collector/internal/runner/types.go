package runner

import (
	"time"

	"collector-shared/appcore"
	"collector-shared/upload"
)

type Config struct {
	Root        string
	GoArch      string
	AgentID     string
	ScanID      string
	ScanScope   []string
	WindowDays  int
	CollectedAt time.Time
	StatusSink  appcore.StatusSink
}

type ScanEnvelope struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Platform        string         `json:"platform"`
	Sections        map[string]any `json:"sections"`
}

type Result struct {
	Envelope    ScanEnvelope  `json:"envelope"`
	UploadItems []upload.Item `json:"uploadItems"`
}
