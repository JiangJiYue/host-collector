package collector

type webLogFormat string

const (
	webLogFormatUnknown    webLogFormat = "unknown"
	webLogFormatIISW3C     webLogFormat = "iisW3C"
	webLogFormatCombined   webLogFormat = "combined"
	webLogFormatJSONAccess webLogFormat = "jsonAccess"
)

type webLogConfidence string

const (
	webLogConfidenceLow    webLogConfidence = "low"
	webLogConfidenceMedium webLogConfidence = "medium"
	webLogConfidenceHigh   webLogConfidence = "high"
)

type webLogSourceCandidate struct {
	ID           string
	Path         string
	ServerType   string
	SiteName     string
	Port         int
	SourceMethod string
	Evidence     []string
	ProcessName  string
	ProcessPID   int
}

type webLogFingerprint struct {
	Format     webLogFormat
	Confidence webLogConfidence
	Evidence   []string
}

type webLogParseState struct {
	Format    webLogFormat
	IISFields []string
}

type webLogFileState struct {
	FileIdentity string
	Size         int64
	ModifiedAt   string
	TailHash     string
}

type webLogResumeState struct {
	SourceID     string
	FileIdentity string
	Size         int64
	LastOffset   int64
	TailHash     string
}

type webLogResumeMode string

const (
	webLogResumeModeTail   webLogResumeMode = "tail"
	webLogResumeModeAppend webLogResumeMode = "append"
)

type webLogResumePlan struct {
	Mode        webLogResumeMode
	StartOffset int64
	Reason      string
}
