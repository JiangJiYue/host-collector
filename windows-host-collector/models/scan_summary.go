package models

type StageState string

const (
	StageCompleted StageState = "completed"
	StagePartial   StageState = "partial"
	StageSkipped   StageState = "skipped"
	StageTimedOut  StageState = "timed_out"
	StageDenied    StageState = "denied"
	StageFailed    StageState = "failed"
)

type ScanStageSummary struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
}
