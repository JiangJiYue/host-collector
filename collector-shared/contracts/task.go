package contracts

type TaskID string

type TaskState string

const (
	TaskPending   TaskState = "pending"
	TaskRunning   TaskState = "running"
	TaskCompleted TaskState = "completed"
	TaskSkipped   TaskState = "skipped"
	TaskFailed    TaskState = "failed"
)

type TaskDefinition struct {
	ID                   TaskID       `json:"id"`
	Name                 string       `json:"name"`
	RequiredCapabilities []Capability `json:"requiredCapabilities,omitempty"`
}

type TaskDiagnostic struct {
	Code                ErrorCode    `json:"code"`
	Message             string       `json:"message"`
	MissingCapabilities []Capability `json:"missingCapabilities,omitempty"`
}

type TaskResult struct {
	TaskID      TaskID           `json:"taskId"`
	State       TaskState        `json:"state"`
	Diagnostics []TaskDiagnostic `json:"diagnostics,omitempty"`
	StartedAt   string           `json:"startedAt,omitempty"`
	FinishedAt  string           `json:"finishedAt,omitempty"`
}
