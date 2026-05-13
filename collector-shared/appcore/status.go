package appcore

import "sync"

type EventType string

const (
	EventScanStarted    EventType = "scan_started"
	EventScanProgress   EventType = "scan_progress"
	EventOutputProgress EventType = "output_progress"
	EventScanCompleted  EventType = "scan_completed"
	EventScanFailed     EventType = "scan_failed"
	EventRuntimeWarning EventType = "runtime_warning"
)

type StatusState string

const (
	StatePending   StatusState = "pending"
	StateRunning   StatusState = "running"
	StateCompleted StatusState = "completed"
	StateSkipped   StatusState = "skipped"
	StateFailed    StatusState = "failed"
	StateDenied    StatusState = "denied"
	StateDegraded  StatusState = "degraded"
)

type StatusEvent struct {
	Type       EventType         `json:"type"`
	StageKey   string            `json:"stageKey,omitempty"`
	StageName  string            `json:"stageName,omitempty"`
	State      StatusState       `json:"state,omitempty"`
	Current    int               `json:"current,omitempty"`
	Total      int               `json:"total,omitempty"`
	Detail     string            `json:"detail,omitempty"`
	Message    string            `json:"message,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type StatusSink interface {
	EmitStatus(StatusEvent)
}

type NopSink struct{}

func (NopSink) EmitStatus(StatusEvent) {}

type Recorder struct {
	mu     sync.Mutex
	events []StatusEvent
}

func NewRecorder() *Recorder {
	return &Recorder{}
}

func (r *Recorder) EmitStatus(event StatusEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.events = append(r.events, cloneStatusEvent(event))
}

func (r *Recorder) Events() []StatusEvent {
	r.mu.Lock()
	defer r.mu.Unlock()

	events := make([]StatusEvent, 0, len(r.events))
	for _, event := range r.events {
		events = append(events, cloneStatusEvent(event))
	}
	return events
}

func cloneStatusEvent(event StatusEvent) StatusEvent {
	if event.Attributes == nil {
		return event
	}
	attributes := make(map[string]string, len(event.Attributes))
	for key, value := range event.Attributes {
		attributes[key] = value
	}
	event.Attributes = attributes
	return event
}
