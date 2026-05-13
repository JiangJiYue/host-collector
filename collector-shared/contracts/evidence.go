package contracts

type EvidenceKind string

const (
	EvidenceProcess     EvidenceKind = "process"
	EvidenceNetwork     EvidenceKind = "network"
	EvidenceFile        EvidenceKind = "file"
	EvidenceLog         EvidenceKind = "log"
	EvidencePersistence EvidenceKind = "persistence"
	EvidenceAccount     EvidenceKind = "account"
)

type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

type SubjectType string

const (
	SubjectHost    SubjectType = "host"
	SubjectProcess SubjectType = "process"
	SubjectUser    SubjectType = "user"
	SubjectFile    SubjectType = "file"
	SubjectNetwork SubjectType = "network"
)

type Subject struct {
	Type SubjectType `json:"type"`
	ID   string      `json:"id"`
	Name string      `json:"name,omitempty"`
}

type Evidence struct {
	ID                 string             `json:"id"`
	Kind               EvidenceKind       `json:"kind"`
	Source             string             `json:"source"`
	Timestamp          string             `json:"timestamp,omitempty"`
	Summary            string             `json:"summary,omitempty"`
	Confidence         Confidence         `json:"confidence"`
	Subject            Subject            `json:"subject"`
	PlatformExtensions PlatformExtensions `json:"platformExtensions,omitempty"`
}

type TimelineEvent struct {
	ID                 string             `json:"id"`
	Timestamp          string             `json:"timestamp"`
	EventType          string             `json:"eventType"`
	Subject            Subject            `json:"subject"`
	EvidenceIDs        []string           `json:"evidenceIds,omitempty"`
	PlatformExtensions PlatformExtensions `json:"platformExtensions,omitempty"`
}
