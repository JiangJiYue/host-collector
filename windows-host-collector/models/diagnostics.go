package models

type PlatformProfile struct {
	Platform            string         `json:"platform"`
	SupportLevel        string         `json:"supportLevel"`
	BuildFamily         string         `json:"buildFamily,omitempty"`
	Architecture        string         `json:"architecture,omitempty"`
	CapabilitiesVersion string         `json:"capabilitiesVersion"`
	Capabilities        []string       `json:"capabilities"`
	CapabilityStatuses  map[string]any `json:"capabilityStatuses,omitempty"`
	Facts               map[string]any `json:"facts,omitempty"`
}

type StageDiagnostic struct {
	Stage      string `json:"stage"`
	State      string `json:"state"`
	ReasonCode string `json:"reasonCode"`
	Capability string `json:"capability,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
}
