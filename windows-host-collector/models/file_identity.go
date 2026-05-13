package models

// FileIdentity records reusable file evidence for process and registry references.
type FileIdentity struct {
	ID                 string   `json:"id"`
	Path               string   `json:"path"`
	NormalizedPath     string   `json:"normalizedPath,omitempty"`
	Basename           string   `json:"basename,omitempty"`
	Extension          string   `json:"extension,omitempty"`
	Size               int64    `json:"size,omitempty"`
	CreatedAt          string   `json:"createdAt,omitempty"`
	ModifiedAt         string   `json:"modifiedAt,omitempty"`
	MD5                string   `json:"md5,omitempty"`
	SHA256             string   `json:"sha256,omitempty"`
	HashState          string   `json:"hashState,omitempty"`
	SignatureState     string   `json:"signatureState,omitempty"`
	SignerSubject      string   `json:"signerSubject,omitempty"`
	SignerIssuer       string   `json:"signerIssuer,omitempty"`
	SignerThumbprint   string   `json:"signerThumbprint,omitempty"`
	PEOriginalFilename string   `json:"peOriginalFilename,omitempty"`
	PECompanyName      string   `json:"peCompanyName,omitempty"`
	PEProductName      string   `json:"peProductName,omitempty"`
	PEFileDescription  string   `json:"peFileDescription,omitempty"`
	EvidenceSources    []string `json:"evidenceSources,omitempty"`
	CollectionError    string   `json:"collectionError,omitempty"`
}

// MasqueradeSignal describes one system process masquerade detection signal.
type MasqueradeSignal struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}
