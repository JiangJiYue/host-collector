package models

// LocalUserAccount 本地用户账户
type LocalUserAccount struct {
	ID               string                 `json:"id"`
	Username         string                 `json:"username"`
	FullName         *string                `json:"fullName,omitempty"`
	SID              *string                `json:"sid,omitempty"`
	RID              *uint32                `json:"rid,omitempty"`
	AccountType      string                 `json:"accountType"`
	Privilege        string                 `json:"privilege"`
	Comment          *string                `json:"comment,omitempty"`
	LogonScript      *string                `json:"logonScript,omitempty"`
	LastLogon        *string                `json:"lastLogon,omitempty"`
	ExpiresAt        *string                `json:"expiresAt,omitempty"`
	LoginFailures    int                    `json:"loginFailures"`
	LoginSuccesses   int                    `json:"loginSuccesses"`
	LocalGroups      []string               `json:"localGroups"`
	GlobalGroups     []string               `json:"globalGroups"`
	AllowedLogonTime *string                `json:"allowedLogonTime,omitempty"`
	Disabled         bool                   `json:"disabled"`
	Sources          []string               `json:"sources"`
	SAM              *SAMAccountEvidence    `json:"sam,omitempty"`
	Visibility       AccountVisibility      `json:"visibility"`
	Shadow           ShadowAccountDetection `json:"shadow"`
}

type AccountVisibility struct {
	NetAPI             bool `json:"netApi"`
	WMI                bool `json:"wmi"`
	NetCommand         bool `json:"netCommand"`
	SAMRidKey          bool `json:"samRidKey"`
	SAMNameIndex       bool `json:"samNameIndex"`
	SAMAliasMembership bool `json:"samAliasMembership"`
}

type SAMAccountEvidence struct {
	NameIndexRID            *uint32  `json:"nameIndexRid,omitempty"`
	RIDKeyPresent           bool     `json:"ridKeyPresent"`
	NameIndexPresent        bool     `json:"nameIndexPresent"`
	FDigest                 string   `json:"fDigest,omitempty"`
	VDigest                 string   `json:"vDigest,omitempty"`
	ParsedUsername          *string  `json:"parsedUsername,omitempty"`
	ParsedFullName          *string  `json:"parsedFullName,omitempty"`
	ParsedComment           *string  `json:"parsedComment,omitempty"`
	Flags                   *uint32  `json:"flags,omitempty"`
	LastLogon               *string  `json:"lastLogon,omitempty"`
	LoginFailures           *int     `json:"loginFailures,omitempty"`
	LoginSuccesses          *int     `json:"loginSuccesses,omitempty"`
	BuiltinAliasMemberships []string `json:"builtinAliasMemberships"`
}

type ShadowAccountDetection struct {
	IsShadowAccount bool     `json:"isShadowAccount"`
	Status          string   `json:"status"`
	Confidence      string   `json:"confidence"`
	Reasons         []string `json:"reasons"`
	Evidence        []string `json:"evidence"`
}

// EnvironmentVariable 环境变量
type EnvironmentVariable struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
