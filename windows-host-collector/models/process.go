package models

// ProcessNode 进程节点（对应前端 types.ts L118-125）
type ProcessNode struct {
	PID         int            `json:"pid"`
	Name        string         `json:"name"`
	Path        *string        `json:"path,omitempty"`
	CommandLine *string        `json:"commandLine,omitempty"`
	ParentPID   *int           `json:"parentPid,omitempty"`
	Children    []*ProcessNode `json:"children,omitempty"`
}

// ProcessBasicInfo 进程基本信息（对应前端 types.ts L127-146）
type ProcessBasicInfo struct {
	ProcessName         string             `json:"processName"`
	PID                 int                `json:"pid"`
	CommandLine         *string            `json:"commandLine,omitempty"`
	ImagePath           *string            `json:"imagePath,omitempty"`
	CreatedAt           *string            `json:"createdAt,omitempty"`
	User                *string            `json:"user,omitempty"`
	HandleCount         *int               `json:"handleCount,omitempty"`
	MD5                 *string            `json:"md5,omitempty"`
	FileIdentityID      *string            `json:"fileIdentityId,omitempty"`
	SHA256              *string            `json:"sha256,omitempty"`
	HashState           *string            `json:"hashState,omitempty"`
	SignatureState      *string            `json:"signatureState,omitempty"`
	SignerSubject       *string            `json:"signerSubject,omitempty"`
	PEOriginalFilename  *string            `json:"peOriginalFilename,omitempty"`
	MasqueradeRiskLevel *string            `json:"masqueradeRiskLevel,omitempty"`
	MasqueradeSignals   []MasqueradeSignal `json:"masqueradeSignals,omitempty"`
	ThreadCount         *int               `json:"threadCount,omitempty"`
	Is64Bit             *bool              `json:"is64Bit,omitempty"`
	SessionID           *int               `json:"sessionId,omitempty"`
	BasePriority        *int               `json:"basePriority,omitempty"`
	Domain              *string            `json:"domain,omitempty"`
	ParentPID           *int               `json:"parentPid,omitempty"`
	ParentName          *string            `json:"parentName,omitempty"`
	ParentCommandLine   *string            `json:"parentCommandLine,omitempty"`
	ParentPath          *string            `json:"parentPath,omitempty"`
	BaseAddress         *string            `json:"baseAddress,omitempty"`
}

// ProcessMemoryBlock 进程内存块（对应前端 types.ts L148-161）
type ProcessMemoryBlock struct {
	ID          string `json:"id"`
	BaseAddress string `json:"baseAddress"`
	Size        string `json:"size"`
	Type        string `json:"type"`
	Protection  string `json:"protection"`
	Owner       string `json:"owner"`
	ThreadID    *int   `json:"threadId,omitempty"`
	CanRead     bool   `json:"canRead"`
	CanWrite    bool   `json:"canWrite"`
	CanExecute  bool   `json:"canExecute"`
	Guarded     bool   `json:"guarded"`
}

// ProcessIOStats 进程IO统计（对应前端 types.ts L163-170）
type ProcessIOStats struct {
	ReadCount          int64 `json:"readCount"`
	WriteCount         int64 `json:"writeCount"`
	OtherCount         int64 `json:"otherCount"`
	ReadTransferCount  int64 `json:"readTransferCount"`
	WriteTransferCount int64 `json:"writeTransferCount"`
	OtherTransferCount int64 `json:"otherTransferCount"`
}

// ProcessModule 进程模块（对应前端 types.ts L172-179）
type ProcessModule struct {
	ID                 string  `json:"id"`
	Name               string  `json:"name"`
	Path               string  `json:"path"`
	BaseAddress        string  `json:"baseAddress"`
	Size               int64   `json:"size"`
	EntryPoint         string  `json:"entryPoint"`
	IsSigned           bool    `json:"isSigned"`
	FileIdentityID     *string `json:"fileIdentityId,omitempty"`
	SHA256             *string `json:"sha256,omitempty"`
	HashState          *string `json:"hashState,omitempty"`
	SignatureState     *string `json:"signatureState,omitempty"`
	SignerSubject      *string `json:"signerSubject,omitempty"`
	PEOriginalFilename *string `json:"peOriginalFilename,omitempty"`
}

// ProcessThread 进程线程（对应前端 types.ts L181-192）
type ProcessThread struct {
	ThreadID           int    `json:"threadId"`
	ReadCount          int64  `json:"readCount"`
	WriteCount         int64  `json:"writeCount"`
	OtherCount         int64  `json:"otherCount"`
	ReadTransferCount  int64  `json:"readTransferCount"`
	WriteTransferCount int64  `json:"writeTransferCount"`
	OtherTransferCount int64  `json:"otherTransferCount"`
	ContextSwitches    int64  `json:"contextSwitches"`
	State              string `json:"state"`
	WaitReason         string `json:"waitReason"`
}

// ProcessWindow 进程窗口（对应前端 types.ts L194-203）
type ProcessWindow struct {
	Handle       string  `json:"handle"`
	ParentHandle *string `json:"parentHandle,omitempty"`
	ThreadID     int     `json:"threadId"`
	ClassName    string  `json:"className"`
	Title        string  `json:"title"`
	Rect         [4]int  `json:"rect"` // [x, y, width, height]
	Visible      bool    `json:"visible"`
}

// ProcessNetworkConnection 进程网络连接（对应前端 types.ts L205-216）
type ProcessNetworkConnection struct {
	ID            string `json:"id"`
	Protocol      string `json:"protocol"` // TCP or UDP
	Family        string `json:"family"`   // AF_INET or AF_INET6
	LocalAddress  string `json:"localAddress"`
	LocalPort     int    `json:"localPort"`
	RemoteAddress string `json:"remoteAddress"`
	RemotePort    int    `json:"remotePort"`
	StateCode     int    `json:"stateCode"`
	StateName     string `json:"stateName"`
	CreatedAt     string `json:"createdAt"`
}

// ProcessHandle 进程句柄（对应前端 types.ts L218-228）
type ProcessHandle struct {
	ID            string  `json:"id"`
	PID           int     `json:"pid"`
	ObjectType    string  `json:"objectType"`
	Attributes    string  `json:"attributes"`
	Value         string  `json:"value"`
	ObjectAddress string  `json:"objectAddress"`
	AccessMask    string  `json:"accessMask"`
	TypeName      string  `json:"typeName"`
	ObjectName    *string `json:"objectName,omitempty"`
}

// ProcessDetail 进程详细信息（对应前端 types.ts L230-240）
type ProcessDetail struct {
	BasicInfo          *ProcessBasicInfo          `json:"basicInfo"`
	MemoryBlocks       []ProcessMemoryBlock       `json:"memoryBlocks"`
	IOStats            ProcessIOStats             `json:"ioStats"`
	Modules            []ProcessModule            `json:"modules"`
	ModulesTotal       int                        `json:"modulesTotal"`
	Threads            []ProcessThread            `json:"threads"`
	Windows            []ProcessWindow            `json:"windows"`
	NetworkConnections []ProcessNetworkConnection `json:"networkConnections"`
	Handles            []ProcessHandle            `json:"handles"`
}
