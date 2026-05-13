package upload

const ProtocolVersionUploadItemsV1 = "upload-items-v1"

type Metadata struct {
	AgentID     string
	ScanID      string
	ScanType    string
	CollectedAt string
}

type Item struct {
	ItemID          string
	ItemKind        string
	ItemName        string
	AgentID         string
	ScanID          string
	ScanType        string
	CollectedAt     string
	ItemIndex       int
	ItemCount       int
	ContentType     string
	ContentEncoding string
	PayloadJSON     []byte
}

type Plan struct {
	ItemID   string
	ItemKind string
	Sections []string
}
