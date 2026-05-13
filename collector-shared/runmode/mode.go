package runmode

type Edition string
type RunMode string
type AuthMode string
type EncryptionState string

const (
	EditionOSS     Edition         = "oss"
	ModeOSSLocal   RunMode         = "oss-local"
	AuthNone       AuthMode        = "none"
	EncryptionNone EncryptionState = "none"
)

type OutputMetadata struct {
	Edition         Edition         `json:"edition"`
	RunMode         RunMode         `json:"run_mode"`
	AuthMode        AuthMode        `json:"auth_mode"`
	EncryptionState EncryptionState `json:"encryption_state"`
	CollectionScope []string        `json:"collection_scope"`
	ToolVersion     string          `json:"tool_version"`
}
