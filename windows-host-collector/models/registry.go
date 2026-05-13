package models

// RegistryValue 注册表值（对应前端 types.ts L96-103）
type RegistryValue struct {
	ID                       string  `json:"id"`
	Name                     string  `json:"name"`
	Type                     string  `json:"type"`
	Data                     string  `json:"data"`
	Path                     string  `json:"path"`
	ModifiedAt               *string `json:"modifiedAt,omitempty"`
	CollectionCategory       string  `json:"collectionCategory,omitempty"`
	RiskPurpose              string  `json:"riskPurpose,omitempty"`
	ReferencedPath           *string `json:"referencedPath,omitempty"`
	ReferencedFileIdentityID *string `json:"referencedFileIdentityId,omitempty"`
}

// RegistryNode 注册表节点（对应前端 types.ts L105-112）
type RegistryNode struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Path     string          `json:"path"`
	Label    string          `json:"label"`
	Children []*RegistryNode `json:"children,omitempty"`
	Values   []RegistryValue `json:"values,omitempty"`
}
