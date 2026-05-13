package models

// NetworkAdapterInfo 网络适配器信息
type NetworkAdapterInfo struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	AdapterName     string   `json:"adapterName,omitempty"`
	Description     string   `json:"description,omitempty"`
	MACAddress      string   `json:"macAddress,omitempty"`
	IPAddresses     []string `json:"ipAddresses,omitempty"`
	DefaultGateways []string `json:"defaultGateways,omitempty"`
	DNSServers      []string `json:"dnsServers,omitempty"`
	DHCPEnabled     *bool    `json:"dhcpEnabled,omitempty"`
	PhysicalAdapter *bool    `json:"physicalAdapter,omitempty"`
	NetEnabled      *bool    `json:"netEnabled,omitempty"`
}

// NetworkSession 网络会话（对应前端 types.ts L295-307）
type NetworkSession struct {
	ID          string  `json:"id"`
	LocalIP     string  `json:"localIp"`
	LocalPort   int     `json:"localPort"`
	RemoteIP    string  `json:"remoteIp"`
	RemotePort  int     `json:"remotePort"`
	StateCode   int     `json:"stateCode"`
	StateName   string  `json:"stateName"`
	ProcessName string  `json:"processName"`
	CreatedAt   string  `json:"createdAt"`
	Protocol    string  `json:"protocol"`
	IPDetails   *string `json:"ipDetails,omitempty"`
}

// NetworkShare 网络共享（对应前端 types.ts L318-326）
type NetworkShare struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Type        string  `json:"type"`
	Remark      *string `json:"remark,omitempty"`
	Path        *string `json:"path,omitempty"`
	Permissions *string `json:"permissions,omitempty"`
	MaxUses     *int    `json:"maxUses,omitempty"`
}

// DnsCacheRecord DNS缓存记录（对应前端 types.ts L328-334）
type DnsCacheRecord struct {
	ID         string `json:"id"`
	Host       string `json:"host"`
	RecordType string `json:"recordType"`
	IPAddress  string `json:"ipAddress"`
	TTL        int    `json:"ttl"`
}

// HostsEntry Hosts文件条目（对应前端 types.ts L336-340）
type HostsEntry struct {
	ID        string `json:"id"`
	IPAddress string `json:"ipAddress"`
	Domain    string `json:"domain"`
}
