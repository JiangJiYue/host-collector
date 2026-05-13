package collector

import (
	"context"
	"fmt"
	"time"
	"windows-host-collector/models"
	"windows-host-collector/utils"

	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

const compNetwork = "NetworkCollector"

// NetworkCollector 网络信息采集器
type NetworkCollector struct{}

// NewNetworkCollector 创建网络采集器
func NewNetworkCollector() *NetworkCollector {
	return &NetworkCollector{}
}

// Name 返回采集器名称
func (nc *NetworkCollector) Name() string {
	return "network"
}

// Collect 采集网络信息
func (nc *NetworkCollector) Collect(ctx context.Context) (interface{}, error) {
	utils.Info(compNetwork, "开始采集网络信息...")

	type result struct {
		sessions []models.NetworkSession
		dns      []models.DnsCacheRecord
		shares   []models.NetworkShare
		hosts    []models.HostsEntry
		err      error
	}

	resultChan := make(chan result, 1)

	go func() {
		var r result

		sessions, err := nc.collectNetworkSessions(ctx)
		if err != nil {
			r.err = fmt.Errorf("failed to collect network sessions: %w", err)
			resultChan <- r
			return
		}
		r.sessions = sessions

		dns, err := nc.collectDNSCache(ctx)
		if err != nil {
			utils.LogError(compNetwork, "DNS缓存采集失败: %v", err)
			dns = []models.DnsCacheRecord{}
		}
		r.dns = dns

		shares, err := nc.collectNetworkShares(ctx)
		if err != nil {
			utils.LogError(compNetwork, "网络共享采集失败: %v", err)
			shares = []models.NetworkShare{}
		}
		r.shares = shares

		hosts, err := nc.collectHostsEntries(ctx)
		if err != nil {
			utils.LogError(compNetwork, "Hosts文件采集失败: %v", err)
			hosts = []models.HostsEntry{}
		}
		r.hosts = hosts

		resultChan <- r
	}()

	select {
	case r := <-resultChan:
		if r.err != nil {
			return nil, r.err
		}

		utils.Info(compNetwork, "网络信息采集完成: %d个连接, %d个DNS缓存, %d个共享, %d个Hosts条目",
			len(r.sessions), len(r.dns), len(r.shares), len(r.hosts))

		return &NetworkCollectionResult{
			Sessions: r.sessions,
			DNS:      r.dns,
			Shares:   r.shares,
			Hosts:    r.hosts,
		}, nil

	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// NetworkCollectionResult 网络采集结果
type NetworkCollectionResult struct {
	Sessions []models.NetworkSession `json:"sessions"`
	DNS      []models.DnsCacheRecord `json:"dns"`
	Shares   []models.NetworkShare   `json:"shares"`
	Hosts    []models.HostsEntry     `json:"hosts"`
}

// collectNetworkSessions 使用 gopsutil 采集真实网络连接
func (nc *NetworkCollector) collectNetworkSessions(ctx context.Context) ([]models.NetworkSession, error) {
	connections, err := net.Connections("all")
	if err != nil {
		utils.LogError(compNetwork, "获取网络连接失败: %v", err)
		return []models.NetworkSession{}, nil
	}

	sessions := make([]models.NetworkSession, 0, len(connections))
	for i, conn := range connections {
		processName := fmt.Sprintf("PID-%d", conn.Pid)
		if conn.Pid > 0 {
			p, err := process.NewProcess(conn.Pid)
			if err == nil {
				if name, err := p.Name(); err == nil && name != "" {
					processName = name
				}
			}
		}

		stateCode := 0
		switch conn.Status {
		case "ESTABLISHED":
			stateCode = 5
		case "LISTEN":
			stateCode = 2
		case "CLOSE_WAIT":
			stateCode = 8
		case "TIME_WAIT":
			stateCode = 6
		}

		connType := "TCP"
		if conn.Type == 2 {
			connType = "UDP"
		}

		session := models.NetworkSession{
			ID:          fmt.Sprintf("conn-%d", i),
			LocalIP:     conn.Laddr.IP,
			LocalPort:   int(conn.Laddr.Port),
			RemoteIP:    conn.Raddr.IP,
			RemotePort:  int(conn.Raddr.Port),
			StateCode:   stateCode,
			StateName:   conn.Status,
			ProcessName: processName,
			Protocol:    connType,
			CreatedAt:   utils.FormatTimeRFC3339(time.Now()),
		}

		sessions = append(sessions, session)
	}

	return sessions, nil
}

// collectDNSCache 采集 DNS 缓存（仅 Windows）
func (nc *NetworkCollector) collectDNSCache(ctx context.Context) ([]models.DnsCacheRecord, error) {
	return nc.collectWindowsDNSCache(ctx)
}

// collectNetworkShares 采集网络共享
func (nc *NetworkCollector) collectNetworkShares(ctx context.Context) ([]models.NetworkShare, error) {
	// Delegate to platform-specific implementation.
	return collectNetworkSharesPlatform(ctx, nc)
}

// collectHostsEntries 采集 Hosts 文件
func (nc *NetworkCollector) collectHostsEntries(ctx context.Context) ([]models.HostsEntry, error) {
	// Delegate to platform-specific implementation.
	return collectHostsEntriesPlatform(ctx, nc)
}
