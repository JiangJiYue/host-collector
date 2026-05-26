//go:build windows

package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"windows-host-collector/models"
	"windows-host-collector/utils"
)

// collectNetworkSharesPlatform Windows: use WMI Win32_Share
func collectNetworkSharesPlatform(ctx context.Context, nc *NetworkCollector) ([]models.NetworkShare, error) {
	type wmiShare struct {
		Name           string
		Path           *string
		Type           uint32
		Description    *string
		MaximumAllowed uint32
		AllowMaximum   bool
	}

	var shares []wmiShare
	// 0: Disk Drive, 1: Print Queue, 2: Device, 3: IPC, 2147483648: Disk Drive Admin, etc.
	query := "SELECT Name, Path, Type, Description, MaximumAllowed, AllowMaximum FROM Win32_Share"
	wmiErr := nc.doWMIQuery(query, &shares)
	if wmiErr == nil && len(shares) > 0 {
		results := make([]models.NetworkShare, 0, len(shares))
		for i, s := range shares {
			t := shareTypeToString(s.Type)
			var remark *string
			if s.Description != nil && strings.TrimSpace(*s.Description) != "" {
				remark = s.Description
			}
			var maxUses *int
			if !s.AllowMaximum {
				v := int(s.MaximumAllowed)
				maxUses = &v
			}
			results = append(results, models.NetworkShare{
				ID:      fmt.Sprintf("share-%d", i),
				Name:    s.Name,
				Type:    t,
				Remark:  remark,
				Path:    s.Path,
				MaxUses: maxUses,
			})
		}
		// 可选增强: 使用 WMI/PowerShell 补齐权限与会话信息
		results = enrichShareDetails(ctx, results)
		utils.Info(compNetwork, "网络共享采集完成(WMI): %d 个", len(results))
		return results, nil
	}

	if wmiErr != nil {
		utils.LogError(compNetwork, "WMI 查询 Win32_Share 失败: %v，尝试 net share 回退", wmiErr)
	} else {
		utils.Info(compNetwork, "WMI 返回 0 个共享，尝试 net share 回退")
	}

	// 回退: 解析 `net share` 输出，并尝试补齐权限/会话
	results, err := collectNetworkSharesViaNetShare(ctx)
	if err == nil && len(results) > 0 {
		results = enrichShareDetails(ctx, results)
	}
	return results, err
}

func shareTypeToString(t uint32) string {
	switch t {
	case 0:
		return "Disk"
	case 1:
		return "Print"
	case 2:
		return "Device"
	case 3:
		return "IPC"
	case 2147483648:
		return "Disk(Admin)"
	case 2147483651:
		return "Print(Admin)"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}

// collectHostsEntriesPlatform Windows: use Win32 API and registry fallback
func collectHostsEntriesPlatform(ctx context.Context, nc *NetworkCollector) ([]models.HostsEntry, error) {
	return nc.collectWindowsHostsEntries(ctx)
}

// collectNetworkSharesViaNetShare 使用 `net share` 作为 WMI 回退
func collectNetworkSharesViaNetShare(ctx context.Context) ([]models.NetworkShare, error) {
	cmd := exec.CommandContext(ctx, systemExecutablePath("cmd.exe"), "/D", "/C", "chcp 65001>nul && net share")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("执行 net share 失败: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	splitRe := regexp.MustCompile(`\s{2,}`)

	var results []models.NetworkShare
	rowIndex := 0
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		// 跳过表头/分隔/尾部
		lower := strings.ToLower(line)
		if strings.Contains(lower, "share name") || strings.Contains(lower, "共享名") {
			continue
		}
		if strings.HasPrefix(line, "---") || strings.HasPrefix(line, "——") {
			continue
		}
		if strings.Contains(lower, "command completed successfully") || strings.Contains(line, "命令成功完成") {
			continue
		}

		cols := splitRe.Split(line, 3)
		if len(cols) == 0 {
			continue
		}
		name := strings.TrimSpace(cols[0])
		if name == "" {
			continue
		}
		var resource string
		var remark *string
		if len(cols) >= 2 {
			resource = strings.TrimSpace(cols[1])
		}
		if len(cols) == 3 {
			r := strings.TrimSpace(cols[2])
			if r != "" {
				remark = &r
			}
		}

		// 推断类型
		t := inferShareType(name, resource)

		var pathPtr *string
		if resource != "" {
			res := resource
			pathPtr = &res
		}

		results = append(results, models.NetworkShare{
			ID:     fmt.Sprintf("share-%d", rowIndex),
			Name:   name,
			Type:   t,
			Remark: remark,
			Path:   pathPtr,
		})
		rowIndex++
	}

	utils.Info(compNetwork, "网络共享采集完成(net share): %d 个", len(results))
	return results, nil
}

func inferShareType(name, resource string) string {
	n := strings.ToUpper(strings.TrimSpace(name))
	if n == "IPC$" {
		return "IPC"
	}
	// 简单推断: 有盘符/UNC 路径 -> Disk
	r := strings.ToUpper(strings.TrimSpace(resource))
	if strings.Contains(r, ":\\") || strings.HasPrefix(r, "\\\\") {
		return "Disk"
	}
	return "Unknown"
}

// ====== 共享增强：权限/会话（尽力而为） ======

// enrichShareDetails 尝试补齐权限与会话统计，不影响主流程
func enrichShareDetails(ctx context.Context, in []models.NetworkShare) []models.NetworkShare {
	if len(in) == 0 {
		return in
	}

	// 1) 会话统计（WMI Win32_ServerConnection）
	sessions := collectShareSessionsViaWMI()

	// 2) 权限列表（PowerShell Get-SmbShareAccess）
	perms := collectSharePermissionsPS(ctx)

	// 3) 合成 Permissions 文本
	for i := range in {
		name := in[i].Name
		sess := sessions[strings.ToUpper(name)]
		permList := perms[strings.ToUpper(name)]

		var pieces []string
		if sess != nil {
			pieces = append(pieces, fmt.Sprintf("sessions=%d opens=%d", sess.Count, sess.Opens))
		}
		if len(permList) > 0 {
			pieces = append(pieces, "access="+strings.Join(permList, "; "))
		}
		if len(pieces) > 0 {
			v := strings.Join(pieces, "; ")
			in[i].Permissions = &v
		}
	}
	return in
}

// collectShareSessionsViaWMI 统计每个共享的会话数量和打开数
func collectShareSessionsViaWMI() map[string]*struct{ Count, Opens int } {
	type wmiConn struct {
		ShareName    string
		UserName     string
		ComputerName string
		ActiveTime   uint32
		NumOpens     uint32
	}
	var rows []wmiConn
	out := map[string]*struct{ Count, Opens int }{}
	// 忽略错误，尽力而为
	if err := defaultNetworkCollector().doWMIQuery("SELECT ShareName,UserName,ComputerName,ActiveTime,NumOpens FROM Win32_ServerConnection", &rows); err != nil {
		return out
	}
	for _, r := range rows {
		key := strings.ToUpper(strings.TrimSpace(r.ShareName))
		if key == "" {
			continue
		}
		e := out[key]
		if e == nil {
			e = &struct{ Count, Opens int }{}
			out[key] = e
		}
		e.Count++
		e.Opens += int(r.NumOpens)
	}
	return out
}

// collectSharePermissionsPS 使用 PowerShell 获取共享 ACL 列表
func collectSharePermissionsPS(ctx context.Context) map[string][]string {
	type psACL struct {
		Name              string `json:"Name"`
		AccountName       string `json:"AccountName"`
		AccessControlType string `json:"AccessControlType"`
		AccessRight       string `json:"AccessRight"`
	}
	// PowerShell: 汇总所有共享的 ACL
	// 可能返回单对象或数组，均需兼容
	cmd := exec.CommandContext(ctx, systemExecutablePath("WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-ExecutionPolicy", "Bypass",
		"-Command",
		`$ErrorActionPreference='SilentlyContinue'; Get-SmbShareAccess -Name * | Select-Object Name,AccountName,AccessControlType,AccessRight | ConvertTo-Json -Compress`)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		return map[string][]string{}
	}

	// 解析 JSON（可能是对象，也可能是数组）
	var arr []psACL
	if len(out) > 0 && out[0] == '{' {
		var single psACL
		if json.Unmarshal(out, &single) == nil {
			arr = []psACL{single}
		}
	} else {
		_ = json.Unmarshal(out, &arr)
	}
	m := map[string][]string{}
	for _, a := range arr {
		key := strings.ToUpper(strings.TrimSpace(a.Name))
		if key == "" {
			continue
		}
		item := fmt.Sprintf("%s:%s(%s)", a.AccountName, a.AccessRight, a.AccessControlType)
		m[key] = append(m[key], item)
	}
	return m
}

// defaultNetworkCollector provides a dummy receiver for doWMIQuery reuse.
func defaultNetworkCollector() *NetworkCollector { return &NetworkCollector{} }
